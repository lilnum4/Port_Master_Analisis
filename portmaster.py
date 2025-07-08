# -*- coding: utf-8 -*-
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend untuk menghindari GUI errors
import sys
import socket
import ipaddress
import struct
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTextEdit, QTabWidget,
    QProgressBar, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QRadioButton, QMessageBox, QFileDialog, QFormLayout, QCheckBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QColor
import smtplib
import time
import os
import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import inch
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QDesktopServices
import seaborn as sns
import matplotlib.pyplot as plt
import io
from PIL import Image as PILImage
import pandas as pd
from bs4 import BeautifulSoup
import hashlib
from datetime import datetime
import re
import select
import asyncio
import warnings

# =============================================
# KONFIGURASI CACHE & DATABASE CVE
# =============================================
CACHE_FILE = "cve_cache.json"
FEED_DB = "feeds.db"
CACHE_TTL = 24 * 60 * 60  # Cache berlaku 24 jam
CVE_CACHE = {}

# Database CVE lokal sebagai fallback
LOCAL_CVE_DB = {
    'http': "CVE-2021-44228 (Log4Shell): Kerentanan remote code execution di Apache Log4j.",
    'https': "CVE-2021-44228 (Log4Shell): Kerentanan remote code execution di Apache Log4j.",
    'ftp': "CVE-2020-0001: Kerentanan pada layanan FTP",
    'ssh': "CVE-2018-15473: Kerentanan enumerasi username di OpenSSH.",
    'smtp': "CVE-2020-28018: Kerentanan di Exim sebelum versi 4.94.2.",
    'telnet': "CVE-2020-0001: Kerentanan di layanan telnet",
    'rdp': "CVE-2019-0708 (BlueKeep): Kerentanan remote code execution di Remote Desktop Services.",
    'smb': "CVE-2017-0144 (EternalBlue): Kerentanan di SMBv1.",
    'dns': "CVE-2020-1350 (SIGRed): Kerentanan execution code di Windows DNS Server.",
    'imap': "CVE-2018-19518: Kerentanan di UW IMAP.",
    'pop3': "CVE-2018-19518: Kerentanan di UW IMAP.",
    'mysql': "CVE-2012-2122: Vulnerability in MySQL authentication.",
    'postgresql': "CVE-2019-9193: Kerentanan command execution di PostgreSQL.",
    'vnc': "CVE-2006-2369: Kerentanan authentication bypass di RealVNC.",
    'snmp': "CVE-2017-6742: Kerentanan di SNMP.",
    'unknown': "Tidak ada data CVE lokal untuk layanan ini."
}

def load_cache():
    """Memuat cache CVE dari file JSON"""
    global CVE_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                raw_cache = json.load(f)
            for key, value in raw_cache.items():
                if isinstance(value, dict) and "timestamp" in value and "data" in value:
                    CVE_CACHE[key] = value
        except Exception as e:
            print(f"[!] Gagal memuat cache: {e}")

def save_cache():
    """Menyimpan cache CVE ke file JSON"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(CVE_CACHE, f, indent=2)
    except Exception as e:
        print(f"[!] Gagal menyimpan cache: {e}")

def is_cache_valid(key):
    """Memeriksa apakah cache masih valid"""
    entry = CVE_CACHE.get(key)
    if not entry:
        return False
    return (time.time() - entry["timestamp"]) < CACHE_TTL

# =============================================
# UTILITAS PEMINDAIAN
# =============================================
def ipstr2int(ip):
    """Konversi IP string ke integer"""
    return struct.unpack('!I', socket.inet_aton(socket.gethostbyname(ip)))[0]

def ipint2str(ipvalue):
    """Konversi integer ke IP string"""
    return socket.inet_ntoa(struct.pack("!I", ipvalue))

class IPRangeIterator:
    """Iterator untuk rentang IP"""
    def __init__(self, ip_ranges):
        self.ip_ranges = ip_ranges
        self.range_index = 0
        self.current_ip = None
        self.end_ip = None
        self.reset()

    def reset(self):
        if self.ip_ranges:
            start, end = self.ip_ranges[0]
            self.current_ip = start
            self.end_ip = end
        else:
            raise StopIteration

    def __iter__(self):
        return self

    def __next__(self):
        if self.current_ip > self.end_ip:
            self.range_index += 1
            if self.range_index >= len(self.ip_ranges):
                raise StopIteration
            start, end = self.ip_ranges[self.range_index]
            self.current_ip = start
            self.end_ip = end
        ip = self.current_ip
        self.current_ip += 1
        return ip

class PortRangeIterator:
    """Iterator untuk rentang port"""
    def __init__(self, port_start, port_end):
        self.port_ranges = [(port_start, port_end)]
        self.range_index = 0
        self.current_port = None
        self.end_port = None
        self.reset()

    def reset(self):
        if self.port_ranges:
            start, end = self.port_ranges[0]
            self.current_port = start
            self.end_port = end
        else:
            raise StopIteration

    def __iter__(self):
        return self

    def __next__(self):
        if self.current_port > self.end_port:
            self.range_index += 1
            if self.range_index >= len(self.port_ranges):
                raise StopIteration
            start, end = self.port_ranges[self.range_index]
            self.current_port = start
            self.end_port = end
        port = self.current_port
        self.current_port += 1
        return port

class IPAndPortIterator:
    """Iterator untuk pasangan IP dan Port"""
    def __init__(self, ip_iter, port_iter):
        self.ip_iter = ip_iter
        self.port_iter = port_iter
        self.reset()

    def reset(self):
        self.ip_iter.reset()
        self.port_iter.reset()
        self.current_ip = next(self.ip_iter)

    def __iter__(self):
        return self

    def __next__(self):
        try:
            port = next(self.port_iter)
            return ipint2str(self.current_ip), port
        except StopIteration:
            self.current_ip = next(self.ip_iter)
            self.port_iter.reset()
            return self.__next__()

# =============================================
# DATABASE KERENTANAN (NVD API + SCRAPING)
# =============================================
def sha1_hash(string):
    """Generate SHA1 hash dari string"""
    return hashlib.sha1(string.encode()).hexdigest()

def is_valid_cve_id_year(cve_id):
    """Validasi format tahun CVE ID"""
    try:
        cve_id_year = re.findall(r"\d{4}", cve_id)[0]
        current_year = datetime.today().strftime("%Y")
        if int(current_year) - int(cve_id_year) >= 1:
            return False
        return True
    except:
        return True

def feeds_exists_in_db(feed_db, _hash_to_check, _id_to_check):
    """Cek apakah feed sudah ada di database"""
    if not os.path.exists(feed_db):
        return False
    try:
        with open(feed_db, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) < 4:
                    continue
                hash_in_db = parts[2]
                id_in_db = parts[3]
                if _id_to_check == id_in_db:
                    return True
        return False
    except:
        return False

def fetch_latest_cve_entries(feed_db="feeds.db"):
    """Ambil entri CVE terbaru dari NVD"""
    base_url = "https://nvd.nist.gov"
    feed_url = "https://nvd.nist.gov/vuln/data-feeds"

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36',
        'Accept': 'application/json'
    }

    newest_cve_entries = []

    for attempt in range(3):
        try:
            r = requests.get(feed_url, headers=headers, timeout=10)
            if r.status_code == 200:
                try:
                    # Coba parsing sebagai JSON
                    data = r.json()
                    if 'CVE_Items' in data:
                        for item in data['CVE_Items'][:5]:
                            cve_id = item['cve']['CVE_data_meta']['ID']
                            newest_cve_entries.append(f"{base_url}/vuln/detail/{cve_id}")
                except ValueError:
                    # Fallback ke parsing HTML
                    soup = BeautifulSoup(r.content, 'html.parser')
                    cve_list = soup.find_all('a', href=re.compile('/vuln/detail/CVE.*'))
                    for item in cve_list[:5]:
                        newest_cve_entries.append(base_url + item['href'])
                break
            elif r.status_code == 429:
                print(f"[{attempt+1}/3] Rate limit tercapai, menunggu 30 detik...")
                time.sleep(30)
            else:
                print(f"[{attempt+1}/3] Gagal mengambil data (HTTP {r.status_code}), mencoba ulang...")
                time.sleep(3)
        except Exception as e:
            print(f"[{attempt+1}/3] Kesalahan koneksi: {e}")
            time.sleep(3)

    filtered_entries = []
    for cve_link in newest_cve_entries:
        try:
            cve_id = re.search(r"CVE-\d{4}-\d+", cve_link).group(0)
            if not is_valid_cve_id_year(cve_id):
                continue
            if feeds_exists_in_db(feed_db, "", cve_id):
                continue
            filtered_entries.append(cve_link)
        except:
            continue

    return filtered_entries

def retrieve_cve_details(feed_db, cve_links):
    """Ambil detail CVE dari link"""
    results = ""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36'
    }

    for link in cve_links:
        try:
            r = requests.get(link, headers=headers, timeout=10)
            if r.status_code != 200:
                print(f"Gagal mengakses {link}, kode: {r.status_code}")
                continue

            soup = BeautifulSoup(r.text, 'html.parser')

            cve_id_tag = soup.find('span', {'data-testid': 'page-header'})
            cve_id = cve_id_tag.text.strip() if cve_id_tag else "CVE Tidak Diketahui"

            description_tag = soup.find('p', {'data-testid': 'vuln-description'})
            description = description_tag.text.strip() if description_tag else "Deskripsi tidak tersedia."

            severity_tag = soup.find('a', {'data-testid': 'vuln-cvss3-cna-score'})
            severity = severity_tag.text.strip() if severity_tag else "UNKNOWN"

            references_heading = soup.find('h2', string=re.compile("References for.*"))
            references = []
            if references_heading:
                ref_list = references_heading.find_next('ul', class_='list-group')
                if ref_list:
                    for li in ref_list.find_all('li'):
                        a_tag = li.find('a')
                        if a_tag and a_tag.has_attr('href'):
                            references.append(a_tag['href'])

            formatted_references = "\n".join([f"  - {ref}" for ref in references])
            results += f"{cve_id}\n- Deskripsi: {description[:200]}...\n- Tingkat Kerentanan: {severity}\n- Referensi:\n{formatted_references}\n{'-'*40}\n"

            hashed_data = sha1_hash(f"{cve_id}_{str(datetime.now())}")
            if not feeds_exists_in_db(feed_db, hashed_data, cve_id):
                with open(feed_db, 'a') as db:
                    db.write(f"{datetime.now()}|{cve_id}|{hashed_data}|{cve_id}\n")

        except Exception as e:
            print(f"Gagal parsing detail CVE {link}: {e}")
            continue

    return results.strip()

def get_local_cve_data(service_name):
    """Gunakan database lokal sebagai fallback"""
    if not service_name or service_name.strip() == "":
        return "Layanan tidak dikenali. Tidak ada data CVE lokal."
    
    service_key = service_name.lower().strip()
    return LOCAL_CVE_DB.get(service_key, LOCAL_CVE_DB['unknown'])

def get_cves_from_nvd(service_name, vendor=None):
    """Ambil CVE dari NVD API"""
    key = f"{service_name.lower()}_{vendor.lower()}" if vendor else service_name.lower()
    
    if key in CVE_CACHE and is_cache_valid(key):
        return CVE_CACHE[key]["data"]

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": service_name, 
        "resultsPerPage": 3,
        "startIndex": 0
    }
    
    if vendor:
        params["keywordSearch"] += f" {vendor}"
        
    headers = {
        "User-Agent": "Mozilla/5.0",
        "apiKey": "AE3961AF-C159-F011-835C-0EBF96DE670D" ## NOTE WAJIB GUNAKAN API KEY DARI NVD 
    }

    retry_count = 3
    result = None
    from_api = False

    for attempt in range(retry_count):
        try:
            response = requests.get(base_url, params=params, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    result = "Tidak ada CVE ditemukan untuk layanan ini."
                    from_api = True
                    break

                cves = []
                for vuln in vulnerabilities[:3]:
                    try:
                        cve_id = vuln["cve"]["id"]
                        desc = vuln["cve"]["descriptions"][0]["value"]
                        severity_info = vuln["cve"].get("metrics", {}).get("cvssMetricV31", []) or \
                                       vuln["cve"].get("metrics", {}).get("cvssMetricV30", [])
                        severity = "UNKNOWN"
                        if severity_info:
                            severity = severity_info[0]["cvssData"]["baseSeverity"]
                        cves.append(f"{cve_id} - {severity}\n{desc[:200]}...")
                    except:
                        continue

                if cves:
                    result = "\n".join(cves)
                else:
                    result = "CVE ditemukan tetapi tidak bisa diproses."
                from_api = True
                break

            elif response.status_code == 429:
                print(f"[{attempt+1}/{retry_count}] Rate limit tercapai, menunggu 30 detik...")
                time.sleep(30)
            else:
                print(f"[{attempt+1}/{retry_count}] Gagal mengambil data (HTTP {response.status_code})")
                time.sleep(3)

        except requests.exceptions.RequestException as e:
            print(f"[{attempt+1}/{retry_count}] Kesalahan koneksi: {str(e)}")
            time.sleep(3)
        except ValueError as e:
            print(f"[{attempt+1}/{retry_count}] Gagal parse JSON: {str(e)}")
            time.sleep(3)
        except Exception as e:
            print(f"[{attempt+1}/{retry_count}] Kesalahan tak terduga: {str(e)}")
            time.sleep(3)

    # Fallback ke cache kadaluarsa jika API gagal
    if result is None:
        if key in CVE_CACHE:
            print(f"  [*] Gunakan cache kadaluarsa untuk {key}")
            result = CVE_CACHE[key]["data"]
        else:
            print(f"  [*] Gunakan database lokal untuk {service_name}")
            result = get_local_cve_data(service_name)

    # Simpan hasil ke cache jika berasal dari API
    if from_api:
        CVE_CACHE[key] = {
            "timestamp": time.time(),
            "data": result
        }
        save_cache()

    return result

def get_cves_for_service(service_name):
    """Dapatkan CVE untuk layanan tertentu"""
    return get_cves_from_nvd(service_name)

# =============================================
# IMPLEMENTASI UDP YANG LEBIH RESPONSIF (DIPERBAIKI)
# =============================================
class DatagramEndpointProtocol(asyncio.DatagramProtocol):
    """Datagram protocol untuk endpoint UDP"""
    def __init__(self, endpoint):
        self._endpoint = endpoint

    def connection_made(self, transport):
        self._endpoint._transport = transport

    def connection_lost(self, exc):
        if self._endpoint._write_ready_future is not None:
            if not self._endpoint._write_ready_future.done():
                self._endpoint._write_ready_future.set_exception(asyncio.CancelledError())
        self._endpoint.close()

    def datagram_received(self, data, addr):
        self._endpoint.feed_datagram(data, addr)

    def error_received(self, exc):
        warnings.warn(f'Endpoint received an error: {exc!r}')

    def pause_writing(self):
        loop = asyncio.get_event_loop()
        self._endpoint._write_ready_future = loop.create_future()

    def resume_writing(self):
        if self._endpoint._write_ready_future is not None:
            self._endpoint._write_ready_future.set_result(None)
            self._endpoint._write_ready_future = None

class UDPEndpoint:
    """Endpoint UDP tingkat tinggi"""
    def __init__(self, queue_size=None):
        if queue_size is None:
            queue_size = 0
        self._queue = asyncio.Queue(queue_size)
        self._closed = False
        self._transport = None
        self._write_ready_future = None

    def feed_datagram(self, data, addr):
        try:
            self._queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            warnings.warn('Endpoint queue is full')

    def close(self):
        if self._closed:
            return
        self._closed = True
        # Hapus semua item dalam queue
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        # Beri sinyal penutupan
        self.feed_datagram(None, None)
        if self._transport:
            self._transport.close()

    def send(self, data, addr):
        if self._closed:
            raise IOError("Endpoint is closed")
        self._transport.sendto(data, addr)

    async def receive(self):
        if self._queue.empty() and self._closed:
            raise IOError("Endpoint is closed")
        data, addr = await self._queue.get()
        if data is None:
            raise IOError("Endpoint is closed")
        return data, addr

    def abort(self):
        if self._closed:
            raise IOError("Endpoint is closed")
        self._transport.abort()
        self.close()

    async def drain(self):
        if self._write_ready_future is not None:
            await self._write_ready_future

    @property
    def address(self):
        return self._transport.get_extra_info("socket").getsockname()

    @property
    def closed(self):
        return self._closed

async def open_udp_endpoint(host, port, queue_size=100, timeout=2):
    """Buat endpoint UDP dengan timeout"""
    loop = asyncio.get_running_loop()
    endpoint = UDPEndpoint(queue_size)
    
    try:
        # Gunakan create_task untuk memiliki kontrol lebih baik
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: DatagramEndpointProtocol(endpoint),
                remote_addr=(host, port)
            ),
            timeout=timeout
        )
        return endpoint
    except asyncio.TimeoutError:
        endpoint.close()
        raise

# =============================================
# THREAD PEMINDAIAN PORT (DENGAN PERBAIKAN MANAJEMEN TASK)
# =============================================
class PortScannerThread(QThread):
    """Thread untuk melakukan pemindaian port dengan asyncio"""
    update_progress = pyqtSignal(int, int, int)  # progress, scanned, total
    update_result = pyqtSignal(str, int, str, str, str, str)
    scan_complete = pyqtSignal()
    scan_failed = pyqtSignal(str)

    def __init__(self, ip_range, port_start, port_end, timeout=2, scan_type="TCP"):
        super().__init__()
        self.ip_range = ip_range
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.stop_scan = False
        self.scan_type = scan_type
        self.total_ips = 0
        self.total_ports = 0
        self.scanned_count = 0
        self.loop = None
        self.semaphore = asyncio.Semaphore(200)  # Batasi konkurensi (dikurangi dari 500)
        self.active_tasks = set()  # Untuk melacak task aktif

        # Database port umum
        self.common_ports = {
            20: ("FTP Data", "HIGH"),
            21: ("FTP Control", "HIGH"),
            22: ("SSH", "MEDIUM"),
            23: ("Telnet", "HIGH"),
            25: ("SMTP", "MEDIUM"),
            53: ("DNS", "MEDIUM"),
            67: ("DHCP Server", "MEDIUM"),
            68: ("DHCP Client", "LOW"),
            69: ("TFTP", "MEDIUM"),
            80: ("HTTP", "MEDIUM"),
            110: ("POP3", "MEDIUM"),
            111: ("RPC", "HIGH"),
            123: ("NTP", "LOW"),
            135: ("MSRPC", "HIGH"),
            137: ("NetBIOS Name Service", "MEDIUM"),
            138: ("NetBIOS Datagram Service", "MEDIUM"),
            139: ("NetBIOS Session Service", "HIGH"),
            143: ("IMAP", "MEDIUM"),
            161: ("SNMP", "MEDIUM"),
            162: ("SNMP Trap", "MEDIUM"),
            179: ("BGP", "LOW"),
            389: ("LDAP", "MEDIUM"),
            443: ("HTTPS", "LOW"),
            445: ("SMB", "HIGH"),
            465: ("SMTPS", "MEDIUM"),
            514: ("Syslog", "LOW"),
            515: ("LPD", "MEDIUM"),
            587: ("SMTP Submission", "MEDIUM"),
            631: ("IPP", "MEDIUM"),
            636: ("LDAPS", "LOW"),
            993: ("IMAPS", "LOW"),
            995: ("POP3S", "LOW"),
            1080: ("SOCKS Proxy", "MEDIUM"),
            1194: ("OpenVPN", "MEDIUM"),
            1433: ("MSSQL", "HIGH"),
            1434: ("MSSQL Monitor", "MEDIUM"),
            1521: ("Oracle DB", "HIGH"),
            1723: ("PPTP", "MEDIUM"),
            1900: ("UPnP", "MEDIUM"),
            2082: ("cPanel", "MEDIUM"),
            2083: ("cPanel SSL", "MEDIUM"),
            2086: ("WHM", "MEDIUM"),
            2087: ("WHM SSL", "MEDium"),
            2095: ("Webmail", "MEDIUM"),
            2096: ("Webmail SSL", "MEDIUM"),
            2181: ("ZooKeeper", "MEDIUM"),
            2375: ("Docker", "HIGH"),
            2376: ("Docker SSL", "HIGH"),
            2377: ("Docker Swarm", "HIGH"),
            2628: ("DICT", "LOW"),
            3000: ("Node.js", "MEDIUM"),
            3306: ("MySQL", "MEDIUM"),
            3389: ("RDP", "HIGH"),
            3690: ("Subversion", "MEDIUM"),
            4369: ("EPMD", "MEDIUM"),
            5000: ("UPnP", "MEDIUM"),
            5432: ("PostgreSQL", "MEDIUM"),
            5900: ("VNC", "HIGH"),
            5938: ("TeamViewer", "HIGH"),
            6379: ("Redis", "MEDIUM"),
            6443: ("Kubernetes API", "HIGH"),
            6666: ("IRC", "LOW"),
            8000: ("HTTP Alternate", "MEDIUM"),
            8008: ("HTTP Alternate", "MEDIUM"),
            8080: ("HTTP Alternate", "MEDIUM"),
            8081: ("HTTP Alternate", "MEDIUM"),
            8443: ("HTTPS Alternate", "MEDIUM"),
            8888: ("HTTP Alternate", "MEDIUM"),
            9000: ("PHP-FPM", "MEDIUM"),
            9090: ("Prometheus", "MEDIUM"),
            9100: ("Printer", "LOW"),
            9200: ("Elasticsearch", "MEDIUM"),
            9300: ("Elasticsearch", "MEDIUM"),
            11211: ("Memcached", "MEDIUM"),
            27017: ("MongoDB", "MEDIUM"),
        }
        
        self.risk_mitigation = {
            "HIGH": "Tutup port jika tidak diperlukan atau batasi akses dengan firewall.",
            "MEDIUM": "Pastikan layanan selalu diperbarui dan atur firewall untuk membatasi akses.",
            "LOW": "Perbarui layanan secara berkala dan pantau log akses.",
            "UNKNOWN": "Identifikasi layanan yang berjalan pada port ini."
        }

    def parse_ip_ranges(self, ip_range):
        """Parse rentang IP menjadi daftar (start, end)"""
        ranges = ip_range.split(',')
        parsed_ranges = []
        for r in ranges:
            r = r.strip()
            if '/' in r:
                network = ipaddress.IPv4Network(r, strict=False)
                start = int(network.network_address)
                end = int(network.broadcast_address)
                parsed_ranges.append((start, end))
                self.total_ips += (end - start + 1)
            elif '-' in r:
                parts = r.split('-')
                start = ipstr2int(parts[0].strip())
                end = ipstr2int(parts[1].strip())
                parsed_ranges.append((start, end))
                self.total_ips += (end - start + 1)
            else:
                ip = ipstr2int(r.strip())
                parsed_ranges.append((ip, ip))
                self.total_ips += 1
        self.total_ports = self.port_end - self.port_start + 1
        return parsed_ranges

    async def scan_socket_async(self, ip, port):
        """Pindai port tertentu pada IP secara asinkron"""
        try:
            # PERBAIKAN: Tambahkan pengecekan stop_scan
            if self.stop_scan:
                return None
                
            service = ""
            is_open = False
            
            if self.scan_type == "TCP":
                # Menggunakan asyncio untuk TCP scan
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    is_open = True
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service_info = self.common_ports.get(port, ("", ""))
                        service = service_info[0] if service_info[0] else ""
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    is_open = False
                except Exception as e:
                    is_open = False

            elif self.scan_type == "UDP":
                # Menggunakan implementasi UDP yang lebih responsif
                try:
                    endpoint = await open_udp_endpoint(ip, port, timeout=self.timeout)
                    await endpoint.send(b'', (ip, port))
                    
                    try:
                        data, addr = await asyncio.wait_for(
                            endpoint.receive(),
                            timeout=self.timeout
                        )
                        is_open = True
                        if port == 53:
                            service = "DNS"
                        elif port == 161:
                            service = "SNMP"
                        else:
                            try:
                                service = socket.getservbyport(port, "udp")
                            except:
                                service_info = self.common_ports.get(port, ("", ""))
                                service = service_info[0] if service_info[0] else ""
                    except asyncio.TimeoutError:
                        # Untuk UDP, tidak ada respons tidak berarti port tertutup
                        is_open = True
                        service_info = self.common_ports.get(port, ("", ""))
                        service = service_info[0] if service_info[0] else ""
                    finally:
                        endpoint.close()
                except Exception as e:
                    # Jika ada kesalahan koneksi, port mungkin tertutup
                    is_open = False
            else:
                return None

            if is_open:
                risk = self.common_ports.get(port, ("", "UNKNOWN"))[1]
                mitigation = self.risk_mitigation.get(risk, "Identifikasi layanan.")
                cves = get_cves_for_service(service)
                if "CVE-" in cves:
                    risk = "HIGH"
                return ip, port, service, risk, mitigation, cves
            return None
        except asyncio.CancelledError:
            # Ditangani dengan benar ketika task dibatalkan
            return None
        except Exception as e:
            print(f"Error scanning {ip}:{port} ({self.scan_type}): {e}")
            return None

    async def scan_with_semaphore(self, ip, port, scanned, total_work):
        """Scan dengan batasan konkurensi dan penanganan task"""
        try:
            async with self.semaphore:
                if self.stop_scan:
                    return
                    
                # Buat task dan tambahkan ke pelacakan
                task = asyncio.create_task(self.scan_socket_async(ip, port))
                self.active_tasks.add(task)
                task.add_done_callback(lambda t: self.active_tasks.discard(t))
                
                result = await task
                if result:
                    self.update_result.emit(*result)
                
                self.scanned_count += 1
                progress = int((self.scanned_count / total_work) * 100)
                self.update_progress.emit(progress, self.scanned_count, total_work)
        except asyncio.CancelledError:
            # Task dibatalkan, tidak perlu melakukan apa-apa
            pass

    async def cancel_pending_tasks(self):
        """Batalkan semua task yang sedang berjalan"""
        for task in self.active_tasks:
            task.cancel()
        # Tunggu sampai semua task selesai dibatalkan
        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)
        self.active_tasks.clear()

    async def run_scan_async(self, ip_ranges):
        """Jalankan pemindaian asinkron dengan manajemen task"""
        tasks = []
        total_work = self.total_ips * self.total_ports
        scanned = 0
        
        for ip_range in ip_ranges:
            start_ip, end_ip = ip_range
            for ip_int in range(start_ip, end_ip + 1):
                ip_str = ipint2str(ip_int)
                for port in range(self.port_start, self.port_end + 1):
                    if self.stop_scan:
                        # Batalkan semua task jika scan dihentikan
                        await self.cancel_pending_tasks()
                        return
                    
                    tasks.append(
                        self.scan_with_semaphore(ip_str, port, scanned, total_work)
                    )
        
        # Gunakan gather dengan return_exceptions untuk menangani error
        await asyncio.gather(*tasks, return_exceptions=True)

    def run(self):
        """Jalankan pemindaian port dengan event loop asinkron"""
        try:
            ip_ranges = self.parse_ip_ranges(self.ip_range)
            self.stop_scan = False
            self.scanned_count = 0
            self.active_tasks = set()
            
            # Buat event loop baru untuk thread ini
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.run_scan_async(ip_ranges))
            self.scan_complete.emit()
        except Exception as e:
            print(f"[!] Error dalam pemindaian: {e}")
            self.scan_failed.emit(str(e))
        finally:
            # Bersihkan dengan benar
            if self.loop and self.loop.is_running():
                self.loop.stop()
                
            # Tunggu sampai loop benar-benar berhenti
            if self.loop:
                self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                self.loop.close()
                self.loop = None

    def stop(self):
        """Hentikan pemindaian dengan benar"""
        self.stop_scan = True
        if self.loop and self.loop.is_running():
            # Kirim task untuk membatalkan semua operasi
            asyncio.run_coroutine_threadsafe(self.cancel_pending_tasks(), self.loop)

# =============================================
# THREAD PEMBARUAN CVE HARIAN
# =============================================
class DailyCveUpdateThread(QThread):
    """Thread untuk pembaruan CVE harian"""
    cve_update_complete = pyqtSignal()

    def run(self):
        """Jalankan pembaruan CVE"""
        print("[*] Memulai pembaruan CVE harian...")
        try:
            cve_links = fetch_latest_cve_entries(FEED_DB)
            if cve_links:
                result = retrieve_cve_details(FEED_DB, cve_links)
                print("[+] CVE berhasil diperbarui hari ini.")
            else:
                print("[-] Tidak ada CVE baru hari ini.")
        except Exception as e:
            print(f"[!] Gagal memperbarui CVE: {e}")
        finally:
            self.cve_update_complete.emit()

# =============================================
# THREAD PENGAMBILAN CVE BERDASARKAN LAYANAN
# =============================================
class CveFetchThread(QThread):
    """Thread untuk mengambil CVE berdasarkan layanan"""
    cve_fetched = pyqtSignal(int, str)

    def __init__(self, row, service_name):
        super().__init__()
        self.row = row
        self.service_name = service_name

    def run(self):
        """Jalankan pengambilan CVE"""
        try:
            cves = get_cves_for_service(self.service_name)
            self.cve_fetched.emit(self.row, cves)
        except Exception as e:
            print(f"[!] Gagal ambil CVE untuk {self.service_name}: {e}")
            self.cve_fetched.emit(self.row, "Gagal mengambil CVE")

# =============================================
# THREAD PEMINDAIAN PORT TERKENAL
# =============================================
class WellKnownPortScanner(QThread):
    """Thread untuk pemindaian port terkenal"""
    update_result = pyqtSignal(str, int, str, str)  # ip, port, status, service
    scan_complete = pyqtSignal()

    def __init__(self, target_ip, ports):
        super().__init__()
        self.target_ip = target_ip
        self.ports = ports
        self.stop_scan = False

    def run(self):
        """Jalankan pemindaian"""
        try:
            for port in self.ports:
                if self.stop_scan:
                    return
                    
                status, service = self.scan_port(port)
                self.update_result.emit(self.target_ip, port, status, service)
                
            self.scan_complete.emit()
        except Exception as e:
            print(f"Error in well-known scan: {e}")

    def scan_port(self, port):
        """Pindai port tertentu"""
        try:
            # Coba koneksi TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                # Dapatkan nama layanan
                try:
                    service = socket.getservbyport(port, "tcp")
                except:
                    service = "Layanan tidak dikenali"
                return "Terbuka", service
            return "Tertutup", "-"
        except Exception:
            return "Error", "-"

    def stop(self):
        """Hentikan pemindaian"""
        self.stop_scan = True

# =============================================
# APLIKASI UTAMA PORTMASTER
# =============================================
class PortMasterApp(QMainWindow):
    """Aplikasi utama PortMaster"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PortMaster : Analisis")
        self.setGeometry(100, 100, 1200, 900)
        self.setStyleSheet(self.get_instagram_stylesheet())
        self.scan_results = []
        load_cache()
        self.active_cve_threads = []
        self.create_ui()
        self.setup_daily_cve_updater()

    def setup_daily_cve_updater(self):
        """Setup pembaruan CVE harian otomatis"""
        self.daily_cve_thread = DailyCveUpdateThread()
        self.daily_cve_thread.cve_update_complete.connect(self.on_daily_cve_complete)
        self.daily_cve_thread.start()

        self.daily_timer = QTimer()
        self.daily_timer.timeout.connect(self.run_daily_cve_update)
        self.daily_timer.start(24 * 60 * 60 * 1000)  # Update setiap 24 jam

    def run_daily_cve_update(self):
        """Jalankan pembaruan CVE harian"""
        if hasattr(self, 'daily_cve_thread') and self.daily_cve_thread.isRunning():
            print("[!] Update CVE sedang berjalan, lewati jadwal harian.")
            return
        self.daily_cve_thread = DailyCveUpdateThread()
        self.daily_cve_thread.cve_update_complete.connect(self.on_daily_cve_complete)
        self.daily_cve_thread.start()

    def on_daily_cve_complete(self):
        """Callback ketika pembaruan CVE selesai"""
        print("[*] Pembaruan CVE harian selesai.")

    def closeEvent(self, event):
        """Simpan cache sebelum aplikasi ditutup"""
        save_cache()
        event.accept()

    def get_instagram_stylesheet(self):
        """Stylesheet untuk antarmuka"""
        return """
            QMainWindow {
                background-color: #fafafa;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                background: #ffffff;
            }
            QPushButton {
                background-color: #6a1b9a;
                color: white;
                padding: 8px;
                border-radius: 20px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #8e24aa;
            }
            QLineEdit, QSpinBox, QComboBox, QTextEdit {
                border: 1px solid #ccc;
                padding: 6px;
                border-radius: 10px;
                background-color: #f0f0f0;
            }
            QLabel {
                font-weight: bold;
                color: #333;
            }
            QGroupBox {
                border: 1px solid #ccc;
                border-radius: 10px;
                margin-top: 10px;
                font-weight: bold;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 4px 10px;
                background-color: #ececec;
                border-radius: 6px;
                font-size: 11pt;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 10px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                          stop:0 #ba53ff,
                                          stop:1 #5bd3ff);
                border-radius: 10px;
            }
            QTableWidget {
                gridline-color: #eee;
            }
            QHeaderView::section {
                background-color: #f5f5f5;
                color: #333;
                font-weight: bold;
            }
            QRadioButton {
                spacing: 5px;
            }
            QRadioButton::indicator {
                width: 16px;
                height: 16px;
                border-radius: 8px;
                border: 2px solid #aaa;
            }
            QRadioButton::indicator:checked {
                background-color: #ce93d8;
            }
            QMessageBox {
                background-color: #fff;
            }
            QCheckBox {
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #aaa;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #6a1b9a;
                border: 1px solid #6a1b9a;
            }
        """

    def create_ui(self):
        """Buat antarmuka pengguna"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Judul aplikasi
        title_label = QLabel("PortMaster : Analisis")
        title_label.setStyleSheet("font-size: 24pt; font-family: Segoe UI; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        subtitle_label = QLabel("Port Scanner dengan Email & Update CVE")
        subtitle_label.setStyleSheet("font-size: 12pt; font-family: Segoe UI;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)

        # Tab utama
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Buat tab-tab
        self.create_scanner_tab()
        self.create_well_known_port_tab()
        self.create_cache_tab()

    def create_scanner_tab(self):
        """Buat tab pemindaian port"""
        scanner_tab = QWidget()
        layout = QVBoxLayout(scanner_tab)

        # Grup parameter pemindaian
        form_group = QGroupBox("Parameter Pemindaian")
        form_layout = QFormLayout()
        
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setPlaceholderText("contoh: 192.168.1.1/24")
        form_layout.addRow(QLabel("Rentang IP:"), self.ip_input)

        self.start_port_input = QSpinBox()
        self.start_port_input.setRange(1, 65535)
        self.start_port_input.setValue(1)
        form_layout.addRow(QLabel("Port Awal:"), self.start_port_input)

        self.end_port_input = QSpinBox()
        self.end_port_input.setRange(1, 65535)
        self.end_port_input.setValue(100)
        form_layout.addRow(QLabel("Port Akhir:"), self.end_port_input)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP"])
        form_layout.addRow(QLabel("Jenis Protokol:"), self.protocol_combo)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 30)
        self.timeout_input.setValue(2)
        form_layout.addRow(QLabel("Timeout (detik):"), self.timeout_input)

        form_group.setLayout(form_layout)
        layout.addWidget(form_group)

        # Grup pengaturan email
        email_group = QGroupBox("Pengaturan Email")
        email_layout = QFormLayout()
        
        self.email_sender = QLineEdit()
        self.email_sender.setPlaceholderText("email_pengirim@gmail.com")
        email_layout.addRow(QLabel("Email Pengirim:"), self.email_sender)
        
        self.email_password = QLineEdit()
        self.email_password.setEchoMode(QLineEdit.Password)
        email_layout.addRow(QLabel("App Password Gmail:"), self.email_password)
        
        self.email_receiver = QLineEdit()
        self.email_receiver.setPlaceholderText("penerima@example.com")
        email_layout.addRow(QLabel("Email Penerima:"), self.email_receiver)
        
        email_group.setLayout(email_layout)
        layout.addWidget(email_group)

        # Tombol aksi
        action_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("Mulai Pemindaian")
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)

        self.stop_button = QPushButton("Berhenti")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        action_layout.addWidget(self.stop_button)
        
        layout.addLayout(action_layout)

        # Tombol ekspor
        export_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("Export to PDF")
        self.export_btn.clicked.connect(self.export_to_pdf)
        export_layout.addWidget(self.export_btn)

        self.send_now_btn = QPushButton("Kirim Sekarang")
        self.send_now_btn.clicked.connect(lambda: self.send_email_now("[Laporan Pemindaian]", self.generate_report_body()))
        export_layout.addWidget(self.send_now_btn)
        
        layout.addLayout(export_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Tabel hasil
        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(["IP", "Port", "Layanan", "Risiko", "Rekomendasi", "CVE Terkait"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.result_table)

        self.tabs.addTab(scanner_tab, "Port Scanner")

    def generate_report_body(self):
        """Generate isi laporan untuk email"""
        body = "Hasil pemindaian:\n"
        for row in range(self.result_table.rowCount()):
            ip = self.result_table.item(row, 0).text()
            port = self.result_table.item(row, 1).text()
            service = self.result_table.item(row, 2).text()
            risk = self.result_table.item(row, 3).text()
            mitigation = self.result_table.item(row, 4).text() if self.result_table.item(row, 4) else ""
            cves = self.result_table.item(row, 5).text() if self.result_table.item(row, 5) else ""
            body += f"IP: {ip}, Port: {port}\nLayanan: {service}, Risiko: {risk}\nRekomendasi: {mitigation}\nCVE: {cves}\n{'-'*30}\n"
        return body

    def send_email_now(self, subject, body):
        """Kirim email dengan hasil pemindaian"""
        sender = self.email_sender.text().strip()
        password = self.email_password.text().strip()
        receiver = self.email_receiver.text().strip()
        
        if not sender or not password or not receiver:
            QMessageBox.warning(self, "Input Tidak Lengkap", "Isi semua pengaturan email.")
            return
        
        try:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.ehlo()
            server.login(sender, password)
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()
            
            self.statusBar().showMessage("Email berhasil dikirim.")
            QMessageBox.information(self, "Berhasil", "Laporan berhasil dikirim via email.")
        except smtplib.SMTPAuthenticationError:
            QMessageBox.critical(self, "Autentikasi Gagal", "Email atau password salah. Gunakan App Password Gmail.")
        except Exception as e:
            self.statusBar().showMessage(f"Gagal mengirim email: {str(e)}")
            QMessageBox.critical(self, "Gagal Mengirim", f"Tidak dapat mengirim email.\n{str(e)}")

    def create_well_known_port_tab(self):
        """Buat tab pemindaian port terkenal"""
        well_known_tab = QWidget()
        layout = QVBoxLayout(well_known_tab)

        # Input target IP
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target IP:"))
        
        self.target_input_wkp = QLineEdit("192.168.1.1")
        target_layout.addWidget(self.target_input_wkp)
        
        layout.addLayout(target_layout)

        # Grup pilihan port terkenal
        port_group = QGroupBox("Pilih Port Terkenal")
        port_layout = QVBoxLayout()
        
        self.wkp_checkboxes = {
            "HTTP (80)": 80,
            "HTTPS (443)": 443,
            "SSH (22)": 22,
            "DNS (53)": 53,
            "SMB (445)": 445,
            "TELNET (23)": 23,
            "IMAP (143)": 143,
            "POP3 (110)": 110,
            "FTP (21)": 21,
            "SMTP (25)": 25,
            "RDP (3389)": 3389,
            "MySQL (3306)": 3306,
            "PostgreSQL (5432)": 5432,
            "VNC (5900)": 5900,
            "MSSQL (1433)": 1433,
            "Redis (6379)": 6379,
            "MongoDB (27017)": 27017,
            "Elasticsearch (9200)": 9200
        }
        
        self.checkboxes = {}
        for name, port in self.wkp_checkboxes.items():
            cb = QCheckBox(name)  # Menggunakan QCheckBox agar bisa pilih banyak
            self.checkboxes[name] = cb
            port_layout.addWidget(cb)
            
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)

        # Tombol pemindaian
        scan_btn = QPushButton("Mulai Pemindaian")
        scan_btn.clicked.connect(self.start_well_known_scan)
        layout.addWidget(scan_btn)

        # Area hasil
        self.well_known_result_text = QTextEdit()
        self.well_known_result_text.setReadOnly(True)
        layout.addWidget(self.well_known_result_text)

        self.tabs.addTab(well_known_tab, "Well-Known Port")

    def create_cache_tab(self):
        """Buat tab manajemen cache"""
        cache_tab = QWidget()
        layout = QVBoxLayout(cache_tab)

        # Grup status cache
        self.cache_status_group = QGroupBox("Status Cache")
        status_layout = QFormLayout()
        
        self.cache_size_label = QLabel("Memuat...")
        self.cache_file_label = QLabel(os.path.abspath(CACHE_FILE))
        self.cache_last_modified_label = QLabel("Belum dimuat")
        
        status_layout.addRow(QLabel("Jumlah Entri Cache:"), self.cache_size_label)
        status_layout.addRow(QLabel("Lokasi File Cache:"), self.cache_file_label)
        status_layout.addRow(QLabel("Terakhir Diperbarui:"), self.cache_last_modified_label)
        
        self.cache_status_group.setLayout(status_layout)
        layout.addWidget(self.cache_status_group)

        # Tombol kontrol cache
        control_layout = QHBoxLayout()
        
        self.refresh_cache_btn = QPushButton("Refresh Status")
        self.refresh_cache_btn.clicked.connect(self.update_cache_status)
        control_layout.addWidget(self.refresh_cache_btn)
        
        self.clear_cache_btn = QPushButton("Hapus Cache")
        self.clear_cache_btn.clicked.connect(self.clear_cache)
        control_layout.addWidget(self.clear_cache_btn)
        
        layout.addLayout(control_layout)

        self.tabs.addTab(cache_tab, "Cache Status")
        self.update_cache_status()

    def update_cache_status(self):
        """Perbarui status cache"""
        load_cache()
        cache_size = len(CVE_CACHE)
        last_modified = os.path.getmtime(CACHE_FILE) if os.path.exists(CACHE_FILE) else None
        
        self.cache_size_label.setText(str(cache_size))
        self.cache_last_modified_label.setText(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_modified)) if last_modified else "Tidak tersedia"
        )

    def clear_cache(self):
        """Hapus semua data cache"""
        global CVE_CACHE
        CVE_CACHE.clear()
        
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        if os.path.exists(FEED_DB):
            os.remove(FEED_DB)
            
        self.update_cache_status()
        QMessageBox.information(self, "Cache Dihapus", "Semua data cache telah dihapus.")

    def calculate_remaining_time(self, elapsed, scanned, remaining):
        """Hitung estimasi waktu tersisa"""
        if scanned == 0:
            return "Menghitung..."
        
        rate = scanned / elapsed  # Target per detik
        if rate > 0:
            remaining_time = remaining / rate
            return time.strftime("%H:%M:%S", time.gmtime(remaining_time))
        return "Menghitung..."

    def update_progress(self, progress, scanned, total):
        """Update progress bar dan status"""
        self.progress_bar.setValue(progress)
        
        # Hitung estimasi waktu tersisa
        if scanned > 0:
            elapsed = time.time() - self.scan_start_time
            remaining = total - scanned
            time_str = self.calculate_remaining_time(elapsed, scanned, remaining)
            self.statusBar().showMessage(
                f"Memindai... {scanned}/{total} ({progress}%) | Estimasi selesai: {time_str}"
            )
        else:
            self.statusBar().showMessage(f"Memindai... {scanned}/{total} ({progress}%)")

    def start_scan(self):
        """Mulai pemindaian port"""
        ip_range = self.ip_input.text().strip()
        start_port = self.start_port_input.value()
        end_port = self.end_port_input.value()
        timeout = self.timeout_input.value()
        scan_type = self.protocol_combo.currentText()
        
        if not ip_range:
            QMessageBox.warning(self, "Input Tidak Valid", "Masukkan alamat IP atau rentang IP.")
            return
            
        if start_port > end_port:
            QMessageBox.warning(self, "Port Salah", "Port awal harus lebih kecil dari port akhir.")
            return
            
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            QMessageBox.critical(self, "Port Salah", "Port harus antara 1 hingga 65535")
            return
            
        self.result_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage("Memulai pemindaian...")
        
        self.scan_start_time = time.time()  # Catat waktu mulai
        self.progress_bar.setRange(0, 100)  # Set range 0-100%

        self.scanner_thread = PortScannerThread(ip_range, start_port, end_port, timeout, scan_type)
        self.scanner_thread.update_result.connect(self.add_result)
        self.scanner_thread.update_progress.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.scan_finished)
        self.scanner_thread.scan_failed.connect(self.handle_scan_error)
        self.scanner_thread.start()

    def handle_scan_error(self, error_msg):
        """Tangani error saat pemindaian"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        QMessageBox.critical(self, "Scan Error", f"Pemindaian gagal: {error_msg}")

    def stop_scan(self):
        """Hentikan pemindaian yang sedang berjalan"""
        if hasattr(self, 'scanner_thread') and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.statusBar().showMessage("Pemindaian dihentikan oleh pengguna.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def add_result(self, ip, port, service, risk, mitigation, cves=None):
        """Tambahkan hasil pemindaian ke tabel"""
        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)
        
        # Warna berdasarkan risiko
        color = QColor(Qt.green)
        if risk == "HIGH":
            color = QColor(255, 0, 0, 150)
        elif risk == "MEDIUM":
            color = QColor(255, 165, 0, 150)
        elif risk == "LOW":
            color = QColor(0, 255, 0, 150)
        elif risk == "UNKNOWN":
            color = QColor(200, 200, 200, 150)
            
        # Tambahkan item ke tabel
        for col, text in enumerate([ip, str(port), service, risk, mitigation, cves or "Memuat..."]):
            item = QTableWidgetItem(text)
            item.setBackground(color)
            self.result_table.setItem(row_position, col, item)

        # Jika CVE belum dimuat, mulai thread untuk mengambilnya
        if service and (cves is None or cves == ""):
            cve_thread = CveFetchThread(row_position, service)
            cve_thread.cve_fetched.connect(self.on_cve_fetched)
            cve_thread.start()
            self.active_cve_threads.append(cve_thread)

    def on_cve_fetched(self, row, cve_data):
        """Update tabel ketika CVE selesai dimuat"""
        if row < self.result_table.rowCount():
            item = QTableWidgetItem(cve_data)
            self.result_table.setItem(row, 5, item)

    def scan_finished(self):
        """Callback ketika pemindaian selesai"""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(f"Pemindaian selesai. Ditemukan {self.result_table.rowCount()} port terbuka.")

    def start_well_known_scan(self):
        """Mulai pemindaian port terkenal"""
        target_ip = self.target_input_wkp.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "Input Kosong", "Masukkan alamat IP target")
            return
            
        # Dapatkan port yang dipilih
        selected_ports = []
        for name, port in self.wkp_checkboxes.items():
            if self.checkboxes[name].isChecked():
                selected_ports.append(port)
                
        if not selected_ports:
            QMessageBox.warning(self, "Pilihan Kosong", "Pilih setidaknya satu port terkenal")
            return
            
        # Tampilkan status
        self.well_known_result_text.clear()
        self.well_known_result_text.append(f"Memulai pemindaian port terkenal di {target_ip}...")
        self.statusBar().showMessage("Memindai port terkenal...")
        
        # Jalankan pemindaian dalam thread terpisah
        self.wkp_scanner = WellKnownPortScanner(target_ip, selected_ports)
        self.wkp_scanner.update_result.connect(self.add_wkp_result)
        self.wkp_scanner.scan_complete.connect(self.wkp_scan_finished)
        self.wkp_scanner.start()

    def add_wkp_result(self, ip, port, status, service):
        """Tambahkan hasil pemindaian ke text area"""
        color = "#4CAF50" if status == "Terbuka" else "#F44336"
        result_html = f"""
        <div style='margin-bottom: 10px;'>
            <b>Port {port}</b>: 
            <span style='color: {color}; font-weight: bold;'>{status}</span>
            <br>Layanan: {service}
        </div>
        """
        current_html = self.well_known_result_text.toHtml()
        self.well_known_result_text.setHtml(current_html + result_html)

    def wkp_scan_finished(self):
        """Callback ketika pemindaian selesai"""
        self.well_known_result_text.append("\nPemindaian selesai!")
        self.statusBar().showMessage("Pemindaian port terkenal selesai")

    def get_dataframe_from_table(self):
        """Konversi tabel hasil ke DataFrame pandas"""
        data = []
        for row in range(self.result_table.rowCount()):
            ip = self.result_table.item(row, 0).text()
            port = int(self.result_table.item(row, 1).text())
            service = self.result_table.item(row, 2).text()
            risk = self.result_table.item(row, 3).text()
            mitigation = self.result_table.item(row, 4).text() if self.result_table.item(row, 4) else ""
            cves = self.result_table.item(row, 5).text() if self.result_table.item(row, 5) else ""
            data.append({'IP': ip, 'Port': port, 'Layanan': service, 'Risiko': risk, 'Rekomendasi': mitigation, 'CVE Terkait': cves})
        return pd.DataFrame(data)

    def export_to_pdf(self):
        """Ekspor hasil pemindaian ke PDF"""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Simpan Laporan sebagai PDF", "", "PDF Files (*.pdf)", options=options
        )
        if not file_path:
            return

        try:
            # Gunakan landscape A4 dan izinkan pembagian tabel
            doc = SimpleDocTemplate(file_path, pagesize=landscape(A4))
            doc.allowSplitting = 1  # Memungkinkan tabel dibagi ke halaman berikutnya
            styles = getSampleStyleSheet()

            # Style untuk teks kecil dan wrapping
            small_style = ParagraphStyle(
                name='Small',
                parent=styles['Normal'],
                fontSize=6,
                leading=8,
                wordWrap='CJK'
            )

            elements = []

            # Judul laporan
            title = Paragraph("Laporan Hasil Pemindaian Port", styles['Title'])
            elements.append(title)
            elements.append(Spacer(1, 12))

            # Informasi pemindaian
            scan_info = [
                f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Rentang IP: {self.ip_input.text()}",
                f"Port: {self.start_port_input.value()} - {self.end_port_input.value()}",
                f"Protokol: {self.protocol_combo.currentText()}",
                f"Total hasil: {self.result_table.rowCount()}"
            ]
            
            for info in scan_info:
                elements.append(Paragraph(info, styles['Normal']))
                elements.append(Spacer(1, 6))

            elements.append(Spacer(1, 12))

            # Cek apakah ada data
            if self.result_table.rowCount() == 0:
                elements.append(Paragraph("Tidak ada hasil pemindaian.", styles['Normal']))
            else:
                # Header tabel
                data = [["IP", "Port", "Layanan", "Risiko", "Rekomendasi", "CVE Terkait"]]

                for row in range(self.result_table.rowCount()):
                    row_data = []
                    for col in range(6):
                        item = self.result_table.item(row, col)
                        text = item.text() if item else ''
                        # Batasi panjang teks CVE jika terlalu panjang
                        if col == 5 and len(text) > 100:
                            text = text[:100] + "... (lihat detail lengkap di aplikasi)"
                        para = Paragraph(text, small_style)
                        row_data.append(para)
                    data.append(row_data)

                # Lebar kolom yang lebih proporsional
                col_widths = [
                    1.0 * inch,  # IP
                    0.6 * inch,  # Port
                    1.2 * inch,  # Layanan
                    0.7 * inch,  # Risiko
                    1.8 * inch,  # Rekomendasi
                    2.0 * inch   # CVE Terkait
                ]

                # Buat tabel dengan repeatRows=1 untuk mengulang header di setiap halaman
                table = Table(data, colWidths=col_widths, repeatRows=1)
                
                # Style tabel
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('WORDWRAP', (0, 0), (-1, -1), True),
                ]))
                
                elements.append(table)
                elements.append(Spacer(1, 12))

                # Tambahkan grafik distribusi risiko jika ada
                df = self.get_dataframe_from_table()
                if not df.empty and 'Risiko' in df.columns:
                    plt.figure(figsize=(6, 3))
                    risk_counts = df['Risiko'].value_counts()
                    colors_list = {'HIGH': '#F44336', 'MEDIUM': '#FFA726', 'LOW': '#4CAF50', 'UNKNOWN': '#9E9E9E'}
                    risk_counts.plot(kind='bar', color=[colors_list.get(r, '#9E9E9E') for r in risk_counts.index])
                    plt.title('Distribusi Risiko Port Terbuka')
                    plt.xlabel('Kategori Risiko')
                    plt.ylabel('Jumlah')
                    plt.xticks(rotation=0)
                    plt.tight_layout()

                    buf = io.BytesIO()
                    plt.savefig(buf, format='png', dpi=100)
                    plt.close()
                    buf.seek(0)
                    img = Image(buf, width=5*inch, height=2.5*inch)
                    elements.append(img)

            # Footer
            footer_text = f"Dicetak pada: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total {self.result_table.rowCount()} hasil"
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(footer_text, small_style))

            # Build PDF
            doc.build(elements)

            # Buka file PDF setelah dibuat
            QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))

        except Exception as e:
            QMessageBox.critical(self, "Gagal Mengekspor", f"Gagal menyimpan laporan PDF.\n{str(e)}")

# =============================================
# JALANKAN APLIKASI
# =============================================
if __name__ == "__main__": 
    app = QApplication(sys.argv)
    window = PortMasterApp()
    window.show()
    sys.exit(app.exec_())
