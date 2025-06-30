# -*- coding: utf-8 -*-
import sys
import socket
import ipaddress
import struct
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTextEdit, QTabWidget,
    QProgressBar, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QGroupBox, QRadioButton, QMessageBox, QFileDialog, QTimeEdit, QFormLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QDateTime
from PyQt5.QtGui import QColor
import smtplib
import time
import os
import matplotlib.pyplot as plt
import networkx as nx
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QDesktopServices
import json

# --- CONFIG CACHE ---
CACHE_FILE = "cve_cache.json"
CACHE_TTL = 24 * 60 * 60  # 24 jam
CVE_CACHE = {}  # Format: {"key": {"timestamp": ..., "data": ...}}

def load_cache():
    global CVE_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                raw_cache = json.load(f)
            for key, value in raw_cache.items():
                if isinstance(value, dict) and "timestamp" in value and "data" in value:
                    CVE_CACHE[key] = value
        except Exception as e:
            print(f"Gagal memuat cache: {e}")

def save_cache():
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(CVE_CACHE, f, indent=2)
    except Exception as e:
        print(f"Gagal menyimpan cache: {e}")

def is_cache_valid(key):
    entry = CVE_CACHE.get(key)
    if not entry:
        return False
    return (time.time() - entry["timestamp"]) < CACHE_TTL

# --- UTILITAS PEMINDAIAN ---
def ipstr2int(ip):
    return struct.unpack('!I', socket.inet_aton(socket.gethostbyname(ip)))[0]

def ipint2str(ipvalue):
    return socket.inet_ntoa(struct.pack("!I", ipvalue))

class IPRangeIterator:
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

# --- NETWORK VISUALIZATION CLASS ---
class NetworkAnalyzer:
    def __init__(self):
        self.graph = nx.Graph()
        self.node_risks = {}

    def add_host(self, ip, port_info):
        if ip not in self.graph:
            self.graph.add_node(ip)
            self.node_risks[ip] = {"ports": [], "risk": "LOW"}
        self.node_risks[ip]["ports"].append(port_info)
        risk_levels = [p[2] for p in self.node_risks[ip]["ports"]]
        if "HIGH" in risk_levels:
            self.node_risks[ip]["risk"] = "HIGH"
        elif "MEDIUM" in risk_levels and self.node_risks[ip]["risk"] != "HIGH":
            self.node_risks[ip]["risk"] = "MEDIUM"

    def visualize_network(self):
        plt.figure(figsize=(12, 9))
        pos = nx.spring_layout(self.graph, k=0.5, iterations=50)
        node_colors = [self.get_risk_color(self.node_risks[node]["risk"]) for node in self.graph.nodes()]
        nx.draw_networkx_nodes(self.graph, pos, node_size=800, node_color=node_colors)
        nx.draw_networkx_edges(self.graph, pos, alpha=0.5)
        nx.draw_networkx_labels(self.graph, pos, font_size=9, font_weight='bold')
        plt.axis('off')
        temp_file = f"network_{int(time.time())}.png"
        plt.savefig(temp_file, dpi=150, bbox_inches='tight')
        plt.close()
        return temp_file

    def get_risk_color(self, risk):
        return {
            "HIGH": "#FF0000",
            "MEDIUM": "#FFA500",
            "LOW": "#00FF00"
        }.get(risk, "#808080")

# --- DATABASE KERENTANAN (NVD API) - FIXED + CACHING ---
def get_cves_from_nvd(service_name, vendor=None):
    key = f"{service_name.lower()}_{vendor.lower()}" if vendor else service_name.lower()

    if key in CVE_CACHE and is_cache_valid(key):
        return CVE_CACHE[key]["data"]

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0 "
    params = {
        "keywordSearch": service_name,
        "resultsPerPage": 3
    }
    if vendor:
        params["keywordSearch"] += f" {vendor}"

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                result = "Tidak ada CVE ditemukan untuk layanan ini."
            else:
                cves = []
                for vuln in vulnerabilities:
                    try:
                        cve_id = vuln["cve"]["id"]
                        desc = vuln["cve"]["descriptions"][0]["value"]
                        severity_info = vuln["cve"].get("metrics", {}).get("cvssMetricV31", []) or \
                                        vuln["cve"].get("metrics", {}).get("cvssMetricV30", [])

                        severity = "UNKNOWN"
                        if severity_info:
                            severity = severity_info[0]["cvssData"]["baseSeverity"]

                        cves.append(f"{cve_id} - {severity}\n{desc[:200]}...")
                    except Exception as e:
                        continue
                result = "\n".join(cves)
        else:
            result = f"Tidak dapat mengambil data CVE. Kode HTTP: {response.status_code}"
    except requests.exceptions.RequestException as e:
        result = f"Kesalahan koneksi saat mencari CVE: {str(e)}"
    except Exception as e:
        result = f"Gagal mengambil informasi CVE: {e}"

    CVE_CACHE[key] = {
        "timestamp": time.time(),
        "data": result
    }
    return result

def get_cves_for_service(service_name):
    """Menggunakan NVD API untuk mencari CVE berdasarkan nama layanan"""
    return get_cves_from_nvd(service_name)

# --- THREAD PEMINDAIAN BERBASIS SOCKET ---
class PortScannerThread(QThread):
    update_progress = pyqtSignal(int)
    update_result = pyqtSignal(str, int, str, str, str, str)
    scan_complete = pyqtSignal()

    def __init__(self, ip_range, port_start, port_end, timeout=2, scan_type="TCP"):
        super().__init__()
        self.ip_range = ip_range
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.stop_scan = False
        self.scan_type = scan_type
        self.common_ports = {
            20: ("FTP Data", "HIGH"),
            21: ("FTP Control", "HIGH"),
            22: ("SSH", "MEDIUM"),
            23: ("Telnet", "HIGH"),
            25: ("SMTP", "MEDIUM"),
            53: ("DNS", "MEDIUM"),
            80: ("HTTP", "MEDIUM"),
            110: ("POP3", "MEDIUM"),
            123: ("NTP", "LOW"),
            143: ("IMAP", "MEDIUM"),
            443: ("HTTPS", "LOW"),
            445: ("SMB", "HIGH"),
            3306: ("MySQL", "MEDIUM"),
            3389: ("RDP", "HIGH"),
            5432: ("PostgreSQL", "MEDIUM"),
            8080: ("HTTP Alternate", "MEDIUM"),
            8443: ("HTTPS Alternate", "MEDIUM")
        }
        self.risk_mitigation = {
            "HIGH": "Tutup port jika tidak diperlukan atau batasi akses dengan firewall.",
            "MEDIUM": "Pastikan layanan selalu diperbarui dan atur firewall untuk membatasi akses.",
            "LOW": "Perbarui layanan secara berkala dan pantau log akses."
        }

    def parse_ip_ranges(self, ip_range):
        ranges = ip_range.split(',')
        parsed_ranges = []
        for r in ranges:
            r = r.strip()
            if '/' in r:
                network = ipaddress.IPv4Network(r, strict=False)
                start = int(network.network_address)
                end = int(network.broadcast_address)
                parsed_ranges.append((start, end))
            elif '-' in r:
                parts = r.split('-')
                start = ipstr2int(parts[0].strip())
                end = ipstr2int(parts[1].strip())
                parsed_ranges.append((start, end))
            else:
                ip = ipstr2int(r.strip())
                parsed_ranges.append((ip, ip))
        return parsed_ranges

    def run(self):
        try:
            ip_ranges = self.parse_ip_ranges(self.ip_range)
            total_ips = sum(end - start + 1 for start, end in ip_ranges)
            total_ports = self.port_end - self.port_start + 1
            total_tasks = total_ips * total_ports
            completed = 0
            ip_iter = IPRangeIterator(ip_ranges)
            port_iter = PortRangeIterator(self.port_start, self.port_end)
            ipport_iter = IPAndPortIterator(ip_iter, port_iter)

            def scanner_task():
                nonlocal completed
                while True:
                    if self.stop_scan:
                        break
                    try:
                        ip_str, port = next(ipport_iter)
                        result = self.scan_socket(ip_str, port)
                        if result:
                            self.update_result.emit(*result)
                        completed += 1
                        self.update_progress.emit(int((completed / total_tasks) * 100))
                    except StopIteration:
                        break

            threads = []
            for _ in range(100):  # Jumlah thread
                t = threading.Thread(target=scanner_task)
                t.daemon = True
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            self.scan_complete.emit()
        except Exception as e:
            print(f"Error dalam pemindaian: {e}")

    def scan_socket(self, ip, port):
        try:
            if self.scan_type == "TCP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif self.scan_type == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.connect_ex((ip, port))
            else:
                return None

            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0 or self.scan_type == "UDP":
                try:
                    service = socket.getservbyport(port, "tcp") if port < 1024 else ""
                except:
                    service = ""

                risk = self.common_ports.get(port, ("", "UNKNOWN"))[1]
                mitigation = self.risk_mitigation.get(risk, "Identifikasi layanan.")
                cves = get_cves_for_service(service)
                if "CVE-" in cves:
                    risk = "HIGH"
                return ip, port, service, risk, mitigation, cves
            return None
        except:
            return None

    def stop(self):
        self.stop_scan = True

# --- APLIKASI UTAMA PORTMASTER ---
class PortMasterApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PortMaster : Analisis")
        self.setGeometry(100, 100, 1200, 900)
        self.setStyleSheet(self.get_instagram_stylesheet())
        self.scan_results = []
        self.network_analyzer = NetworkAnalyzer()
        load_cache()
        self.create_ui()

    def closeEvent(self, event):
        save_cache()
        event.accept()

    def get_instagram_stylesheet(self):
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
                subcontrol-position: top center;
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
        """

    def create_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        title_label = QLabel("PortMaster : Analisis")
        title_label.setStyleSheet("font-size: 24pt; font-family: Segoe UI; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        subtitle_label = QLabel("Port Scanner dengan Email & Penjadwalan Otomatis")
        subtitle_label.setStyleSheet("font-size: 12pt; font-family: Segoe UI;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.create_scanner_tab()
        self.create_scheduler_tab()
        self.create_well_known_port_tab()
        self.create_cache_tab()

    def create_scanner_tab(self):
        scanner_tab = QWidget()
        layout = QVBoxLayout(scanner_tab)

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

        action_layout = QHBoxLayout()
        self.scan_button = QPushButton("Mulai Pemindaian")
        self.scan_button.clicked.connect(self.start_scan)
        action_layout.addWidget(self.scan_button)
        self.stop_button = QPushButton("Berhenti")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        action_layout.addWidget(self.stop_button)
        layout.addLayout(action_layout)

        export_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export to PDF")
        self.export_btn.clicked.connect(self.export_to_pdf)
        export_layout.addWidget(self.export_btn)
        self.send_now_btn = QPushButton("Kirim Sekarang")
        self.send_now_btn.clicked.connect(lambda: self.send_email_now("[Laporan Pemindaian Sekarang]", self.generate_report_body()))
        export_layout.addWidget(self.send_now_btn)
        layout.addLayout(export_layout)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(["IP", "Port", "Layanan", "Risiko", "Rekomendasi", "CVE Terkait"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.result_table)

        self.tabs.addTab(scanner_tab, "Port Scanner")

    def create_scheduler_tab(self):
        scheduler_tab = QWidget()
        layout = QVBoxLayout(scheduler_tab)

        schedule_group = QGroupBox("Penjadwalan Otomatis")
        schedule_layout = QVBoxLayout()

        self.schedule_type_combo = QComboBox()
        self.schedule_type_combo.addItems(["Harian", "Mingguan"])
        self.schedule_type_combo.currentIndexChanged.connect(self.update_schedule_ui)
        schedule_layout.addWidget(QLabel("Jenis Jadwal:"))
        schedule_layout.addWidget(self.schedule_type_combo)

        time_layout = QHBoxLayout()
        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        time_layout.addWidget(QLabel("Waktu Eksekusi:"))
        time_layout.addWidget(self.time_edit)
        schedule_layout.addLayout(time_layout)

        self.day_combo = QComboBox()
        self.day_combo.addItems([
            "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"
        ])
        self.day_combo.setEnabled(False)
        schedule_layout.addWidget(QLabel("Hari (jika mingguan):"))
        schedule_layout.addWidget(self.day_combo)

        schedule_group.setLayout(schedule_layout)
        layout.addWidget(schedule_group)

        control_layout = QHBoxLayout()
        self.start_schedule_button = QPushButton("Mulai Jadwal")
        self.start_schedule_button.clicked.connect(self.start_scheduled_scan)
        control_layout.addWidget(self.start_schedule_button)
        self.stop_schedule_button = QPushButton("Berhenti")
        self.stop_schedule_button.clicked.connect(self.stop_scheduled_scan)
        self.stop_schedule_button.setEnabled(False)
        control_layout.addWidget(self.stop_schedule_button)
        layout.addLayout(control_layout)

        self.schedule_log = QTextEdit()
        self.schedule_log.setReadOnly(True)
        layout.addWidget(self.schedule_log)

        self.tabs.addTab(scheduler_tab, "Jadwal Otomatis")

    def create_well_known_port_tab(self):
        well_known_tab = QWidget()
        layout = QVBoxLayout(well_known_tab)

        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target IP:"))
        self.target_input_wkp = QLineEdit("192.168.1.1")
        target_layout.addWidget(self.target_input_wkp)
        layout.addLayout(target_layout)

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
            "POP3 (110)": 110
        }
        self.checkboxes = {}
        for name, port in self.wkp_checkboxes.items():
            cb = QRadioButton(name)
            self.checkboxes[name] = cb
            port_layout.addWidget(cb)
        port_group.setLayout(port_layout)
        layout.addWidget(port_group)

        scan_btn = QPushButton("Mulai Pemindaian")
        scan_btn.clicked.connect(self.start_well_known_scan)
        layout.addWidget(scan_btn)

        self.well_known_result_text = QTextEdit()
        self.well_known_result_text.setReadOnly(True)
        layout.addWidget(self.well_known_result_text)

        self.tabs.addTab(well_known_tab, "Well-Known Port")

    def create_cache_tab(self):
        cache_tab = QWidget()
        layout = QVBoxLayout(cache_tab)

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
        load_cache()
        cache_size = len(CVE_CACHE)
        last_modified = os.path.getmtime(CACHE_FILE) if os.path.exists(CACHE_FILE) else None
        self.cache_size_label.setText(str(cache_size))
        self.cache_last_modified_label.setText(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_modified)) if last_modified else "Tidak tersedia"
        )

    def clear_cache(self):
        global CVE_CACHE
        CVE_CACHE.clear()
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
        self.update_cache_status()
        QMessageBox.information(self, "Cache Dihapus", "Semua data cache telah dihapus.")

    def generate_report_body(self):
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
        except Exception as e:
            self.statusBar().showMessage(f"Gagal mengirim email: {str(e)}")
            QMessageBox.critical(self, "Gagal Mengirim", f"Tidak dapat mengirim email.\n{str(e)}")

    def start_scan(self):
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

        self.scanner_thread = PortScannerThread(ip_range, start_port, end_port, timeout, scan_type)
        self.scanner_thread.update_result.connect(self.add_result)
        self.scanner_thread.update_progress.connect(self.progress_bar.setValue)
        self.scanner_thread.scan_complete.connect(self.scan_finished)
        self.scanner_thread.start()

    def stop_scan(self):
        if hasattr(self, 'scanner_thread') and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.statusBar().showMessage("Pemindaian dihentikan oleh pengguna.")
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def add_result(self, ip, port, service, risk, mitigation, cves):
        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)
        color = QColor(Qt.green)
        if risk == "HIGH":
            color = QColor(255, 0, 0, 150)
        elif risk == "MEDIUM":
            color = QColor(255, 165, 0, 150)
        elif risk == "LOW":
            color = QColor(0, 255, 0, 150)
        for col, text in enumerate([ip, str(port), service, risk, mitigation, cves]):
            item = QTableWidgetItem(text)
            item.setBackground(color)
            self.result_table.setItem(row_position, col, item)
        self.network_analyzer.add_host(ip, (port, service, risk))

    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(f"Pemindaian selesai. Ditemukan {self.result_table.rowCount()} port terbuka.")

    def export_to_pdf(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Simpan Laporan sebagai PDF", "", "PDF Files (*.pdf)", options=options)
        if not file_path:
            return

        doc = SimpleDocTemplate(file_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        title = Paragraph("Laporan Hasil Pemindaian Port", styles['Title'])
        elements.append(title)
        elements.append(Spacer(1, 12))

        data = [["IP", "Port", "Layanan", "Risiko", "Rekomendasi", "CVE Terkait"]]
        for row in range(self.result_table.rowCount()):
            row_data = [self.result_table.item(row, col).text() for col in range(6)]
            data.append(row_data)
        table = Table(data)
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])
        table.setStyle(style)
        elements.append(table)

        graph_image_path = self.network_analyzer.visualize_network()
        if os.path.exists(graph_image_path):
            img = Image(graph_image_path)
            img.drawWidth = 400
            img.drawHeight = 300
            elements.append(Spacer(1, 24))
            elements.append(Paragraph("Visualisasi Jaringan", styles['Heading2']))
            elements.append(img)
            os.remove(graph_image_path)

        elements.append(Spacer(1, 24))
        elements.append(Paragraph(f"Dicetak pada: {time.strftime('%Y-%m-%d %H:%M')}", styles['Normal']))

        doc.build(elements)
        try:
            QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
            QMessageBox.information(self, "Berhasil", f"Laporan berhasil disimpan dan dibuka:\n{file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Gagal Membuka", f"Laporan tersimpan tetapi gagal dibuka:\n{file_path}\n{str(e)}")

    def update_schedule_ui(self):
        is_weekly = self.schedule_type_combo.currentText() == "Mingguan"
        self.day_combo.setEnabled(is_weekly)

    def start_scheduled_scan(self):
        if hasattr(self, 'schedule_timer'):
            self.stop_scheduled_scan()
        self.schedule_timer = QTimer()
        self.schedule_timer.timeout.connect(self.check_and_run_scheduled_scan)
        self.schedule_timer.start(60000)
        self.start_schedule_button.setEnabled(False)
        self.stop_schedule_button.setEnabled(True)
        self.log_schedule("Jadwal otomatis dimulai.")

    def stop_scheduled_scan(self):
        if hasattr(self, 'schedule_timer'):
            self.schedule_timer.stop()
            del self.schedule_timer
        self.start_schedule_button.setEnabled(True)
        self.stop_schedule_button.setEnabled(False)
        self.log_schedule("Jadwal otomatis dihentikan.")

    def check_and_run_scheduled_scan(self):
        now = QDateTime.currentDateTime()
        current_time = now.time()
        scheduled_time = self.time_edit.time()
        if current_time.hour() == scheduled_time.hour() and current_time.minute() == scheduled_time.minute():
            self.run_scheduled_scan()

    def run_scheduled_scan(self):
        ip_range = "192.168.1.1/24"
        start_port = 1
        end_port = 1024
        timeout = 2
        self.log_schedule(f"Memulai pemindaian otomatis pada {QDateTime.currentDateTime().toString()}")
        self.scanner_thread = PortScannerThread(ip_range, start_port, end_port, timeout, scan_type="TCP")
        self.scanner_thread.update_result.connect(self.add_result)
        self.scanner_thread.update_progress.connect(self.progress_bar.setValue)
        self.scanner_thread.scan_complete.connect(lambda: self.finish_scheduled_scan(ip_range))
        self.scanner_thread.start()

    def finish_scheduled_scan(self, ip_range):
        self.log_schedule(f"Pemindaian otomatis selesai. Ditemukan {self.result_table.rowCount()} port terbuka.")
        body = f"Pemindaian otomatis selesai.\nRingkasan hasil pemindaian:"
        for row in range(min(10, self.result_table.rowCount())):  # Batas 10 baris
            ip = self.result_table.item(row, 0).text()
            port = self.result_table.item(row, 1).text()
            service = self.result_table.item(row, 2).text()
            risk = self.result_table.item(row, 3).text()
            body += f"\n- IP: {ip}, Port: {port}, Layanan: {service}, Risiko: {risk}"
        self.send_email_update("[Laporan Otomatis] Hasil Pemindaian", body)

    def log_schedule(self, message):
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
        self.schedule_log.append(f"[{timestamp}] {message}")

    def send_email_update(self, subject, body):
        sender = self.email_sender.text().strip()
        password = self.email_password.text().strip()
        receiver = self.email_receiver.text().strip()
        if not sender or not password or not receiver:
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
            server.close()
            self.statusBar().showMessage("Email terkirim.")
        except Exception as e:
            self.statusBar().showMessage(f"Gagal mengirim email: {str(e)}")

    def start_well_known_scan(self):
        target_ip = self.target_input_wkp.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "Input Tidak Valid", "Silakan masukkan alamat IP target.")
            return
        selected_ports = [port for name, port in self.wkp_checkboxes.items() if self.checkboxes[name].isChecked()]
        if not selected_ports:
            QMessageBox.warning(self, "Input Tidak Lengkap", "Pilih setidaknya satu port terkenal.")
            return

        self.well_known_result_text.clear()
        self.well_known_result_text.append(f"Pemindaian dimulai pada {target_ip}...\nHasil:\n")
        results = []
        for port in selected_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    try:
                        service = socket.getservbyport(port, "tcp") if port < 1024 else ""
                    except:
                        service = ""
                    risk = self.common_ports.get(port, ("", "UNKNOWN"))[1]
                    mitigation = self.risk_mitigation.get(risk, "Identifikasi layanan.")
                    cves = get_cves_for_service(service)
                    uptime = time.strftime("%Y-%m-%d %H:%M:%S")
                    results.append((port, service, "Terbuka", risk, mitigation, cves, uptime))
                    self.well_known_result_text.append(
                        f"Port {port}: Terbuka\nLayanan: {service}\nRisiko: {risk}\nDaftar CVE: {cves}\n{'-'*30}\n"
                    )
                else:
                    self.well_known_result_text.append(f"Port {port}: Tertutup\n{'-'*30}\n")
            except Exception as e:
                self.well_known_result_text.append(f"Port {port}: Gagal memindai - {str(e)}\n{'-'*30}\n")
        self.well_known_result_text.append("\nPemindaian selesai.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortMasterApp()
    window.show()
    sys.exit(app.exec_())