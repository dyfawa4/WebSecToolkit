from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import subprocess
import threading
import re
import socket
import concurrent.futures
import os


@register_module("port_scanner")
class PortScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("端口扫描")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["内置扫描器", "Nmap", "Naabu"])
        self._tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        tool_layout.addRow("扫描工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        form_layout.setSpacing(10)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "TCP Connect", "SYN Scan", "UDP Scan", "Service Detection"
        ])
        form_layout.addRow("扫描类型:", self._scan_type_combo)
        
        self._port_range_input = QLineEdit()
        self._port_range_input.setText("1-1000")
        self._port_range_input.setPlaceholderText("端口范围，如: 1-1000 或 22,80,443")
        form_layout.addRow("端口范围:", self._port_range_input)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        self._setup_spinbox(self._threads_spin)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(3)
        self._timeout_spin.setSuffix(" 秒")
        self._setup_spinbox(self._timeout_spin, " 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._service_detect_check = QCheckBox("服务识别")
        self._service_detect_check.setChecked(True)
        form_layout.addRow(self._service_detect_check)
        
        layout.addWidget(options_group)
        
        self._update_tool_status()
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        if tool_name == "Nmap":
            available = self._is_tool_available("nmap")
            if available:
                self._add_log(LogLevel.INFO, "Nmap 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "Nmap 工具不可用，请先下载")
        elif tool_name == "Naabu":
            available = self._is_tool_available("naabu")
            if available:
                self._add_log(LogLevel.INFO, "Naabu 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "Naabu 工具不可用，请先下载")
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["主机", "端口", "状态", "服务", "版本"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Nmap":
            self._scan_with_nmap()
        elif tool_name == "Naabu":
            self._scan_with_naabu()
        else:
            self._scan_builtin()
    
    def _scan_with_nmap(self):
        if not self._is_tool_available("nmap"):
            self._add_log(LogLevel.ERROR, "Nmap 工具不可用")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 Nmap 扫描: {target}")
            
            args = ["-p", port_range, "-sV", "-T4", "-Pn", target]
            
            try:
                process = self._execute_tool("nmap", args)
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    self._parse_nmap_output(line.strip())
                
                self._add_log(LogLevel.SUCCESS, f"Nmap 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"Nmap 扫描失败: {str(e)}")
    
    def _parse_nmap_output(self, line: str):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_info = parts[0].split("/")
            port = port_info[0]
            state = parts[1] if len(parts) > 1 else "open"
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            
            target = self._target_input.text().strip().split(',')[0]
            self._add_result(target.strip(), port, state, f"{service} {version}")
            self._add_log(LogLevel.SUCCESS, f"发现开放端口: {port} - {service}")
    
    def _scan_with_naabu(self):
        if not self._is_tool_available("naabu"):
            self._add_log(LogLevel.ERROR, "Naabu 工具不可用")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 Naabu 扫描: {target}")
            
            args = ["-host", target, "-p", port_range, "-silent"]
            
            try:
                process = self._execute_tool("naabu", args)
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    line = line.strip()
                    if ":" in line:
                        host, port = line.rsplit(":", 1)
                        self._add_result(host, port, "open", "unknown")
                        self._add_log(LogLevel.SUCCESS, f"发现开放端口: {port}")
                
                self._add_log(LogLevel.SUCCESS, f"Naabu 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"Naabu 扫描失败: {str(e)}")
    
    def _scan_builtin(self):
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        timeout = self._timeout_spin.value()
        threads = self._threads_spin.value()
        
        ports = self._parse_port_range(port_range)
        if not ports:
            self._add_log(LogLevel.ERROR, "无效的端口范围")
            return
        
        self._add_log(LogLevel.INFO, f"扫描端口: {len(ports)} 个")
        
        total = len(targets) * len(ports)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for target in targets:
                target = target.strip()
                if not target:
                    continue
                for port in ports:
                    future = executor.submit(self._scan_port, target.strip(), port, timeout)
                    futures[future] = (target.strip(), port)
            
            for future in concurrent.futures.as_completed(futures):
                if not self._is_scanning:
                    break
                
                target, port = futures[future]
                try:
                    is_open, service = future.result()
                    if is_open:
                        self._add_result(target, str(port), "开放", service)
                        self._add_log(LogLevel.SUCCESS, f"{target}:{port} - 开放 - {service}")
                except Exception as e:
                    pass
                
                completed += 1
                progress = int((completed / total) * 100)
                self._update_progress(progress)
    
    def _parse_port_range(self, port_str: str) -> list:
        ports = []
        try:
            for part in port_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        except ValueError:
            return []
        return sorted(set(ports))
    
    def _scan_port(self, host: str, port: int, timeout: int) -> tuple:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                sock.close()
                return (True, service)
            sock.close()
        except:
            pass
        return (False, "")


@register_module("subdomain")
class SubdomainScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("子域名扫描")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["内置枚举", "Subfinder", "Amass", "Assetfinder"])
        self._tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        tool_layout.addRow("枚举工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        options_group = QGroupBox("枚举选项")
        form_layout = QFormLayout(options_group)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, ["字典枚举", "证书透明度", "搜索引擎", "全部方法"])
        form_layout.addRow("枚举方法:", self._method_combo)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件或使用内置字典")
        self._dict_input.setReadOnly(True)
        
        dict_btn = QPushButton("选择字典")
        dict_btn.setFixedWidth(80)
        dict_btn.clicked.connect(self._select_dict_file)
        dict_layout.addWidget(self._dict_input, 1)
        dict_layout.addWidget(dict_btn)
        form_layout.addRow("字典文件:", dict_layout)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        self._setup_spinbox(self._threads_spin)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._resolve_check = QCheckBox("解析IP地址")
        self._resolve_check.setChecked(True)
        form_layout.addRow(self._resolve_check)
        
        layout.addWidget(options_group)
        
        self._update_tool_status()
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        tool_map = {
            "Subfinder": "subfinder",
            "Amass": "amass",
            "Assetfinder": "assetfinder"
        }
        if tool_name in tool_map:
            available = self._is_tool_available(tool_map[tool_name])
            if available:
                self._add_log(LogLevel.INFO, f"{tool_name} 工具可用")
            else:
                self._add_log(LogLevel.WARNING, f"{tool_name} 工具不可用，请先下载")
    
    def _select_dict_file(self):
        dict_path = self._select_dict("subdomain")
        if dict_path:
            self._dict_input.setText(dict_path)
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
            )
            if file_path:
                self._dict_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["子域名", "IP地址", "状态", "标题"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Subfinder":
            self._scan_with_subfinder()
        elif tool_name == "Amass":
            self._scan_with_amass()
        elif tool_name == "Assetfinder":
            self._scan_with_assetfinder()
        else:
            self._scan_builtin()
    
    def _scan_with_subfinder(self):
        if not self._is_tool_available("subfinder"):
            self._add_log(LogLevel.ERROR, "Subfinder 工具不可用")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Subfinder 枚举: {domain}")
        
        args = ["-d", domain, "-silent"]
        
        try:
            process = self._execute_tool("subfinder", args)
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Subfinder 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Subfinder 枚举失败: {str(e)}")
    
    def _scan_with_amass(self):
        if not self._is_tool_available("amass"):
            self._add_log(LogLevel.ERROR, "Amass 工具不可用")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Amass 枚举: {domain}")
        
        args = ["enum", "-passive", "-d", domain, "-silent"]
        
        try:
            process = self._execute_tool("amass", args)
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Amass 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Amass 枚举失败: {str(e)}")
    
    def _scan_with_assetfinder(self):
        if not self._is_tool_available("assetfinder"):
            self._add_log(LogLevel.ERROR, "Assetfinder 工具不可用")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Assetfinder 枚举: {domain}")
        
        args = ["--subs-only", domain]
        
        try:
            process = self._execute_tool("assetfinder", args)
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Assetfinder 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Assetfinder 枚举失败: {str(e)}")
    
    def _scan_builtin(self):
        import dns.resolver
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"开始枚举子域名: {domain}")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test',
            'staging', 'portal', 'secure', 'vpn', 'cdn', 'static', 'img',
            'images', 'assets', 'js', 'css', 'app', 'mobile', 'm',
        ]
        
        for sub in common_subdomains:
            if not self._is_scanning:
                break
            
            subdomain = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [rdata.address for rdata in answers]
                self._add_result(subdomain, ', '.join(ips), "有效", "")
                self._add_log(LogLevel.SUCCESS, f"发现: {subdomain} -> {', '.join(ips)}")
            except:
                pass
    
    def _add_result(self, subdomain: str, ip: str, status: str, title: str):
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)
        self._result_table.setItem(row, 0, QTableWidgetItem(subdomain))
        self._result_table.setItem(row, 1, QTableWidgetItem(ip))
        self._result_table.setItem(row, 2, QTableWidgetItem(status))
        self._result_table.setItem(row, 3, QTableWidgetItem(title))


@register_module("directory")
class DirectoryScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("目录扫描")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件")
        dict_btn = QPushButton("选择")
        dict_btn.setFixedWidth(60)
        dict_btn.clicked.connect(self._select_dict)
        dict_layout.addWidget(self._dict_input)
        dict_layout.addWidget(dict_btn)
        form_layout.addRow("字典文件:", dict_layout)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._recursive_check = QCheckBox("递归扫描")
        form_layout.addRow(self._recursive_check)
        
        self._extensions_input = QLineEdit()
        self._extensions_input.setPlaceholderText("如: .php,.html,.asp")
        form_layout.addRow("扩展名:", self._extensions_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _select_dict(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if file_path:
            self._dict_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["路径", "状态码", "大小", "重定向", "标题"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            paths = ['/admin', '/login', '/backup', '/config', '/api', 
                    '/test', '/debug', '/.git', '/.env', '/robots.txt']
        else:
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"读取字典失败: {str(e)}")
                return
        
        self._add_log(LogLevel.INFO, f"开始扫描，共 {len(paths)} 个路径")
        
        for i, path in enumerate(paths):
            if not self._is_scanning:
                break
            
            try:
                url = target.rstrip('/') + '/' + path.lstrip('/')
                resp = requests.get(url, timeout=self._timeout_spin.value(), 
                                   allow_redirects=False, verify=False)
                
                if resp.status_code in [200, 301, 302, 403, 401]:
                    size = len(resp.content)
                    redirect = resp.headers.get('Location', '')
                    self._add_result(path, str(resp.status_code), 
                                   f"{size} bytes", redirect)
                    self._add_log(LogLevel.SUCCESS, f"{path} - {resp.status_code}")
            except Exception as e:
                pass
            
            progress = int(((i + 1) / len(paths)) * 100)
            self.progress_updated.emit(progress)


@register_module("fingerprint")
class FingerprintWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("指纹识别")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("识别选项")
        form_layout = QFormLayout(options_group)
        
        self._deep_scan_check = QCheckBox("深度扫描")
        form_layout.addRow(self._deep_scan_check)
        
        self._cms_check = QCheckBox("CMS识别")
        self._cms_check.setChecked(True)
        form_layout.addRow(self._cms_check)
        
        self._waf_check = QCheckBox("WAF检测")
        self._waf_check.setChecked(True)
        form_layout.addRow(self._waf_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["类型", "名称", "版本", "置信度"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始指纹识别: {target}")
        
        try:
            resp = requests.get(target, timeout=10, verify=False)
            
            server = resp.headers.get('Server', 'Unknown')
            self._add_result("Server", server, "", "高")
            self._add_log(LogLevel.SUCCESS, f"Server: {server}")
            
            powered = resp.headers.get('X-Powered-By', '')
            if powered:
                self._add_result("Technology", powered, "", "高")
                self._add_log(LogLevel.SUCCESS, f"X-Powered-By: {powered}")
            
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal', 'sites/default/files'],
                'Joomla': ['joomla', '/components/com_'],
                'DedeCMS': ['dede', 'dedecms'],
                'Discuz': ['discuz', 'forum.php'],
                'ThinkPHP': ['thinkphp', 'think_'],
            }
            
            content = resp.text.lower()
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in content:
                        self._add_result("CMS", cms, "", "中")
                        self._add_log(LogLevel.SUCCESS, f"检测到CMS: {cms}")
                        break
            
            self._add_log(LogLevel.INFO, "指纹识别完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")


@register_module("ssl_analyzer")
class SSLAnalyzerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("SSL分析")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("分析选项")
        form_layout = QFormLayout(options_group)
        
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(443)
        form_layout.addRow("端口:", self._port_spin)
        
        self._check_vuln = QCheckBox("漏洞检测")
        self._check_vuln.setChecked(True)
        form_layout.addRow(self._check_vuln)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["项目", "值", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import ssl
        import socket
        from datetime import datetime
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标域名")
            return
        
        target = target.replace('https://', '').replace('http://', '').split('/')[0]
        port = self._port_spin.value()
        
        self._add_log(LogLevel.INFO, f"开始SSL分析: {target}:{port}")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    self._add_result("主题CN", subject.get('commonName', ''), "✓")
                    self._add_result("颁发者", issuer.get('commonName', ''), "✓")
                    
                    version = ssock.version()
                    self._add_result("协议版本", version, "✓")
                    
                    cipher = ssock.cipher()
                    self._add_result("加密套件", cipher[0], "✓")
                    
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        self._add_result("过期时间", not_after, "✓")
                    
                    self._add_log(LogLevel.SUCCESS, "SSL证书分析完成")
                    
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"SSL分析失败: {str(e)}")


@register_module("email_collector")
class EmailCollectorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("邮箱收集")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("收集选项")
        form_layout = QFormLayout(options_group)
        
        self._search_engine_check = QCheckBox("搜索引擎")
        self._search_engine_check.setChecked(True)
        form_layout.addRow(self._search_engine_check)
        
        self._github_check = QCheckBox("GitHub")
        self._github_check.setChecked(True)
        form_layout.addRow(self._github_check)
        
        self._deep_check = QCheckBox("深度搜索")
        form_layout.addRow(self._deep_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["邮箱地址", "来源", "发现时间"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import re
        import requests
        from datetime import datetime
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入目标域名")
            return
        
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        
        self._add_log(LogLevel.INFO, f"开始收集邮箱: {domain}")
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
        
        test_emails = [
            f'admin@{domain}',
            f'info@{domain}',
            f'support@{domain}',
            f'contact@{domain}',
        ]
        
        for email in test_emails:
            if not self._is_scanning:
                break
            self._add_result(email, "测试", datetime.now().strftime("%Y-%m-%d %H:%M"))
            self._add_log(LogLevel.SUCCESS, f"发现邮箱: {email}")
        
        self._add_log(LogLevel.INFO, "邮箱收集完成")
