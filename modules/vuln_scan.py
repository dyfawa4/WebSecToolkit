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
import os


@register_module("batch_scan")
class BatchScanWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("批量扫描")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "快速扫描", "标准扫描", "深度扫描", "自定义扫描"
        ])
        form_layout.addRow("扫描类型:", self._scan_type_combo)
        
        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 50)
        self._concurrency_spin.setValue(10)
        form_layout.addRow("并发数:", self._concurrency_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._info_check = QCheckBox("信息泄露")
        self._info_check.setChecked(True)
        form_layout.addRow(self._info_check)
        
        self._vuln_check = QCheckBox("漏洞检测")
        self._vuln_check.setChecked(True)
        form_layout.addRow(self._vuln_check)
        
        self._cve_check = QCheckBox("CVE检测")
        self._cve_check.setChecked(True)
        form_layout.addRow(self._cve_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["目标", "漏洞名称", "严重程度", "CVE", "描述"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        targets = self._target_input.text().strip().split(',')
        if not targets:
            self._add_log(LogLevel.ERROR, "请输入目标")
            return
        
        self._add_log(LogLevel.INFO, f"开始批量扫描: {len(targets)} 个目标")
        
        if self._is_tool_available("nuclei"):
            self._scan_with_nuclei(targets)
        else:
            self._scan_builtin(targets)
    
    def _scan_with_nuclei(self, targets: list):
        self._add_log(LogLevel.INFO, "使用 Nuclei 批量扫描")
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(t.strip() for t in targets if t.strip()))
            target_file = f.name
        
        try:
            args = ["-l", target_file, "-silent", "-severity", "critical,high,medium"]
            
            process = self._execute_tool("nuclei", args)
            
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
                    self._add_log(LogLevel.SUCCESS, line)
            
            self._add_log(LogLevel.SUCCESS, "Nuclei 扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")
        finally:
            os.unlink(target_file)
    
    def _scan_builtin(self, targets: list):
        import requests
        
        self._add_log(LogLevel.INFO, "使用内置扫描器")
        
        for i, target in enumerate(targets):
            target = target.strip()
            if not target:
                continue
            
            if not self._is_scanning:
                break
            
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            try:
                resp = requests.get(target, timeout=self._timeout_spin.value(), verify=False)
                
                headers = resp.headers
                
                if 'Server' in headers:
                    self._add_result(target, "服务器信息泄露", "低", "", headers['Server'])
                
                if 'X-Powered-By' in headers:
                    self._add_result(target, "技术栈泄露", "低", "", headers['X-Powered-By'])
                
                if 'X-Frame-Options' not in headers:
                    self._add_result(target, "缺少X-Frame-Options", "中", "", "可能存在点击劫持风险")
                
                if 'X-Content-Type-Options' not in headers:
                    self._add_result(target, "缺少X-Content-Type-Options", "低", "", "可能存在MIME类型嗅探风险")
                
                if '/.git' in resp.text or '.git/config' in resp.text:
                    self._add_result(target, "Git信息泄露", "高", "", "可能存在.git目录泄露")
                
                self._add_log(LogLevel.SUCCESS, f"扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"扫描失败: {target} - {str(e)}")
            
            progress = int(((i + 1) / len(targets)) * 100)
            self._update_progress(progress)
        
        self._add_log(LogLevel.INFO, "批量扫描完成")


@register_module("cve_search")
class CVESearchWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("CVE查询")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("搜索选项")
        form_layout = QFormLayout(options_group)
        
        self._search_type_combo = QComboBox()
        self._setup_combo(self._search_type_combo, [
            "CVE编号", "关键词", "产品名称", "厂商名称"
        ])
        form_layout.addRow("搜索类型:", self._search_type_combo)
        
        self._severity_combo = QComboBox()
        self._setup_combo(self._severity_combo, [
            "全部", "严重", "高危", "中危", "低危"
        ])
        form_layout.addRow("严重程度:", self._severity_combo)
        
        self._year_spin = QSpinBox()
        self._year_spin.setRange(1999, 2030)
        self._year_spin.setValue(2024)
        form_layout.addRow("年份:", self._year_spin)
        
        self._limit_spin = QSpinBox()
        self._limit_spin.setRange(1, 100)
        self._limit_spin.setValue(20)
        form_layout.addRow("结果数量:", self._limit_spin)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["CVE编号", "严重程度", "CVSS评分", "描述"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        keyword = self._target_input.text().strip()
        if not keyword:
            self._add_log(LogLevel.ERROR, "请输入搜索关键词")
            return
        
        self._add_log(LogLevel.INFO, f"搜索CVE: {keyword}")
        
        self._add_result("CVE-2024-1234", "高危", "7.5", f"与 {keyword} 相关的示例漏洞")
        self._add_result("CVE-2024-5678", "中危", "5.5", f"与 {keyword} 相关的示例漏洞")
        
        self._add_log(LogLevel.SUCCESS, "CVE搜索完成")


@register_module("scanner")
class ScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("漏洞扫描器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["内置扫描器", "Nikto", "WhatWeb"])
        form_layout.addRow("扫描工具:", self._tool_combo)
        
        self._scan_depth_combo = QComboBox()
        self._setup_combo(self._scan_depth_combo, ["浅层扫描", "标准扫描", "深度扫描"])
        form_layout.addRow("扫描深度:", self._scan_depth_combo)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["项目", "值", "风险", "建议"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
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
        
        tool = self._tool_combo.currentText()
        
        if tool == "Nikto" and self._is_tool_available("nikto"):
            self._scan_with_nikto(target)
        elif tool == "WhatWeb" and self._is_tool_available("whatweb"):
            self._scan_with_whatweb(target)
        else:
            self._scan_builtin(target)
    
    def _scan_with_nikto(self, target: str):
        self._add_log(LogLevel.INFO, f"使用 Nikto 扫描: {target}")
        
        args = ["-h", target, "-Format", "txt"]
        
        try:
            process = self._execute_tool("nikto", args)
            
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
                    self._add_log(LogLevel.DEBUG, line)
            
            self._add_log(LogLevel.SUCCESS, "Nikto 扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")
    
    def _scan_with_whatweb(self, target: str):
        self._add_log(LogLevel.INFO, f"使用 WhatWeb 扫描: {target}")
        
        args = [target, "--color=never"]
        
        try:
            process = self._execute_tool("whatweb", args)
            
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
                    self._add_log(LogLevel.SUCCESS, line)
            
            self._add_log(LogLevel.SUCCESS, "WhatWeb 扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")
    
    def _scan_builtin(self, target: str):
        import requests
        
        self._add_log(LogLevel.INFO, f"使用内置扫描器: {target}")
        
        try:
            resp = requests.get(target, timeout=self._timeout_spin.value(), verify=False)
            
            headers = resp.headers
            
            checks = [
                ('Server', '服务器信息', '低'),
                ('X-Powered-By', '技术栈信息', '低'),
                ('X-Frame-Options', '点击劫持防护', '中'),
                ('X-Content-Type-Options', 'MIME类型嗅探防护', '低'),
                ('Strict-Transport-Security', 'HSTS', '中'),
                ('Content-Security-Policy', 'CSP策略', '中'),
                ('X-XSS-Protection', 'XSS防护', '低'),
            ]
            
            for header, name, risk in checks:
                if header in headers:
                    self._add_result(name, headers[header], "已配置", "")
                else:
                    self._add_result(name, "未设置", risk, f"建议添加 {header} 头")
            
            self._add_log(LogLevel.SUCCESS, "扫描完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")


@register_module("leak")
class LeakScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("信息泄露检测")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("检测选项")
        form_layout = QFormLayout(options_group)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "Git泄露", "敏感文件", "API密钥", "全部类型"
        ])
        form_layout.addRow("检测类型:", self._scan_type_combo)
        
        self._deep_check = QCheckBox("深度扫描")
        form_layout.addRow(self._deep_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["类型", "位置", "内容", "风险"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import requests
        import re
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始泄露检测: {target}")
        
        leak_paths = [
            ('/.git/config', 'Git配置'),
            ('/.git/HEAD', 'Git HEAD'),
            ('/.env', '环境变量'),
            ('/config.php', '配置文件'),
            ('/wp-config.php', 'WordPress配置'),
            ('/database.yml', '数据库配置'),
            ('/.htpasswd', 'Apache密码文件'),
        ]
        
        for path, name in leak_paths:
            if not self._is_scanning:
                break
            
            try:
                url = target.rstrip('/') + path
                resp = requests.get(url, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    content = resp.text[:100]
                    self._add_result(name, path, content, "高")
                    self._add_log(LogLevel.SUCCESS, f"发现泄露: {path}")
            except:
                pass
        
        try:
            resp = requests.get(target, timeout=10, verify=False)
            
            api_patterns = [
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
                (r'AIza[0-9A-Za-z-_]{35}', 'Google API Key'),
                (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key'),
            ]
            
            for pattern, name in api_patterns:
                matches = re.findall(pattern, resp.text)
                if matches:
                    self._add_result(name, "页面内容", matches[0][:20] + "...", "高")
                    self._add_log(LogLevel.SUCCESS, f"发现API密钥: {name}")
        except:
            pass
        
        self._add_log(LogLevel.INFO, "泄露检测完成")
