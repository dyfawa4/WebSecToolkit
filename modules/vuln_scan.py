from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox,
    QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QSplitter, QFrame, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import subprocess
import threading
import os
import re
import json
import tempfile
from pathlib import Path


class NucleiWorker(QThread):
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, list)
    
    def __init__(self, nuclei_path, args, target=None):
        super().__init__()
        self._nuclei_path = nuclei_path
        self._args = args
        self._target = target
        self._is_cancelled = False
        self._process = None
        self._results = []
    
    def run(self):
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            
            self._process = subprocess.Popen(
                self._args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=True,
                creationflags=creation_flags
            )
            
            while True:
                if self._is_cancelled:
                    self._process.terminate()
                    break
                
                line = self._process.stdout.readline()
                if not line:
                    if self._process.poll() is not None:
                        break
                    continue
                
                line = line.rstrip()
                self.output_received.emit(line)
                
                if '[' in line and ']' in line:
                    self._parse_nuclei_result(line)
            
            self.finished_signal.emit(True, self._results)
            
        except Exception as e:
            self.output_received.emit(f"Error: {str(e)}")
            self.finished_signal.emit(False, self._results)
    
    def _parse_nuclei_result(self, line: str):
        try:
            severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
            if severity_match:
                severity = severity_match.group(1).lower()
                
                template_match = re.search(r'\[([^\]]+)\]', line)
                template = template_match.group(1) if template_match else "unknown"
                
                url_match = re.search(r'https?://[^\s]+', line)
                url = url_match.group(0) if url_match else self._target or ""
                
                self._results.append({
                    'template': template,
                    'severity': severity,
                    'url': url,
                    'line': line
                })
        except:
            pass
    
    def cancel(self):
        self._is_cancelled = True
        if self._process:
            self._process.terminate()


class SearchSploitWorker(QThread):
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, list)
    
    def __init__(self, searchsploit_path, query):
        super().__init__()
        self._searchsploit_path = searchsploit_path
        self._query = query
        self._is_cancelled = False
        self._process = None
        self._results = []
    
    def run(self):
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            
            cmd = f'python "{self._searchsploit_path}" --json {self._query}'
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                creationflags=creation_flags
            )
            
            stdout, stderr = self._process.communicate(timeout=60)
            
            self.output_received.emit(stdout)
            
            try:
                data = json.loads(stdout)
                if 'RESULTS_EXPLOIT' in data:
                    for item in data['RESULTS_EXPLOIT']:
                        self._results.append({
                            'title': item.get('Title', ''),
                            'type': item.get('Type', ''),
                            'platform': item.get('Platform', ''),
                            'path': item.get('Path', ''),
                            'cve': item.get('Codes', '')
                        })
            except json.JSONDecodeError:
                lines = stdout.split('\n')
                for line in lines:
                    if '|' in line and not line.startswith('|'):
                        parts = [p.strip() for p in line.split('|') if p.strip()]
                        if len(parts) >= 2:
                            self._results.append({
                                'title': parts[0],
                                'type': parts[1] if len(parts) > 1 else '',
                                'platform': parts[2] if len(parts) > 2 else '',
                                'path': '',
                                'cve': ''
                            })
            
            self.finished_signal.emit(True, self._results)
            
        except Exception as e:
            self.output_received.emit(f"Error: {str(e)}")
            self.finished_signal.emit(False, self._results)
    
    def cancel(self):
        self._is_cancelled = True
        if self._process:
            self._process.terminate()


@register_module("batch_scan")
class BatchScanWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("batch_scan", "批量扫描")
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tabs = QTabWidget()
        
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["Nuclei", "内置扫描"])
        tool_layout.addRow("扫描工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        options_group = QGroupBox("Nuclei 基本选项")
        form_layout = QFormLayout(options_group)
        
        severity_layout = QHBoxLayout()
        self._critical_check = QCheckBox("critical")
        self._critical_check.setChecked(True)
        self._high_check = QCheckBox("high")
        self._high_check.setChecked(True)
        self._medium_check = QCheckBox("medium")
        self._medium_check.setChecked(True)
        self._low_check = QCheckBox("low")
        self._info_check = QCheckBox("info")
        severity_layout.addWidget(self._critical_check)
        severity_layout.addWidget(self._high_check)
        severity_layout.addWidget(self._medium_check)
        severity_layout.addWidget(self._low_check)
        severity_layout.addWidget(self._info_check)
        severity_layout.addStretch()
        form_layout.addRow("严重程度:", severity_layout)
        
        self._tags_input = QLineEdit()
        self._tags_input.setPlaceholderText("标签过滤，如: cve,rce,sqli (逗号分隔)")
        form_layout.addRow("包含标签:", self._tags_input)
        
        self._excludeTags_input = QLineEdit()
        self._excludeTags_input.setPlaceholderText("排除标签，如: dos,fuzz")
        form_layout.addRow("排除标签:", self._excludeTags_input)
        
        self._templates_input = QLineEdit()
        self._templates_input.setPlaceholderText("自定义模板目录 (可选)")
        templates_btn = QPushButton("选择")
        templates_btn.setFixedWidth(60)
        templates_btn.clicked.connect(self._select_templates)
        templates_layout = QHBoxLayout()
        templates_layout.addWidget(self._templates_input)
        templates_layout.addWidget(templates_btn)
        form_layout.addRow("模板目录:", templates_layout)
        
        self._templateId_input = QLineEdit()
        self._templateId_input.setPlaceholderText("指定模板ID (逗号分隔)")
        form_layout.addRow("模板ID:", self._templateId_input)
        
        self._concurrency_spin = QSpinBox()
        self._concurrency_spin.setRange(1, 100)
        self._concurrency_spin.setValue(10)
        form_layout.addRow("并发数:", self._concurrency_spin)
        
        self._rate_limit_spin = QSpinBox()
        self._rate_limit_spin.setRange(1, 1000)
        self._rate_limit_spin.setValue(150)
        form_layout.addRow("速率限制:", self._rate_limit_spin)
        
        self._bulkSize_spin = QSpinBox()
        self._bulkSize_spin.setRange(1, 1000)
        self._bulkSize_spin.setValue(25)
        form_layout.addRow("批量大小:", self._bulkSize_spin)
        
        basic_layout.addWidget(options_group)
        tabs.addTab(basic_tab, "基本选项")
        
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        advanced_group = QGroupBox("高级选项")
        advanced_form = QFormLayout(advanced_group)
        
        self._headless_check = QCheckBox("启用Headless浏览器")
        advanced_form.addRow(self._headless_check)
        
        self._headlessOptions_input = QLineEdit()
        self._headlessOptions_input.setPlaceholderText("Headless选项，如: --headless-options=--no-sandbox")
        advanced_form.addRow("Headless选项:", self._headlessOptions_input)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 300)
        self._timeout_spin.setValue(5)
        self._timeout_spin.setSuffix(" 秒")
        advanced_form.addRow("超时时间:", self._timeout_spin)
        
        self._retries_spin = QSpinBox()
        self._retries_spin.setRange(0, 10)
        self._retries_spin.setValue(1)
        advanced_form.addRow("重试次数:", self._retries_spin)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 60)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" 秒")
        advanced_form.addRow("请求延迟:", self._delay_spin)
        
        self._proxy_input = QLineEdit()
        self._proxy_input.setPlaceholderText("代理地址，如: http://127.0.0.1:8080")
        advanced_form.addRow("代理:", self._proxy_input)
        
        self._silent_check = QCheckBox("静默模式")
        self._silent_check.setChecked(True)
        advanced_form.addRow(self._silent_check)
        
        self._verbose_check = QCheckBox("详细输出")
        advanced_form.addRow(self._verbose_check)
        
        self._debug_check = QCheckBox("调试模式")
        advanced_form.addRow(self._debug_check)
        
        self._update_templates_check = QCheckBox("自动更新模板")
        advanced_form.addRow(self._update_templates_check)
        
        self._validate_check = QCheckBox("验证模板")
        advanced_form.addRow(self._validate_check)
        
        advanced_layout.addWidget(advanced_group)
        advanced_layout.addStretch()
        tabs.addTab(advanced_tab, "高级选项")
        
        output_tab = QWidget()
        output_layout = QVBoxLayout(output_tab)
        
        output_group = QGroupBox("输出选项")
        output_form = QFormLayout(output_group)
        
        self._outputFormat_combo = QComboBox()
        self._setup_combo(self._outputFormat_combo, [
            "默认", "JSON", "JSONL", "Markdown", "CSV"
        ])
        output_form.addRow("输出格式:", self._outputFormat_combo)
        
        self._outputFile_input = QLineEdit()
        self._outputFile_input.setPlaceholderText("输出文件路径 (可选)")
        output_btn = QPushButton("选择")
        output_btn.setFixedWidth(60)
        output_btn.clicked.connect(self._select_output_file)
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(self._outputFile_input)
        output_file_layout.addWidget(output_btn)
        output_form.addRow("输出文件:", output_file_layout)
        
        self._reportDb_input = QLineEdit()
        self._reportDb_input.setPlaceholderText("报告数据库路径 (可选)")
        output_form.addRow("报告数据库:", self._reportDb_input)
        
        self._noColor_check = QCheckBox("禁用颜色输出")
        output_form.addRow(self._noColor_check)
        
        self._noTimestamp_check = QCheckBox("禁用时间戳")
        output_form.addRow(self._noTimestamp_check)
        
        output_layout.addWidget(output_group)
        output_layout.addStretch()
        tabs.addTab(output_tab, "输出选项")
        
        layout.addWidget(tabs)
        return widget
    
    def _select_templates(self):
        dir_path = QFileDialog.getExistingDirectory(self, "选择模板目录")
        if dir_path:
            self._templates_input.setText(dir_path)
    
    def _select_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "选择输出文件", "", "所有文件 (*)"
        )
        if file_path:
            self._outputFile_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["模板", "严重程度", "URL", "CVE", "描述"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool = self._tool_combo.currentText()
        
        if tool == "Nuclei":
            self._scan_with_nuclei()
        else:
            self._scan_builtin()
    
    def _scan_with_nuclei(self):
        if not self._is_tool_available("nuclei"):
            self._add_log(LogLevel.ERROR, "Nuclei 工具不可用")
            return
        
        targets = self._target_input.text().strip().split(',')
        targets = [t.strip() for t in targets if t.strip()]
        
        if not targets:
            self._add_log(LogLevel.ERROR, "请输入目标")
            return
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(targets))
            target_file = f.name
        
        cmd_parts = [
            f'"{self._get_tool_path("nuclei")}"',
            f"-l {target_file}",
            f"-c {self._concurrency_spin.value()}",
            f"-rate-limit {self._rate_limit_spin.value()}",
            f"-bs {self._bulkSize_spin.value()}",
        ]
        
        severities = []
        if self._critical_check.isChecked():
            severities.append("critical")
        if self._high_check.isChecked():
            severities.append("high")
        if self._medium_check.isChecked():
            severities.append("medium")
        if self._low_check.isChecked():
            severities.append("low")
        if self._info_check.isChecked():
            severities.append("info")
        
        if severities:
            cmd_parts.append(f"-severity {','.join(severities)}")
        
        tags = self._tags_input.text().strip()
        if tags:
            cmd_parts.append(f"-tags {tags}")
        
        exclude_tags = self._excludeTags_input.text().strip()
        if exclude_tags:
            cmd_parts.append(f"-exclude-tags {exclude_tags}")
        
        templates = self._templates_input.text().strip()
        if templates:
            cmd_parts.append(f"-t {templates}")
        
        template_id = self._templateId_input.text().strip()
        if template_id:
            cmd_parts.append(f"-id {template_id}")
        
        if self._headless_check.isChecked():
            cmd_parts.append("-headless")
            headless_opts = self._headlessOptions_input.text().strip()
            if headless_opts:
                cmd_parts.append(headless_opts)
        
        cmd_parts.append(f"-timeout {self._timeout_spin.value()}")
        cmd_parts.append(f"-retries {self._retries_spin.value()}")
        
        delay = self._delay_spin.value()
        if delay > 0:
            cmd_parts.append(f"-delay {delay}s")
        
        proxy = self._proxy_input.text().strip()
        if proxy:
            cmd_parts.append(f"-proxy {proxy}")
        
        if self._silent_check.isChecked():
            cmd_parts.append("-silent")
        
        if self._verbose_check.isChecked():
            cmd_parts.append("-v")
        
        if self._debug_check.isChecked():
            cmd_parts.append("-debug")
        
        if self._update_templates_check.isChecked():
            cmd_parts.append("-update-templates")
        
        if self._validate_check.isChecked():
            cmd_parts.append("-validate")
        
        output_format = self._outputFormat_combo.currentText()
        if output_format != "默认":
            format_map = {"JSON": "json", "JSONL": "jsonl", "Markdown": "md", "CSV": "csv"}
            cmd_parts.append(f"-format {format_map.get(output_format, 'json')}")
        
        output_file = self._outputFile_input.text().strip()
        if output_file:
            cmd_parts.append(f"-o {output_file}")
        
        report_db = self._reportDb_input.text().strip()
        if report_db:
            cmd_parts.append(f"-report-db {report_db}")
        
        if self._noColor_check.isChecked():
            cmd_parts.append("-no-color")
        
        if self._noTimestamp_check.isChecked():
            cmd_parts.append("-no-timestamp")
        
        cmd_parts.append("-json")
        
        cmd = " ".join(cmd_parts)
        self._add_log(LogLevel.INFO, f"执行: {cmd}")
        
        self._worker = NucleiWorker(
            self._get_tool_path("nuclei"),
            cmd,
            targets[0] if targets else None
        )
        self._worker.output_received.connect(self._on_nuclei_output)
        self._worker.finished_signal.connect(lambda s, r: self._on_nuclei_finished(s, r, target_file))
        self._worker.start()
    
    def _on_nuclei_output(self, line: str):
        if '[' in line and ']' in line:
            if 'critical' in line.lower() or 'high' in line.lower():
                self._add_log(LogLevel.ERROR, line)
            elif 'medium' in line.lower():
                self._add_log(LogLevel.WARNING, line)
            else:
                self._add_log(LogLevel.SUCCESS, line)
        elif 'error' in line.lower():
            self._add_log(LogLevel.ERROR, line)
    
    def _on_nuclei_finished(self, success: bool, results: list, target_file: str):
        for result in results:
            self._add_result(
                result.get('template', ''),
                result.get('severity', ''),
                result.get('url', ''),
                '',
                result.get('line', '')[:100]
            )
        
        self._add_log(LogLevel.SUCCESS, f"Nuclei 扫描完成，发现 {len(results)} 个结果")
        
        try:
            os.unlink(target_file)
        except:
            pass
    
    def _scan_builtin(self):
        import requests
        
        targets = self._target_input.text().strip().split(',')
        targets = [t.strip() for t in targets if t.strip()]
        
        if not targets:
            self._add_log(LogLevel.ERROR, "请输入目标")
            return
        
        self._add_log(LogLevel.INFO, f"开始批量扫描: {len(targets)} 个目标")
        
        for i, target in enumerate(targets):
            if not self._is_scanning:
                break
            
            if not target.startswith(('http://', 'https://')):
                target = 'http://' + target
            
            try:
                resp = requests.get(target, timeout=10, verify=False)
                
                headers = resp.headers
                
                if 'Server' in headers:
                    self._add_result("Server信息泄露", "低", target, "", headers['Server'])
                
                if 'X-Powered-By' in headers:
                    self._add_result("技术栈泄露", "低", target, "", headers['X-Powered-By'])
                
                if 'X-Frame-Options' not in headers:
                    self._add_result("缺少X-Frame-Options", "中", target, "", "点击劫持风险")
                
                if 'X-Content-Type-Options' not in headers:
                    self._add_result("缺少X-Content-Type-Options", "低", target, "", "MIME嗅探风险")
                
                if '/.git' in resp.text or '.git/config' in resp.text:
                    self._add_result("Git信息泄露", "高", target, "", ".git目录可能泄露")
                
                self._add_log(LogLevel.SUCCESS, f"扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"扫描失败: {target} - {str(e)}")
            
            progress = int(((i + 1) / len(targets)) * 100)
            self._update_progress(progress)
        
        self._add_log(LogLevel.INFO, "批量扫描完成")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("cve_search")
class CVESearchWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("cve_search", "CVE查询")
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["SearchSploit", "在线API", "本地数据库"])
        tool_layout.addRow("搜索工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        options_group = QGroupBox("搜索选项")
        form_layout = QFormLayout(options_group)
        
        self._search_type_combo = QComboBox()
        self._setup_combo(self._search_type_combo, [
            "关键词", "CVE编号", "产品名称", "厂商名称"
        ])
        form_layout.addRow("搜索类型:", self._search_type_combo)
        
        self._platform_combo = QComboBox()
        self._setup_combo(self._platform_combo, [
            "全部", "Windows", "Linux", "macOS", "Android", "iOS", "Hardware"
        ])
        form_layout.addRow("平台:", self._platform_combo)
        
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, [
            "全部", "remote", "local", "dos", "webapps"
        ])
        form_layout.addRow("类型:", self._type_combo)
        
        self._limit_spin = QSpinBox()
        self._limit_spin.setRange(1, 100)
        self._limit_spin.setValue(20)
        form_layout.addRow("结果数量:", self._limit_spin)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["标题", "类型", "平台", "CVE", "路径"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        keyword = self._target_input.text().strip()
        if not keyword:
            self._add_log(LogLevel.ERROR, "请输入搜索关键词")
            return
        
        tool = self._tool_combo.currentText()
        
        if tool == "SearchSploit":
            self._search_with_searchsploit(keyword)
        elif tool == "在线API":
            self._search_online(keyword)
        else:
            self._search_local(keyword)
    
    def _search_with_searchsploit(self, query: str):
        if not self._is_tool_available("searchsploit"):
            self._add_log(LogLevel.ERROR, "SearchSploit 工具不可用")
            return
        
        self._add_log(LogLevel.INFO, f"使用 SearchSploit 搜索: {query}")
        
        platform = self._platform_combo.currentText()
        exploit_type = self._type_combo.currentText()
        
        search_query = query
        if platform != "全部":
            search_query += f" platform:{platform}"
        if exploit_type != "全部":
            search_query += f" type:{exploit_type}"
        
        self._worker = SearchSploitWorker(
            self._get_tool_path("searchsploit"),
            search_query
        )
        self._worker.output_received.connect(self._on_searchsploit_output)
        self._worker.finished_signal.connect(self._on_searchsploit_finished)
        self._worker.start()
    
    def _on_searchsploit_output(self, output: str):
        if output.strip():
            self._add_log(LogLevel.DEBUG, output[:200])
    
    def _on_searchsploit_finished(self, success: bool, results: list):
        if success and results:
            for result in results[:self._limit_spin.value()]:
                self._add_result(
                    result.get('title', ''),
                    result.get('type', ''),
                    result.get('platform', ''),
                    result.get('cve', ''),
                    result.get('path', '')
                )
            self._add_log(LogLevel.SUCCESS, f"找到 {len(results)} 个结果")
        else:
            self._add_log(LogLevel.WARNING, "未找到相关漏洞")
    
    def _search_online(self, query: str):
        import requests
        
        self._add_log(LogLevel.INFO, f"在线搜索: {query}")
        
        try:
            if query.upper().startswith('CVE-'):
                url = f"https://cve.circl.lu/api/cve/{query}"
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    self._add_result(
                        data.get('id', ''),
                        'CVE',
                        '',
                        data.get('id', ''),
                        data.get('summary', '')[:100]
                    )
                    self._add_log(LogLevel.SUCCESS, f"找到: {data.get('id')}")
            else:
                url = f"https://cve.circl.lu/api/search/{query}"
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('results', [])[:self._limit_spin.value()]:
                        self._add_result(
                            item.get('id', ''),
                            'CVE',
                            '',
                            item.get('id', ''),
                            item.get('summary', '')[:100]
                        )
                    self._add_log(LogLevel.SUCCESS, f"找到 {len(data.get('results', []))} 个结果")
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"搜索失败: {str(e)}")
    
    def _search_local(self, query: str):
        self._add_log(LogLevel.INFO, "本地数据库搜索功能开发中...")
        self._add_log(LogLevel.INFO, "请使用 SearchSploit 或在线API")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("poc_manager")
class PoCManagerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("poc_manager", "PoC管理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("PoC管理选项")
        form_layout = QFormLayout(options_group)
        
        self._source_combo = QComboBox()
        self._setup_combo(self._source_combo, [
            "Nuclei模板", "自定义PoC", "ExploitDB"
        ])
        form_layout.addRow("PoC来源:", self._source_combo)
        
        self._category_combo = QComboBox()
        self._setup_combo(self._category_combo, [
            "全部", "CVE", "RCE", "SQLi", "XSS", "SSRF", "LFI"
        ])
        form_layout.addRow("分类:", self._category_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["名称", "类型", "严重程度", "路径"])
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
        source = self._source_combo.currentText()
        
        if source == "Nuclei模板":
            self._list_nuclei_templates()
        else:
            self._add_log(LogLevel.INFO, "功能开发中...")
    
    def _list_nuclei_templates(self):
        base_dir = Path(__file__).parent.parent
        templates_dir = base_dir / "tools" / "nuclei-templates"
        
        if not templates_dir.exists():
            self._add_log(LogLevel.ERROR, "Nuclei模板目录不存在")
            return
        
        self._add_log(LogLevel.INFO, f"扫描模板目录: {templates_dir}")
        
        count = 0
        for template_file in templates_dir.rglob("*.yaml"):
            if count >= 100:
                break
            
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                name = template_file.stem
                severity = "unknown"
                if 'severity: critical' in content.lower():
                    severity = "critical"
                elif 'severity: high' in content.lower():
                    severity = "high"
                elif 'severity: medium' in content.lower():
                    severity = "medium"
                elif 'severity: low' in content.lower():
                    severity = "low"
                
                template_type = template_file.parent.name
                
                self._add_result(name, template_type, severity, str(template_file))
                count += 1
                
            except:
                continue
        
        self._add_log(LogLevel.SUCCESS, f"找到 {count} 个模板")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("exploit_search")
class ExploitSearchWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("exploit_search", "Exploit搜索")
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("搜索选项")
        form_layout = QFormLayout(options_group)
        
        self._search_type_combo = QComboBox()
        self._setup_combo(self._search_type_combo, [
            "关键词", "CVE编号", "产品", "作者"
        ])
        form_layout.addRow("搜索类型:", self._search_type_combo)
        
        self._platform_combo = QComboBox()
        self._setup_combo(self._platform_combo, [
            "全部", "Windows", "Linux", "macOS", "PHP", "ASP", "JSP"
        ])
        form_layout.addRow("平台:", self._platform_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["标题", "类型", "平台", "日期", "路径"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        keyword = self._target_input.text().strip()
        if not keyword:
            self._add_log(LogLevel.ERROR, "请输入搜索关键词")
            return
        
        if self._is_tool_available("searchsploit"):
            self._search_with_searchsploit(keyword)
        else:
            self._add_log(LogLevel.ERROR, "SearchSploit 工具不可用")
    
    def _search_with_searchsploit(self, query: str):
        self._add_log(LogLevel.INFO, f"搜索漏洞利用: {query}")
        
        self._worker = SearchSploitWorker(
            self._get_tool_path("searchsploit"),
            query
        )
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.start()
    
    def _on_output(self, output: str):
        self._add_log(LogLevel.DEBUG, output[:200])
    
    def _on_finished(self, success: bool, results: list):
        if success and results:
            for result in results:
                self._add_result(
                    result.get('title', ''),
                    result.get('type', ''),
                    result.get('platform', ''),
                    '',
                    result.get('path', '')
                )
            self._add_log(LogLevel.SUCCESS, f"找到 {len(results)} 个漏洞利用")
        else:
            self._add_log(LogLevel.WARNING, "未找到相关漏洞利用")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()
