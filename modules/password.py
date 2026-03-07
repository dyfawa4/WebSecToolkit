from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox,
    QTabWidget, QPlainTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import subprocess
import threading
import re
import os
import tempfile
from pathlib import Path


HASHCAT_HASH_TYPES = {
    "MD5": "0",
    "SHA1": "100",
    "SHA256": "1400",
    "SHA512": "1700",
    "NTLM": "1000",
    "NTLMv1": "5500",
    "NTLMv2": "5600",
    "Kerberos 5 TGS": "13100",
    "Kerberos 5 AS-REP": "18200",
    "Kerberos 5 TGS-REP": "19600",
    "MSSQL": "132",
    "MySQL": "200",
    "PostgreSQL": "12",
    "Oracle": "3100",
    "WordPress": "400",
    "Drupal": "4711",
    "Joomla": "11",
    "bcrypt": "3200",
    "scrypt": "8900",
    "WPA/WPA2": "22000",
    "PDF 1.4": "10500",
    "Office 2013": "28200",
    "7-Zip": "11600",
    "RAR5": "13000",
    "ZIP": "17200",
    "Cisco-PIX": "1500",
    "Cisco-ASA": "2410",
    "Juniper": "22",
}


class ToolWorker(QThread):
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, cmd, tool_name="tool"):
        super().__init__()
        self._cmd = cmd
        self._tool_name = tool_name
        self._is_cancelled = False
        self._process = None
    
    def run(self):
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            
            self._process = subprocess.Popen(
                self._cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=True,
                creationflags=creation_flags
            )
            
            output_lines = []
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
                output_lines.append(line)
                self.output_received.emit(line)
            
            output = "\n".join(output_lines)
            success = self._process.returncode == 0
            self.finished_signal.emit(success, output)
            
        except Exception as e:
            self.finished_signal.emit(False, str(e))
    
    def cancel(self):
        self._is_cancelled = True
        if self._process:
            self._process.terminate()


@register_module("hash_crack")
class HashCrackerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("hash_crack", "Hash破解")
        self._worker = None
        self._hash_file = None
    
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
        self._setup_combo(self._tool_combo, ["Hashcat", "John the Ripper", "内置破解"])
        self._tool_combo.currentTextChanged.connect(self._on_tool_changed)
        tool_layout.addRow("破解工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        hash_group = QGroupBox("哈希设置")
        hash_layout = QFormLayout(hash_group)
        
        hash_input_layout = QHBoxLayout()
        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("输入哈希值或从文件加载")
        hash_file_btn = QPushButton("加载文件")
        hash_file_btn.setFixedWidth(80)
        hash_file_btn.clicked.connect(self._load_hash_file)
        hash_input_layout.addWidget(self._hash_input)
        hash_input_layout.addWidget(hash_file_btn)
        hash_layout.addRow("哈希值:", hash_input_layout)
        
        self._hash_type_combo = QComboBox()
        self._setup_combo(self._hash_type_combo, list(HASHCAT_HASH_TYPES.keys()))
        hash_layout.addRow("哈希类型:", self._hash_type_combo)
        
        self._auto_detect_check = QCheckBox("自动检测哈希类型")
        self._auto_detect_check.setChecked(True)
        hash_layout.addRow(self._auto_detect_check)
        
        basic_layout.addWidget(hash_group)
        
        crack_group = QGroupBox("破解选项")
        crack_layout = QFormLayout(crack_group)
        
        self._mode_combo = QComboBox()
        self._setup_combo(self._mode_combo, [
            "字典攻击 (0)", "组合攻击 (1)", "暴力破解 (3)", 
            "混合攻击 (6)", "规则攻击 (7)"
        ])
        crack_layout.addRow("攻击模式:", self._mode_combo)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件")
        dict_btn = QPushButton("选择")
        dict_btn.setFixedWidth(60)
        dict_btn.clicked.connect(self._select_dict)
        dict_layout.addWidget(self._dict_input)
        dict_layout.addWidget(dict_btn)
        crack_layout.addRow("字典文件:", dict_layout)
        
        rule_layout = QHBoxLayout()
        self._rule_input = QLineEdit()
        self._rule_input.setPlaceholderText("规则文件 (可选)")
        rule_btn = QPushButton("选择")
        rule_btn.setFixedWidth(60)
        rule_btn.clicked.connect(self._select_rule)
        rule_layout.addWidget(self._rule_input)
        rule_layout.addWidget(rule_btn)
        crack_layout.addRow("规则文件:", rule_layout)
        
        self._mask_input = QLineEdit()
        self._mask_input.setPlaceholderText("掩码，如: ?a?a?a?a?a?a (暴力破解用)")
        crack_layout.addRow("掩码:", self._mask_input)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 64)
        self._threads_spin.setValue(4)
        crack_layout.addRow("线程数:", self._threads_spin)
        
        self._gpu_check = QCheckBox("使用GPU加速")
        self._gpu_check.setChecked(True)
        crack_layout.addRow(self._gpu_check)
        
        self._show_cracked_check = QCheckBox("显示已破解")
        self._show_cracked_check.setChecked(True)
        crack_layout.addRow(self._show_cracked_check)
        
        basic_layout.addWidget(crack_group)
        tabs.addTab(basic_tab, "基本选项")
        
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        advanced_group = QGroupBox("Hashcat 高级选项")
        advanced_form = QFormLayout(advanced_group)
        
        self._session_input = QLineEdit()
        self._session_input.setPlaceholderText("会话名称 (用于恢复)")
        advanced_form.addRow("会话名称:", self._session_input)
        
        self._restore_check = QCheckBox("恢复上次会话")
        advanced_form.addRow(self._restore_check)
        
        self._increment_check = QCheckBox("增量破解")
        advanced_form.addRow(self._increment_check)
        
        self._incrementMin_spin = QSpinBox()
        self._incrementMin_spin.setRange(1, 32)
        self._incrementMin_spin.setValue(1)
        advanced_form.addRow("最小长度:", self._incrementMin_spin)
        
        self._incrementMax_spin = QSpinBox()
        self._incrementMax_spin.setRange(1, 32)
        self._incrementMax_spin.setValue(8)
        advanced_form.addRow("最大长度:", self._incrementMax_spin)
        
        self._workload_profile_combo = QComboBox()
        self._setup_combo(self._workload_profile_combo, [
            "低 (1)", "中 (2)", "高 (3)", "噩梦 (4)"
        ])
        self._workload_profile_combo.setCurrentIndex(1)
        advanced_form.addRow("工作负载:", self._workload_profile_combo)
        
        self._optimized_check = QCheckBox("优化内核")
        self._optimized_check.setChecked(True)
        advanced_form.addRow(self._optimized_check)
        
        self._force_check = QCheckBox("忽略警告")
        advanced_form.addRow(self._force_check)
        
        self._potfile_check = QCheckBox("使用potfile")
        self._potfile_check.setChecked(True)
        advanced_form.addRow(self._potfile_check)
        
        self._potfile_path_input = QLineEdit()
        self._potfile_path_input.setPlaceholderText("自定义potfile路径")
        advanced_form.addRow("Potfile路径:", self._potfile_path_input)
        
        self._outfile_input = QLineEdit()
        self._outfile_input.setPlaceholderText("输出文件路径")
        advanced_form.addRow("输出文件:", self._outfile_input)
        
        self._outfileFormat_input = QLineEdit()
        self._outfileFormat_input.setPlaceholderText("输出格式，如: 1,2,3")
        advanced_form.addRow("输出格式:", self._outfileFormat_input)
        
        self._remove_check = QCheckBox("破解后删除哈希")
        advanced_form.addRow(self._remove_check)
        
        advanced_layout.addWidget(advanced_group)
        advanced_layout.addStretch()
        tabs.addTab(advanced_tab, "高级选项")
        
        hardware_tab = QWidget()
        hardware_layout = QVBoxLayout(hardware_tab)
        
        hardware_group = QGroupBox("硬件选项")
        hardware_form = QFormLayout(hardware_group)
        
        self._opencl_device_types_combo = QComboBox()
        self._setup_combo(self._opencl_device_types_combo, [
            "自动", "CPU (1)", "GPU (2)", "FPGA (3)", "DSP (4)"
        ])
        hardware_form.addRow("设备类型:", self._opencl_device_types_combo)
        
        self._opencl_platforms_input = QLineEdit()
        self._opencl_platforms_input.setPlaceholderText("平台ID (逗号分隔)")
        hardware_form.addRow("OpenCL平台:", self._opencl_platforms_input)
        
        self._opencl_devices_input = QLineEdit()
        self._opencl_devices_input.setPlaceholderText("设备ID (逗号分隔)")
        hardware_form.addRow("OpenCL设备:", self._opencl_devices_input)
        
        self._skip_spin = QSpinBox()
        self._skip_spin.setRange(0, 1000000000)
        self._skip_spin.setValue(0)
        hardware_form.addRow("跳过数量:", self._skip_spin)
        
        self._limit_spin = QSpinBox()
        self._limit_spin.setRange(0, 1000000000)
        self._limit_spin.setValue(0)
        hardware_form.addRow("限制数量:", self._limit_spin)
        
        hardware_layout.addWidget(hardware_group)
        hardware_layout.addStretch()
        tabs.addTab(hardware_tab, "硬件选项")
        
        layout.addWidget(tabs)
        
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        if tool_name == "Hashcat":
            available = self._is_tool_available("hashcat")
            self._add_log(LogLevel.INFO, f"Hashcat: {'可用' if available else '不可用'}")
        elif tool_name == "John the Ripper":
            available = self._is_tool_available("john")
            self._add_log(LogLevel.INFO, f"John the Ripper: {'可用' if available else '不可用'}")
    
    def _load_hash_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择哈希文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                self._hash_input.setText(content[:100] + "..." if len(content) > 100 else content)
                self._hash_file = file_path
                self._add_log(LogLevel.SUCCESS, f"已加载哈希文件: {file_path}")
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"加载失败: {str(e)}")
    
    def _select_dict(self):
        dict_path = self._select_dict("password")
        if dict_path:
            self._dict_input.setText(dict_path)
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
            )
            if file_path:
                self._dict_input.setText(file_path)
    
    def _select_rule(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择规则文件", "", "规则文件 (*.rule);;文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self._rule_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["哈希值", "明文", "类型", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Hashcat":
            self._crack_with_hashcat()
        elif tool_name == "John the Ripper":
            self._crack_with_john()
        else:
            self._crack_builtin()
    
    def _crack_with_hashcat(self):
        if not self._is_tool_available("hashcat"):
            self._add_log(LogLevel.ERROR, "Hashcat 工具不可用")
            return
        
        hash_value = self._hash_input.text().strip()
        if not hash_value and not self._hash_file:
            self._add_log(LogLevel.ERROR, "请输入哈希值或加载哈希文件")
            return
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            self._add_log(LogLevel.ERROR, "请选择字典文件")
            return
        
        hash_type = HASHCAT_HASH_TYPES.get(self._hash_type_combo.currentText(), "0")
        
        mode_map = {
            "字典攻击 (0)": "0",
            "组合攻击 (1)": "1",
            "暴力破解 (3)": "3",
            "混合攻击 (6)": "6",
            "规则攻击 (7)": "7"
        }
        attack_mode = mode_map.get(self._mode_combo.currentText(), "0")
        
        if self._hash_file:
            hash_input = self._hash_file
        else:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(hash_value)
                hash_input = f.name
        
        cmd_parts = [
            f'"{self._get_tool_path("hashcat")}"',
            f"-m {hash_type}",
            f"-a {attack_mode}",
        ]
        
        if self._restore_check.isChecked():
            session = self._session_input.text().strip()
            if session:
                cmd_parts.insert(0, f'"{self._get_tool_path("hashcat")}" --restore --session {session}')
                cmd = " ".join(cmd_parts)
                self._add_log(LogLevel.INFO, f"恢复会话: {session}")
                self._worker = ToolWorker(cmd, "hashcat")
                self._worker.output_received.connect(self._on_hashcat_output)
                self._worker.finished_signal.connect(self._on_hashcat_finished)
                self._worker.start()
                return
        
        session = self._session_input.text().strip()
        if session:
            cmd_parts.append(f"--session {session}")
        
        if not self._gpu_check.isChecked():
            cmd_parts.append("-D 1")
        else:
            device_type = self._opencl_device_types_combo.currentText()
            if "CPU" in device_type:
                cmd_parts.append("-D 1")
            elif "GPU" in device_type:
                cmd_parts.append("-D 2")
            elif "FPGA" in device_type:
                cmd_parts.append("-D 3")
        
        workload_map = {"低 (1)": "1", "中 (2)": "2", "高 (3)": "3", "噩梦 (4)": "4"}
        workload = workload_map.get(self._workload_profile_combo.currentText(), "2")
        cmd_parts.append(f"-w {workload}")
        
        if self._optimized_check.isChecked():
            cmd_parts.append("-O")
        
        if self._force_check.isChecked():
            cmd_parts.append("--force")
        
        if not self._potfile_check.isChecked():
            cmd_parts.append("--potfile-disable")
        
        potfile_path = self._potfile_path_input.text().strip()
        if potfile_path:
            cmd_parts.append(f"--potfile-path {potfile_path}")
        
        outfile = self._outfile_input.text().strip()
        if outfile:
            cmd_parts.append(f"-o {outfile}")
        
        outfile_format = self._outfileFormat_input.text().strip()
        if outfile_format:
            cmd_parts.append(f"--outfile-format {outfile_format}")
        
        if self._remove_check.isChecked():
            cmd_parts.append("--remove")
        
        if self._increment_check.isChecked():
            cmd_parts.append("--increment")
            cmd_parts.append(f"--increment-min {self._incrementMin_spin.value()}")
            cmd_parts.append(f"--increment-max {self._incrementMax_spin.value()}")
        
        opencl_platforms = self._opencl_platforms_input.text().strip()
        if opencl_platforms:
            cmd_parts.append(f"--opencl-platforms {opencl_platforms}")
        
        opencl_devices = self._opencl_devices_input.text().strip()
        if opencl_devices:
            cmd_parts.append(f"--opencl-devices {opencl_devices}")
        
        skip = self._skip_spin.value()
        if skip > 0:
            cmd_parts.append(f"-s {skip}")
        
        limit = self._limit_spin.value()
        if limit > 0:
            cmd_parts.append(f"-l {limit}")
        
        if attack_mode == "0":
            cmd_parts.extend([f'"{hash_input}"', f'"{dict_path}"'])
        elif attack_mode == "3":
            mask = self._mask_input.text().strip() or "?a?a?a?a?a?a"
            cmd_parts.extend([f'"{hash_input}"', mask])
        else:
            cmd_parts.extend([f'"{hash_input}"', f'"{dict_path}"'])
        
        if self._rule_input.text().strip():
            cmd_parts.append(f'-r "{self._rule_input.text().strip()}"')
        
        cmd = " ".join(cmd_parts)
        self._add_log(LogLevel.INFO, f"执行: {cmd}")
        
        self._worker = ToolWorker(cmd, "hashcat")
        self._worker.output_received.connect(self._on_hashcat_output)
        self._worker.finished_signal.connect(self._on_hashcat_finished)
        self._worker.start()
    
    def _on_hashcat_output(self, line: str):
        if "Status........: Cracked" in line or "Cracked" in line:
            self._add_log(LogLevel.SUCCESS, "破解成功!")
        elif "Status........: Running" in line:
            self._add_log(LogLevel.INFO, "正在破解...")
        elif "Speed" in line:
            self._add_log(LogLevel.DEBUG, line)
        elif ":" in line and len(line.split(":")) >= 2:
            parts = line.split(":")
            if len(parts) >= 2:
                hash_part = parts[0].strip()
                plain_part = parts[-1].strip()
                if len(hash_part) > 10 and len(plain_part) > 0:
                    self._add_result(hash_part[:30] + "...", plain_part, 
                                    self._hash_type_combo.currentText(), "已破解")
    
    def _on_hashcat_finished(self, success: bool, output: str):
        if success:
            self._add_log(LogLevel.SUCCESS, "Hashcat 破解完成")
            if self._show_cracked_check.isChecked():
                self._show_hashcat_results()
        else:
            self._add_log(LogLevel.WARNING, "Hashcat 破解结束")
        
        if self._hash_file is None and not self._hash_input.text().strip().startswith("temp"):
            pass
    
    def _show_hashcat_results(self):
        if not self._is_tool_available("hashcat"):
            return
        
        hash_input = self._hash_file if self._hash_file else self._hash_input.text().strip()
        hash_type = HASHCAT_HASH_TYPES.get(self._hash_type_combo.currentText(), "0")
        
        cmd = f'"{self._get_tool_path("hashcat")}" -m {hash_type} --show "{hash_input}"'
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, _ = process.communicate(timeout=30)
            
            for line in stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    if len(parts) == 2:
                        self._add_result(parts[0][:30] + "...", parts[1], 
                                        self._hash_type_combo.currentText(), "已破解")
        except:
            pass
    
    def _crack_with_john(self):
        if not self._is_tool_available("john"):
            self._add_log(LogLevel.ERROR, "John the Ripper 工具不可用")
            return
        
        hash_value = self._hash_input.text().strip()
        if not hash_value:
            self._add_log(LogLevel.ERROR, "请输入哈希值")
            return
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            self._add_log(LogLevel.ERROR, "请选择字典文件")
            return
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(hash_value)
            hash_file = f.name
        
        hash_type_map = {
            "MD5": "raw-md5",
            "SHA1": "raw-sha1",
            "SHA256": "raw-sha256",
            "SHA512": "raw-sha512",
            "NTLM": "nt",
            "bcrypt": "bcrypt",
        }
        john_format = hash_type_map.get(self._hash_type_combo.currentText(), "raw-md5")
        
        cmd = f'"{self._get_tool_path("john")}" --format={john_format} --wordlist="{dict_path}" "{hash_file}"'
        
        self._add_log(LogLevel.INFO, f"执行: {cmd}")
        
        self._worker = ToolWorker(cmd, "john")
        self._worker.output_received.connect(self._on_john_output)
        self._worker.finished_signal.connect(lambda s, o: self._on_john_finished(s, o, hash_file))
        self._worker.start()
    
    def _on_john_output(self, line: str):
        if "loaded" in line.lower():
            self._add_log(LogLevel.INFO, line)
        elif "remaining" in line.lower():
            self._add_log(LogLevel.DEBUG, line)
        elif "guesses" in line.lower():
            self._add_log(LogLevel.SUCCESS, line)
    
    def _on_john_finished(self, success: bool, output: str, hash_file: str):
        self._add_log(LogLevel.SUCCESS, "John the Ripper 破解完成")
        
        try:
            show_cmd = f'"{self._get_tool_path("john")}" --show "{hash_file}"'
            process = subprocess.Popen(
                show_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            stdout, _ = process.communicate(timeout=10)
            
            for line in stdout.strip().split('\n'):
                if ':' in line and not line.startswith('0 password'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        self._add_result(parts[0][:30] + "...", parts[1], 
                                        self._hash_type_combo.currentText(), "已破解")
        except:
            pass
        
        try:
            os.unlink(hash_file)
        except:
            pass
    
    def _crack_builtin(self):
        import hashlib
        
        hash_value = self._hash_input.text().strip()
        if not hash_value:
            self._add_log(LogLevel.ERROR, "请输入哈希值")
            return
        
        self._add_log(LogLevel.INFO, "使用内置字典破解")
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            common_passwords = ["123456", "password", "admin", "12345678", "qwerty",
                              "letmein", "welcome", "monkey", "dragon", "master"]
        else:
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    common_passwords = [line.strip() for line in f if line.strip()]
            except:
                common_passwords = ["123456", "password", "admin"]
        
        hash_type = self._hash_type_combo.currentText().lower()
        
        total = len(common_passwords)
        for i, password in enumerate(common_passwords):
            if not self._is_scanning:
                break
            
            try:
                if hash_type == "md5":
                    computed = hashlib.md5(password.encode()).hexdigest()
                elif hash_type == "sha1":
                    computed = hashlib.sha1(password.encode()).hexdigest()
                elif hash_type == "sha256":
                    computed = hashlib.sha256(password.encode()).hexdigest()
                elif hash_type == "sha512":
                    computed = hashlib.sha512(password.encode()).hexdigest()
                elif hash_type == "ntlm":
                    computed = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                else:
                    computed = hashlib.md5(password.encode()).hexdigest()
                
                if computed.lower() == hash_value.lower():
                    self._add_result(hash_value[:30] + "...", password, 
                                    self._hash_type_combo.currentText(), "已破解")
                    self._add_log(LogLevel.SUCCESS, f"破解成功: {password}")
                    return
            except:
                pass
            
            if (i + 1) % 100 == 0:
                progress = int(((i + 1) / total) * 100)
                self._update_progress(progress)
        
        self._add_log(LogLevel.INFO, "内置字典破解完成，未找到匹配")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("online_brute")
class OnlineBruteWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("online_brute", "在线爆破")
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
        self._setup_combo(self._tool_combo, ["Hydra", "内置爆破"])
        tool_layout.addRow("爆破工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        target_group = QGroupBox("目标设置")
        target_layout = QFormLayout(target_group)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址，如: 192.168.1.1 或 example.com")
        target_layout.addRow("目标地址:", self._target_input)
        
        self._service_combo = QComboBox()
        self._setup_combo(self._service_combo, [
            "SSH (22)", "FTP (21)", "Telnet (23)", "SMTP (25)",
            "HTTP (80)", "HTTPS (443)", "RDP (3389)", "SMB (445)",
            "MySQL (3306)", "MSSQL (1433)", "PostgreSQL (5432)",
            "VNC (5900)", "Redis (6379)", "MongoDB (27017)",
            "POP3 (110)", "IMAP (143)", "LDAP (389)", "SNMP (161)",
            "SIP (5060)", "Rlogin (513)", "CVS (2401)", "SVN (3690)"
        ])
        target_layout.addRow("服务类型:", self._service_combo)
        
        self._port_input = QLineEdit()
        self._port_input.setPlaceholderText("自定义端口 (可选)")
        target_layout.addRow("自定义端口:", self._port_input)
        
        basic_layout.addWidget(target_group)
        
        cred_group = QGroupBox("凭据设置")
        cred_layout = QFormLayout(cred_group)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        cred_layout.addRow("用户名:", self._username_input)
        
        user_dict_layout = QHBoxLayout()
        self._user_dict_input = QLineEdit()
        self._user_dict_input.setPlaceholderText("用户名字典")
        user_dict_btn = QPushButton("选择")
        user_dict_btn.setFixedWidth(60)
        user_dict_btn.clicked.connect(lambda: self._select_dict_file("user"))
        user_dict_layout.addWidget(self._user_dict_input)
        user_dict_layout.addWidget(user_dict_btn)
        cred_layout.addRow("用户名字典:", user_dict_layout)
        
        pass_dict_layout = QHBoxLayout()
        self._pass_dict_input = QLineEdit()
        self._pass_dict_input.setPlaceholderText("密码字典")
        pass_dict_btn = QPushButton("选择")
        pass_dict_btn.setFixedWidth(60)
        pass_dict_btn.clicked.connect(lambda: self._select_dict_file("pass"))
        pass_dict_layout.addWidget(self._pass_dict_input)
        pass_dict_layout.addWidget(pass_dict_btn)
        cred_layout.addRow("密码字典:", pass_dict_layout)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("单个密码 (可选)")
        cred_layout.addRow("单个密码:", self._password_input)
        
        basic_layout.addWidget(cred_group)
        tabs.addTab(basic_tab, "基本选项")
        
        options_tab = QWidget()
        options_layout = QVBoxLayout(options_tab)
        
        options_group = QGroupBox("爆破选项")
        options_form = QFormLayout(options_group)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 64)
        self._threads_spin.setValue(4)
        options_form.addRow("线程数:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" 秒")
        options_form.addRow("超时时间:", self._timeout_spin)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 10)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" 秒")
        options_form.addRow("请求延迟:", self._delay_spin)
        
        self._max_attempts_spin = QSpinBox()
        self._max_attempts_spin.setRange(0, 1000)
        self._max_attempts_spin.setValue(0)
        options_form.addRow("最大尝试:", self._max_attempts_spin)
        
        self._connect_timeout_spin = QSpinBox()
        self._connect_timeout_spin.setRange(1, 60)
        self._connect_timeout_spin.setValue(30)
        self._connect_timeout_spin.setSuffix(" 秒")
        options_form.addRow("连接超时:", self._connect_timeout_spin)
        
        self._verbose_check = QCheckBox("详细输出")
        options_form.addRow(self._verbose_check)
        
        self._debug_check = QCheckBox("调试模式")
        options_form.addRow(self._debug_check)
        
        self._stop_on_success = QCheckBox("成功后停止")
        self._stop_on_success.setChecked(True)
        options_form.addRow(self._stop_on_success)
        
        self._exit_on_first_check = QCheckBox("首次错误退出")
        options_form.addRow(self._exit_on_first_check)
        
        options_layout.addWidget(options_group)
        options_layout.addStretch()
        tabs.addTab(options_tab, "爆破选项")
        
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        advanced_group = QGroupBox("Hydra 高级选项")
        advanced_form = QFormLayout(advanced_group)
        
        self._proxy_input = QLineEdit()
        self._proxy_input.setPlaceholderText("代理地址，如: socks5://127.0.0.1:1080")
        advanced_form.addRow("代理:", self._proxy_input)
        
        self._proxyAuth_input = QLineEdit()
        self._proxyAuth_input.setPlaceholderText("代理认证: user:pass")
        advanced_form.addRow("代理认证:", self._proxyAuth_input)
        
        self._outputFile_input = QLineEdit()
        self._outputFile_input.setPlaceholderText("输出文件路径")
        advanced_form.addRow("输出文件:", self._outputFile_input)
        
        self._colon_check = QCheckBox("使用冒号分隔输出")
        advanced_form.addRow(self._colon_check)
        
        self._useSSL_check = QCheckBox("使用SSL/TLS")
        advanced_form.addRow(self._useSSL_check)
        
        self._noSSL_check = QCheckBox("禁用SSL")
        advanced_form.addRow(self._noSSL_check)
        
        self._fudge_spin = QSpinBox()
        self._fudge_spin.setRange(0, 10)
        self._fudge_spin.setValue(0)
        advanced_form.addRow("时间偏差:", self._fudge_spin)
        
        self._retry_spin = QSpinBox()
        self._retry_spin.setRange(0, 10)
        self._retry_spin.setValue(2)
        advanced_form.addRow("重试次数:", self._retry_spin)
        
        self._tasks_spin = QSpinBox()
        self._tasks_spin.setRange(1, 64)
        self._tasks_spin.setValue(1)
        advanced_form.addRow("并行任务:", self._tasks_spin)
        
        advanced_layout.addWidget(advanced_group)
        
        service_group = QGroupBox("服务特定选项")
        service_form = QFormLayout(service_group)
        
        self._module_input = QLineEdit()
        self._module_input.setPlaceholderText("模块特定选项，如: http-post-form")
        service_form.addRow("模块选项:", self._module_input)
        
        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("路径，如: /login.php:user=^USER^&pass=^PASS^:Invalid")
        service_form.addRow("请求路径:", self._path_input)
        
        self._header_input = QLineEdit()
        self._header_input.setPlaceholderText("自定义头，如: Cookie: session=abc")
        service_form.addRow("自定义头:", self._header_input)
        
        advanced_layout.addWidget(service_group)
        advanced_layout.addStretch()
        tabs.addTab(advanced_tab, "高级选项")
        
        layout.addWidget(tabs)
        return widget
    
    def _select_dict_file(self, dict_type: str):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            if dict_type == "user":
                self._user_dict_input.setText(file_path)
            else:
                self._pass_dict_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["服务", "用户名", "密码", "状态", "时间"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Hydra":
            self._brute_with_hydra()
        else:
            self._brute_builtin()
    
    def _brute_with_hydra(self):
        if not self._is_tool_available("hydra"):
            self._add_log(LogLevel.ERROR, "Hydra 工具不可用")
            return
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标地址")
            return
        
        service_text = self._service_combo.currentText()
        service = service_text.split(" ")[0].lower()
        
        custom_port = self._port_input.text().strip()
        
        username = self._username_input.text().strip()
        user_dict = self._user_dict_input.text().strip()
        pass_dict = self._pass_dict_input.text().strip()
        single_password = self._password_input.text().strip()
        
        if not user_dict and not username:
            self._add_log(LogLevel.ERROR, "请输入用户名或选择用户名字典")
            return
        
        if not pass_dict and not single_password:
            self._add_log(LogLevel.ERROR, "请选择密码字典或输入单个密码")
            return
        
        cmd_parts = [
            f'"{self._get_tool_path("hydra")}"',
            f"-t {self._threads_spin.value()}",
            f"-W {self._delay_spin.value()}",
            f"-w {self._timeout_spin.value()}",
            f"-T {self._connect_timeout_spin.value()}",
        ]
        
        if self._verbose_check.isChecked():
            cmd_parts.append("-V")
        
        if self._debug_check.isChecked():
            cmd_parts.append("-d")
        
        if self._exit_on_first_check.isChecked():
            cmd_parts.append("-f")
        
        if self._stop_on_success.isChecked():
            cmd_parts.append("-F")
        
        max_attempts = self._max_attempts_spin.value()
        if max_attempts > 0:
            cmd_parts.append(f"-e {max_attempts}")
        
        proxy = self._proxy_input.text().strip()
        if proxy:
            cmd_parts.append(f"-s {proxy}")
        
        proxy_auth = self._proxyAuth_input.text().strip()
        if proxy_auth:
            cmd_parts.append(f"-S {proxy_auth}")
        
        output_file = self._outputFile_input.text().strip()
        if output_file:
            cmd_parts.append(f"-o {output_file}")
        
        if self._colon_check.isChecked():
            cmd_parts.append("-O")
        
        if self._useSSL_check.isChecked():
            cmd_parts.append("-S")
        
        if self._noSSL_check.isChecked():
            cmd_parts.append("-n")
        
        fudge = self._fudge_spin.value()
        if fudge > 0:
            cmd_parts.append(f"-f {fudge}")
        
        retry = self._retry_spin.value()
        if retry != 2:
            cmd_parts.append(f"-R {retry}")
        
        tasks = self._tasks_spin.value()
        if tasks > 1:
            cmd_parts.append(f"-T {tasks}")
        
        if username:
            cmd_parts.append(f"-l {username}")
        else:
            cmd_parts.append(f'-L "{user_dict}"')
        
        if single_password:
            cmd_parts.append(f"-p {single_password}")
        else:
            cmd_parts.append(f'-P "{pass_dict}"')
        
        if custom_port:
            cmd_parts.append(f"-s {custom_port}")
        
        module = self._module_input.text().strip()
        path = self._path_input.text().strip()
        header = self._header_input.text().strip()
        
        if module:
            if path:
                cmd_parts.append(f"-m {path}")
            if header:
                cmd_parts.append(f"-H {header}")
        
        cmd_parts.append(f"{target} {service}")
        
        cmd = " ".join(cmd_parts)
        self._add_log(LogLevel.INFO, f"执行: {cmd}")
        
        self._worker = ToolWorker(cmd, "hydra")
        self._worker.output_received.connect(self._on_hydra_output)
        self._worker.finished_signal.connect(self._on_hydra_finished)
        self._worker.start()
    
    def _on_hydra_output(self, line: str):
        if "login:" in line.lower() and "password:" in line.lower():
            import re
            login_match = re.search(r'login:\s*(\S+)', line)
            pass_match = re.search(r'password:\s*(\S+)', line)
            
            if login_match and pass_match:
                login = login_match.group(1)
                password = pass_match.group(1)
                service = self._service_combo.currentText().split(" ")[0]
                self._add_result(service, login, password, "成功", "")
                self._add_log(LogLevel.SUCCESS, f"发现凭据: {login}:{password}")
                
                if self._stop_on_success.isChecked():
                    if self._worker:
                        self._worker.cancel()
        elif "host:" in line.lower():
            self._add_log(LogLevel.DEBUG, line)
        elif "attempt" in line.lower():
            if self._verbose_check.isChecked():
                self._add_log(LogLevel.DEBUG, line)
    
    def _on_hydra_finished(self, success: bool, output: str):
        self._add_log(LogLevel.SUCCESS, "Hydra 爆破完成")
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()
    
    def _brute_builtin(self):
        import requests
        from datetime import datetime
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标地址")
            return
        
        username = self._username_input.text().strip()
        pass_dict = self._pass_dict_input.text().strip()
        
        if not pass_dict:
            passwords = ["123456", "password", "admin", "12345678", "qwerty"]
        else:
            try:
                with open(pass_dict, 'r', encoding='utf-8') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except:
                passwords = ["123456", "password", "admin"]
        
        self._add_log(LogLevel.INFO, f"开始在线爆破: {target}")
        
        for i, password in enumerate(passwords):
            if not self._is_scanning:
                break
            
            try:
                resp = requests.post(
                    target,
                    data={'username': username, 'password': password},
                    timeout=self._timeout_spin.value(),
                    allow_redirects=False,
                    verify=False
                )
                
                status = "失败"
                if resp.status_code == 200 and "登录失败" not in resp.text:
                    status = "可能成功"
                    self._add_result("HTTP", username, password, "可能成功", 
                                   datetime.now().strftime("%H:%M:%S"))
                    self._add_log(LogLevel.SUCCESS, f"可能正确的密码: {password}")
                    
                    if self._stop_on_success.isChecked():
                        break
                elif resp.status_code == 302:
                    status = "可能成功"
                    self._add_result("HTTP", username, password, "重定向", 
                                   datetime.now().strftime("%H:%M:%S"))
                    self._add_log(LogLevel.SUCCESS, f"可能正确的密码: {password}")
                    
                    if self._stop_on_success.isChecked():
                        break
                
                delay = self._delay_spin.value()
                if delay > 0:
                    import time
                    time.sleep(delay)
                    
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"请求失败: {str(e)}")
            
            progress = int(((i + 1) / len(passwords)) * 100)
            self._update_progress(progress)
        
        self._add_log(LogLevel.INFO, "在线爆破完成")


@register_module("hash_identify")
class HashIdentifyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("hash_identify", "Hash识别")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        hash_group = QGroupBox("哈希输入")
        hash_layout = QVBoxLayout(hash_group)
        
        self._hash_input = QTextEdit()
        self._hash_input.setPlaceholderText("输入哈希值进行识别...")
        self._hash_input.setMaximumHeight(100)
        hash_layout.addWidget(self._hash_input)
        
        layout.addWidget(hash_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["哈希类型", "可能性", "Hashcat模式"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        hash_value = self._hash_input.toPlainText().strip()
        if not hash_value:
            self._add_log(LogLevel.ERROR, "请输入哈希值")
            return
        
        hash_value = hash_value.split('\n')[0].strip()
        
        self._add_log(LogLevel.INFO, f"识别哈希: {hash_value[:30]}...")
        
        hash_patterns = [
            (r'^[a-f0-9]{32}$', "MD5", "0", "高"),
            (r'^[a-f0-9]{40}$', "SHA1", "100", "高"),
            (r'^[a-f0-9]{64}$', "SHA256", "1400", "高"),
            (r'^[a-f0-9]{128}$', "SHA512", "1700", "高"),
            (r'^[a-f0-9]{32}:[a-f0-9]{32}$', "NTLM", "1000", "高"),
            (r'^\$NT\$', "NTLM", "1000", "高"),
            (r'^\$6\$', "SHA-512 Crypt", "1800", "高"),
            (r'^\$5\$', "SHA-256 Crypt", "7400", "高"),
            (r'^\$2[aby]?\$', "bcrypt", "3200", "高"),
            (r'^\$apr1\$', "Apache MD5", "1600", "高"),
            (r'^\$1\$', "MD5 Crypt", "500", "高"),
            (r'^[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32}$', "NTLMv1", "5500", "中"),
            (r'^[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32}$', "NTLMv2", "5600", "中"),
        ]
        
        found = False
        for pattern, hash_type, mode, confidence in hash_patterns:
            if re.match(pattern, hash_value, re.IGNORECASE):
                self._add_result(hash_type, confidence, mode)
                self._add_log(LogLevel.SUCCESS, f"识别为: {hash_type}")
                found = True
        
        if not found:
            self._add_result("未知", "低", "-")
            self._add_log(LogLevel.WARNING, "未能识别哈希类型")
        
        self._add_log(LogLevel.INFO, "哈希识别完成")


@register_module("password_generator")
class PasswordGeneratorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("password_generator", "密码生成器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("生成选项")
        form_layout = QFormLayout(options_group)
        
        self._length_spin = QSpinBox()
        self._length_spin.setRange(4, 64)
        self._length_spin.setValue(16)
        form_layout.addRow("密码长度:", self._length_spin)
        
        self._count_spin = QSpinBox()
        self._count_spin.setRange(1, 1000)
        self._count_spin.setValue(10)
        form_layout.addRow("生成数量:", self._count_spin)
        
        self._uppercase_check = QCheckBox("大写字母 (A-Z)")
        self._uppercase_check.setChecked(True)
        form_layout.addRow(self._uppercase_check)
        
        self._lowercase_check = QCheckBox("小写字母 (a-z)")
        self._lowercase_check.setChecked(True)
        form_layout.addRow(self._lowercase_check)
        
        self._digits_check = QCheckBox("数字 (0-9)")
        self._digits_check.setChecked(True)
        form_layout.addRow(self._digits_check)
        
        self._special_check = QCheckBox("特殊字符 (!@#$%)")
        self._special_check.setChecked(True)
        form_layout.addRow(self._special_check)
        
        self._exclude_input = QLineEdit()
        self._exclude_input.setPlaceholderText("排除的字符")
        form_layout.addRow("排除字符:", self._exclude_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["密码", "强度", "熵值"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import random
        import string
        import math
        
        length = self._length_spin.value()
        count = self._count_spin.value()
        
        chars = ""
        if self._uppercase_check.isChecked():
            chars += string.ascii_uppercase
        if self._lowercase_check.isChecked():
            chars += string.ascii_lowercase
        if self._digits_check.isChecked():
            chars += string.digits
        if self._special_check.isChecked():
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        exclude = self._exclude_input.text().strip()
        if exclude:
            for c in exclude:
                chars = chars.replace(c, "")
        
        if not chars:
            self._add_log(LogLevel.ERROR, "请至少选择一种字符类型")
            return
        
        self._add_log(LogLevel.INFO, f"生成 {count} 个密码，长度 {length}")
        
        charset_size = len(chars)
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0
        
        for i in range(count):
            if not self._is_scanning:
                break
            
            password = ''.join(random.choice(chars) for _ in range(length))
            
            strength = "弱"
            if length >= 12 and charset_size >= 70:
                strength = "强"
            elif length >= 8 and charset_size >= 50:
                strength = "中"
            
            self._add_result(password, strength, f"{entropy:.2f}")
            
            if (i + 1) % 100 == 0:
                progress = int(((i + 1) / count) * 100)
                self._update_progress(progress)
        
        self._add_log(LogLevel.SUCCESS, f"密码生成完成: {count} 个")
