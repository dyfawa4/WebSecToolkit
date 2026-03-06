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


@register_module("hash_crack")
class HashCrackerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Hash破解")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        hash_group = QGroupBox("哈希设置")
        hash_layout = QFormLayout(hash_group)
        
        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("输入哈希值")
        hash_layout.addRow("哈希值:", self._hash_input)
        
        self._hash_type_combo = QComboBox()
        self._setup_combo(self._hash_type_combo, [
            "MD5", "SHA1", "SHA256", "SHA512", "NTLM"
        ])
        hash_layout.addRow("哈希类型:", self._hash_type_combo)
        
        layout.addWidget(hash_group)
        
        crack_group = QGroupBox("破解选项")
        crack_layout = QFormLayout(crack_group)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件")
        dict_btn = QPushButton("选择")
        dict_btn.setFixedWidth(60)
        dict_btn.clicked.connect(self._select_dict)
        dict_layout.addWidget(self._dict_input)
        dict_layout.addWidget(dict_btn)
        crack_layout.addRow("字典文件:", dict_layout)
        
        self._mode_combo = QComboBox()
        self._setup_combo(self._mode_combo, ["字典攻击", "暴力破解", "混合模式"])
        crack_layout.addRow("破解模式:", self._mode_combo)
        
        self._charset_input = QLineEdit()
        self._charset_input.setPlaceholderText("字符集，如: 0123456789")
        crack_layout.addRow("字符集:", self._charset_input)
        
        self._min_len_spin = QSpinBox()
        self._min_len_spin.setRange(1, 32)
        self._min_len_spin.setValue(1)
        crack_layout.addRow("最小长度:", self._min_len_spin)
        
        self._max_len_spin = QSpinBox()
        self._max_len_spin.setRange(1, 32)
        self._max_len_spin.setValue(8)
        crack_layout.addRow("最大长度:", self._max_len_spin)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 64)
        self._threads_spin.setValue(4)
        crack_layout.addRow("线程数:", self._threads_spin)
        
        layout.addWidget(crack_group)
        return widget
    
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
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["哈希值", "明文", "状态"])
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
        hash_value = self._hash_input.text().strip()
        if not hash_value:
            self._add_log(LogLevel.ERROR, "请输入哈希值")
            return
        
        self._add_log(LogLevel.INFO, f"开始破解哈希: {hash_value}")
        
        if self._is_tool_available("john"):
            self._crack_with_john(hash_value)
        elif self._is_tool_available("hashcat"):
            self._crack_with_hashcat(hash_value)
        else:
            self._crack_builtin(hash_value)
    
    def _crack_with_john(self, hash_value: str):
        self._add_log(LogLevel.INFO, "使用 John the Ripper 破解")
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(hash_value)
            hash_file = f.name
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            self._add_log(LogLevel.ERROR, "请选择字典文件")
            return
        
        try:
            args = ["--wordlist=" + dict_path, hash_file]
            process = self._execute_tool("john", args)
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._add_log(LogLevel.DEBUG, line.strip())
            
            self._add_log(LogLevel.SUCCESS, "John the Ripper 破解完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"破解失败: {str(e)}")
        finally:
            os.unlink(hash_file)
    
    def _crack_with_hashcat(self, hash_value: str):
        self._add_log(LogLevel.INFO, "使用 Hashcat 破解")
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(hash_value)
            hash_file = f.name
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            self._add_log(LogLevel.ERROR, "请选择字典文件")
            return
        
        try:
            hash_type = "0"
            hash_type_map = {
                "MD5": "0",
                "SHA1": "100",
                "SHA256": "1400",
                "SHA512": "1700",
                "NTLM": "1000"
            }
            hash_type = hash_type_map.get(self._hash_type_combo.currentText(), "0")
            
            args = ["-m", hash_type, "-a", "0", hash_file, dict_path]
            process = self._execute_tool("hashcat", args)
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._add_log(LogLevel.DEBUG, line.strip())
            
            self._add_log(LogLevel.SUCCESS, "Hashcat 破解完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"破解失败: {str(e)}")
        finally:
            os.unlink(hash_file)
    
    def _crack_builtin(self, hash_value: str):
        import hashlib
        
        self._add_log(LogLevel.INFO, "使用内置字典破解")
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            common_passwords = ["123456", "password", "admin", "12345678", "qwerty"]
        else:
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    common_passwords = [line.strip() for line in f if line.strip()]
            except:
                common_passwords = ["123456", "password", "admin", "12345678", "qwerty"]
        
        hash_type = self._hash_type_combo.currentText().lower()
        
        for password in common_passwords:
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
                    import hashlib
                    computed = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                else:
                    computed = hashlib.md5(password.encode()).hexdigest()
                
                if computed.lower() == hash_value.lower():
                    self._add_result(hash_value, password, "破解成功")
                    self._add_log(LogLevel.SUCCESS, f"破解成功: {password}")
                    return
            except:
                pass
        
        self._add_result(hash_value, "", "未破解")
        self._add_log(LogLevel.INFO, "内置字典破解完成")


@register_module("online_brute")
class OnlineBruteWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("在线爆破")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        auth_group = QGroupBox("认证设置")
        auth_layout = QFormLayout(auth_group)
        
        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("登录URL")
        auth_layout.addRow("目标URL:", self._url_input)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        auth_layout.addRow("用户名:", self._username_input)
        
        self._param_combo = QComboBox()
        self._setup_combo(self._param_combo, [
            "POST参数", "Basic认证", "Digest认证", "NTLM认证"
        ])
        auth_layout.addRow("认证方式:", self._param_combo)
        
        layout.addWidget(auth_group)
        
        brute_group = QGroupBox("爆破选项")
        brute_layout = QFormLayout(brute_group)
        
        user_dict_layout = QHBoxLayout()
        self._user_dict_input = QLineEdit()
        self._user_dict_input.setPlaceholderText("用户名字典")
        user_dict_btn = QPushButton("选择")
        user_dict_btn.setFixedWidth(60)
        user_dict_btn.clicked.connect(lambda: self._select_dict_file("user"))
        user_dict_layout.addWidget(self._user_dict_input)
        user_dict_layout.addWidget(user_dict_btn)
        brute_layout.addRow("用户名字典:", user_dict_layout)
        
        pass_dict_layout = QHBoxLayout()
        self._pass_dict_input = QLineEdit()
        self._pass_dict_input.setPlaceholderText("密码字典")
        pass_dict_btn = QPushButton("选择")
        pass_dict_btn.setFixedWidth(60)
        pass_dict_btn.clicked.connect(lambda: self._select_dict_file("pass"))
        pass_dict_layout.addWidget(self._pass_dict_input)
        pass_dict_layout.addWidget(pass_dict_btn)
        brute_layout.addRow("密码字典:", pass_dict_layout)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(10)
        brute_layout.addRow("线程数:", self._threads_spin)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 10)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" 秒")
        brute_layout.addRow("请求延迟:", self._delay_spin)
        
        layout.addWidget(brute_group)
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
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["用户名", "密码", "状态码", "响应"])
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
        
        url = self._url_input.text().strip()
        if not url:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        username = self._username_input.text().strip()
        if not username:
            self._add_log(LogLevel.ERROR, "请输入用户名")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        pass_dict = self._pass_dict_input.text().strip()
        if not pass_dict:
            passwords = ["123456", "password", "admin", "12345678"]
        else:
            try:
                with open(pass_dict, 'r', encoding='utf-8') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except:
                passwords = ["123456", "password", "admin", "12345678"]
        
        self._add_log(LogLevel.INFO, f"开始在线爆破: {url}")
        
        for password in passwords:
            if not self._is_scanning:
                break
            
            try:
                resp = requests.post(url, 
                                   data={'username': username, 'password': password},
                                   timeout=10, 
                                   allow_redirects=False,
                                   verify=False)
                
                if resp.status_code == 200 and "登录失败" not in resp.text:
                    self._add_result(username, password, str(resp.status_code), "可能成功")
                    self._add_log(LogLevel.SUCCESS, f"可能正确的密码: {password}")
                else:
                    self._add_result(username, password, str(resp.status_code), resp.text[:50])
                
                delay = self._delay_spin.value()
                if delay > 0:
                    import time
                    time.sleep(delay)
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"请求失败: {str(e)}")
        
        self._add_log(LogLevel.INFO, "在线爆破完成")


@register_module("password_generator")
class PasswordGeneratorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("密码生成器")
    
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
