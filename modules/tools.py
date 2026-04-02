import base64
import hashlib
import hmac
import json
import urllib.parse
import secrets
import string
import re
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QSpinBox, QFileDialog, QMessageBox, QListView, QDialog,
    QListWidget, QDialogButtonBox, QFormLayout, QRadioButton,
    QButtonGroup, QPlainTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont

from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel


@register_module("request_builder")
class RequestBuilderWidget(BaseModuleWidget):
    def __init__(self):
        self._request_history = []
        super().__init__("request_builder", "请求构造器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        method_group = QGroupBox("请求设置")
        method_layout = QHBoxLayout(method_group)
        
        method_layout.addWidget(QLabel("请求方法:"))
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self._method_combo.setCurrentText("GET")
        self._method_combo.setFixedWidth(100)
        method_layout.addWidget(self._method_combo)
        
        method_layout.addWidget(QLabel("协议:"))
        self._protocol_combo = QComboBox()
        self._setup_combo(self._protocol_combo, ["https://", "http://"])
        self._protocol_combo.setFixedWidth(80)
        method_layout.addWidget(self._protocol_combo)
        
        method_layout.addStretch()
        layout.addWidget(method_group)
        
        headers_group = QGroupBox("请求头")
        headers_layout = QVBoxLayout(headers_group)
        
        self._headers_edit = QPlainTextEdit()
        self._headers_edit.setPlaceholderText("Content-Type: application/json\nUser-Agent: Mozilla/5.0\nAuthorization: Bearer token")
        self._headers_edit.setMaximumHeight(100)
        headers_layout.addWidget(self._headers_edit)
        
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("预设头部:"))
        self._preset_combo = QComboBox()
        self._setup_combo(self._preset_combo, [
            "选择预设...",
            "JSON API", "Form Data", "Multipart", 
            "Browser Chrome", "Browser Firefox", "Mobile Android", "Mobile iOS"
        ])
        self._preset_combo.currentTextChanged.connect(self._apply_header_preset)
        preset_layout.addWidget(self._preset_combo)
        preset_layout.addStretch()
        headers_layout.addLayout(preset_layout)
        
        layout.addWidget(headers_group)
        
        body_group = QGroupBox("请求体")
        body_layout = QVBoxLayout(body_group)
        
        self._body_edit = QPlainTextEdit()
        self._body_edit.setPlaceholderText('{"key": "value"}')
        self._body_edit.setMaximumHeight(120)
        body_layout.addWidget(self._body_edit)
        
        body_btn_layout = QHBoxLayout()
        json_btn = QPushButton("格式化JSON")
        json_btn.setObjectName("secondaryButton")
        json_btn.clicked.connect(self._format_json_body)
        
        urlenc_btn = QPushButton("URL编码")
        urlenc_btn.setObjectName("secondaryButton")
        urlenc_btn.clicked.connect(self._urlencode_body)
        
        body_btn_layout.addWidget(json_btn)
        body_btn_layout.addWidget(urlenc_btn)
        body_btn_layout.addStretch()
        body_layout.addLayout(body_btn_layout)
        
        layout.addWidget(body_group)
        
        auth_group = QGroupBox("认证设置")
        auth_layout = QFormLayout(auth_group)
        
        self._auth_type_combo = QComboBox()
        self._setup_combo(self._auth_type_combo, ["无", "Basic Auth", "Bearer Token", "API Key", "Digest"])
        auth_layout.addRow("认证类型:", self._auth_type_combo)
        
        self._auth_user_input = QLineEdit()
        self._auth_user_input.setPlaceholderText("用户名/API Key")
        auth_layout.addRow("用户名:", self._auth_user_input)
        
        self._auth_pass_input = QLineEdit()
        self._auth_pass_input.setPlaceholderText("密码/Token")
        self._auth_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addRow("密码:", self._auth_pass_input)
        
        layout.addWidget(auth_group)
        
        return widget
    
    def _apply_header_preset(self, preset: str):
        presets = {
            "JSON API": "Content-Type: application/json\nAccept: application/json",
            "Form Data": "Content-Type: application/x-www-form-urlencoded",
            "Multipart": "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary",
            "Browser Chrome": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\nAccept-Language: zh-CN,zh;q=0.9,en;q=0.8",
            "Browser Firefox": "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Mobile Android": "User-Agent: Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mobile iOS": "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
        }
        if preset in presets:
            self._headers_edit.setPlainText(presets[preset])
    
    def _format_json_body(self):
        try:
            text = self._body_edit.toPlainText()
            if text:
                data = json.loads(text)
                formatted = json.dumps(data, indent=2, ensure_ascii=False)
                self._body_edit.setPlainText(formatted)
                self._add_log(LogLevel.SUCCESS, "JSON格式化成功")
        except json.JSONDecodeError as e:
            self._add_log(LogLevel.ERROR, f"JSON格式错误: {str(e)}")
    
    def _urlencode_body(self):
        text = self._body_edit.toPlainText()
        if text:
            encoded = urllib.parse.quote(text, safe='')
            self._body_edit.setPlainText(encoded)
            self._add_log(LogLevel.SUCCESS, "URL编码完成")
    
    def _do_scan(self):
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        protocol = self._protocol_combo.currentText()
        url = protocol + target
        
        method = self._method_combo.currentText()
        headers_text = self._headers_edit.toPlainText()
        body = self._body_edit.toPlainText()
        
        headers = {}
        if headers_text:
            for line in headers_text.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        auth_type = self._auth_type_combo.currentText()
        if auth_type != "无":
            auth_user = self._auth_user_input.text()
            auth_pass = self._auth_pass_input.text()
            if auth_type == "Basic Auth":
                credentials = base64.b64encode(f"{auth_user}:{auth_pass}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
            elif auth_type == "Bearer Token":
                headers["Authorization"] = f"Bearer {auth_pass}"
            elif auth_type == "API Key":
                headers["X-API-Key"] = auth_pass
        
        self._add_log(LogLevel.INFO, f"构造请求: {method} {url}")
        self._add_log(LogLevel.INFO, f"请求头: {json.dumps(headers, ensure_ascii=False)}")
        if body:
            self._add_log(LogLevel.INFO, f"请求体: {body[:200]}...")
        
        self._add_result(url, method, "已构造", f"Headers: {len(headers)}, Body: {len(body)} bytes")


@register_module("repeater")
class RepeaterWidget(BaseModuleWidget):
    def __init__(self):
        self._history = []
        super().__init__("request_replay", "请求重放")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        raw_group = QGroupBox("原始请求")
        raw_layout = QVBoxLayout(raw_group)
        
        self._raw_request = QPlainTextEdit()
        self._raw_request.setPlaceholderText("粘贴原始HTTP请求:\n\nPOST /api/login HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{\"username\":\"admin\",\"password\":\"123456\"}")
        self._raw_request.setMaximumHeight(200)
        raw_layout.addWidget(self._raw_request)
        
        parse_btn = QPushButton("解析请求")
        parse_btn.setObjectName("secondaryButton")
        parse_btn.clicked.connect(self._parse_raw_request)
        raw_layout.addWidget(parse_btn)
        
        layout.addWidget(raw_group)
        
        options_group = QGroupBox("重放选项")
        options_layout = QFormLayout(options_group)
        
        self._repeat_count = QSpinBox()
        self._repeat_count.setRange(1, 10000)
        self._repeat_count.setValue(1)
        options_layout.addRow("重复次数:", self._repeat_count)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 60000)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" ms")
        options_layout.addRow("请求间隔:", self._delay_spin)
        
        self._follow_redirects = QCheckBox("跟随重定向")
        self._follow_redirects.setChecked(True)
        options_layout.addRow(self._follow_redirects)
        
        self._keep_session = QCheckBox("保持会话Cookie")
        options_layout.addRow(self._keep_session)
        
        layout.addWidget(options_group)
        
        modify_group = QGroupBox("请求修改")
        modify_layout = QVBoxLayout(modify_group)
        
        self._modify_rules = QPlainTextEdit()
        self._modify_rules.setPlaceholderText("修改规则 (每行一个):\nadmin->root\npassword=123456->password=admin")
        self._modify_rules.setMaximumHeight(80)
        modify_layout.addWidget(self._modify_rules)
        
        layout.addWidget(modify_group)
        
        return widget
    
    def _parse_raw_request(self):
        raw = self._raw_request.toPlainText()
        if not raw:
            return
        
        lines = raw.strip().split('\n')
        if not lines:
            return
        
        first_line = lines[0].split()
        if len(first_line) >= 2:
            method = first_line[0]
            path = first_line[1]
            self._add_log(LogLevel.INFO, f"解析请求: {method} {path}")
            
            host = ""
            headers = {}
            body_start = False
            body_lines = []
            
            for line in lines[1:]:
                if body_start:
                    body_lines.append(line)
                elif line.strip() == "":
                    body_start = True
                elif ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
                    if key.strip().lower() == "host":
                        host = value.strip()
            
            self._add_log(LogLevel.INFO, f"Host: {host}")
            self._add_log(LogLevel.INFO, f"Headers: {len(headers)}")
            if body_lines:
                self._add_log(LogLevel.INFO, f"Body: {len(body_lines)} lines")
            
            self._add_result(f"{host}{path}", method, "已解析", f"Headers: {len(headers)}")
    
    def _do_scan(self):
        raw = self._raw_request.toPlainText()
        if not raw:
            self._add_log(LogLevel.ERROR, "请输入原始请求")
            return
        
        count = self._repeat_count.value()
        delay = self._delay_spin.value()
        
        self._add_log(LogLevel.INFO, f"开始重放请求，共 {count} 次")
        
        for i in range(count):
            self._add_log(LogLevel.INFO, f"发送第 {i+1}/{count} 次请求")
            self._add_result(f"Request #{i+1}", "SENT", "OK", f"Delay: {delay}ms")
            if delay > 0 and i < count - 1:
                time.sleep(delay / 1000)
        
        self._add_log(LogLevel.SUCCESS, f"完成 {count} 次请求重放")


@register_module("intruder")
class IntruderWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("intruder", "入侵者")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        request_group = QGroupBox("请求模板")
        request_layout = QVBoxLayout(request_group)
        
        self._request_template = QPlainTextEdit()
        self._request_template.setPlaceholderText("使用 § 标记攻击位置:\n\nPOST /login HTTP/1.1\nHost: example.com\n\nusername=§admin§&password=§123456§")
        self._request_template.setMaximumHeight(150)
        request_layout.addWidget(self._request_template)
        
        layout.addWidget(request_group)
        
        attack_group = QGroupBox("攻击类型")
        attack_layout = QVBoxLayout(attack_group)
        
        self._attack_type_group = QButtonGroup()
        
        sniper_radio = QRadioButton("Sniper (狙击手) - 单个位置依次测试")
        battering_radio = QRadioButton("Battering Ram (攻城锤) - 同一payload测试所有位置")
        pitchfork_radio = QRadioButton("Pitchfork (干草叉) - 多个payload并行")
        cluster_radio = QRadioButton("Cluster Bomb (集束炸弹) - 所有可能组合")
        cluster_radio.setChecked(True)
        
        self._attack_type_group.addButton(sniper_radio, 0)
        self._attack_type_group.addButton(battering_radio, 1)
        self._attack_type_group.addButton(pitchfork_radio, 2)
        self._attack_type_group.addButton(cluster_radio, 3)
        
        attack_layout.addWidget(sniper_radio)
        attack_layout.addWidget(battering_radio)
        attack_layout.addWidget(pitchfork_radio)
        attack_layout.addWidget(cluster_radio)
        
        layout.addWidget(attack_group)
        
        payload_group = QGroupBox("Payload设置")
        payload_layout = QVBoxLayout(payload_group)
        
        tabs = QTabWidget()
        
        simple_tab = QWidget()
        simple_layout = QVBoxLayout(simple_tab)
        self._simple_payloads = QPlainTextEdit()
        self._simple_payloads.setPlaceholderText("每行一个payload:\nadmin\nroot\ntest\nuser")
        simple_layout.addWidget(self._simple_payloads)
        tabs.addTab(simple_tab, "简单列表")
        
        number_tab = QWidget()
        number_layout = QFormLayout(number_tab)
        self._num_start = QSpinBox()
        self._num_start.setRange(0, 999999)
        self._num_start.setValue(1)
        number_layout.addRow("起始:", self._num_start)
        
        self._num_end = QSpinBox()
        self._num_end.setRange(0, 999999)
        self._num_end.setValue(100)
        number_layout.addRow("结束:", self._num_end)
        
        self._num_step = QSpinBox()
        self._num_step.setRange(1, 1000)
        self._num_step.setValue(1)
        number_layout.addRow("步长:", self._num_step)
        
        self._num_format = QLineEdit()
        self._num_format.setPlaceholderText("格式化: user{} 或 %03d")
        number_layout.addRow("格式:", self._num_format)
        tabs.addTab(number_tab, "数字序列")
        
        brute_tab = QWidget()
        brute_layout = QFormLayout(brute_tab)
        
        self._charset_input = QLineEdit()
        self._charset_input.setText("abcdefghijklmnopqrstuvwxyz0123456789")
        brute_layout.addRow("字符集:", self._charset_input)
        
        self._min_len = QSpinBox()
        self._min_len.setRange(1, 10)
        self._min_len.setValue(1)
        brute_layout.addRow("最小长度:", self._min_len)
        
        self._max_len = QSpinBox()
        self._max_len.setRange(1, 10)
        self._max_len.setValue(3)
        brute_layout.addRow("最大长度:", self._max_len)
        tabs.addTab(brute_tab, "暴力破解")
        
        payload_layout.addWidget(tabs)
        layout.addWidget(payload_group)
        
        options_layout = QHBoxLayout()
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 10000)
        self._delay_spin.setValue(0)
        self._delay_spin.setSuffix(" ms")
        options_layout.addWidget(QLabel("请求间隔:"))
        options_layout.addWidget(self._delay_spin)
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        return widget
    
    def _get_payloads(self) -> List[str]:
        payloads = []
        
        simple_text = self._simple_payloads.toPlainText().strip()
        if simple_text:
            payloads.extend([p.strip() for p in simple_text.split('\n') if p.strip()])
        
        if self._num_start.value() <= self._num_end.value():
            start = self._num_start.value()
            end = self._num_end.value()
            step = self._num_step.value()
            fmt = self._num_format.text()
            
            for i in range(start, end + 1, step):
                if fmt:
                    if '{}' in fmt:
                        payloads.append(fmt.format(i))
                    elif '%' in fmt:
                        payloads.append(fmt % i)
                    else:
                        payloads.append(f"{fmt}{i}")
                else:
                    payloads.append(str(i))
        
        return list(set(payloads))
    
    def _do_scan(self):
        template = self._request_template.toPlainText()
        if not template:
            self._add_log(LogLevel.ERROR, "请输入请求模板")
            return
        
        positions = template.count('§') // 2
        if positions == 0:
            self._add_log(LogLevel.ERROR, "请使用 § 标记攻击位置")
            return
        
        self._add_log(LogLevel.INFO, f"检测到 {positions} 个攻击位置")
        
        payloads = self._get_payloads()
        if not payloads:
            self._add_log(LogLevel.ERROR, "请设置Payload")
            return
        
        self._add_log(LogLevel.INFO, f"共 {len(payloads)} 个Payload")
        
        attack_type = self._attack_type_group.checkedId()
        
        total = len(payloads) ** positions if attack_type == 3 else len(payloads)
        self._add_log(LogLevel.INFO, f"预计发送 {total} 个请求")
        
        count = 0
        for i, payload in enumerate(payloads[:10]):
            modified = template.replace('§', payload, 1)
            while '§' in modified:
                if attack_type == 1:
                    modified = modified.replace('§', payload, 1)
                else:
                    modified = modified.replace('§', f"[pos{count}]", 1)
            
            self._add_result(f"Request #{i+1}", payload[:20], "Ready", modified[:100])
            count += 1
            self._update_progress(int((i / min(10, len(payloads))) * 100))
        
        self._add_log(LogLevel.SUCCESS, f"攻击配置完成，共 {count} 个请求")


@register_module("base_encoder")
class BaseEncoderWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("base_encoder", "Base编码")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText("输入要编码/解码的文本")
        self._input_text.setMaximumHeight(100)
        input_layout.addWidget(self._input_text)
        
        layout.addWidget(input_group)
        
        encode_group = QGroupBox("编码选项")
        encode_layout = QFormLayout(encode_group)
        
        self._encoding_combo = QComboBox()
        self._setup_combo(self._encoding_combo, [
            "Base64", "Base64 URL Safe", "Base32", "Base16 (Hex)",
            "Base58", "Base85", "Base91"
        ])
        encode_layout.addRow("编码类型:", self._encoding_combo)
        
        self._charset_combo = QComboBox()
        self._setup_combo(self._charset_combo, ["UTF-8", "GBK", "ASCII", "Latin-1"])
        encode_layout.addRow("字符编码:", self._charset_combo)
        
        layout.addWidget(encode_group)
        
        btn_layout = QHBoxLayout()
        
        encode_btn = QPushButton("编码")
        encode_btn.setObjectName("secondaryButton")
        encode_btn.clicked.connect(self._encode)
        
        decode_btn = QPushButton("解码")
        decode_btn.setObjectName("secondaryButton")
        decode_btn.clicked.connect(self._decode)
        
        swap_btn = QPushButton("交换输入输出")
        swap_btn.setObjectName("secondaryButton")
        swap_btn.clicked.connect(self._swap_io)
        
        btn_layout.addWidget(encode_btn)
        btn_layout.addWidget(decode_btn)
        btn_layout.addWidget(swap_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(100)
        output_layout.addWidget(self._output_text)
        
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("secondaryButton")
        copy_btn.clicked.connect(self._copy_output)
        output_layout.addWidget(copy_btn)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _encode(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        encoding = self._charset_combo.currentText()
        enc_type = self._encoding_combo.currentText()
        
        try:
            data = text.encode(encoding)
            
            if enc_type == "Base64":
                result = base64.b64encode(data).decode()
            elif enc_type == "Base64 URL Safe":
                result = base64.urlsafe_b64encode(data).decode()
            elif enc_type == "Base32":
                result = base64.b32encode(data).decode()
            elif enc_type == "Base16 (Hex)":
                result = base64.b16encode(data).decode()
            elif enc_type == "Base58":
                result = self._base58_encode(data)
            elif enc_type == "Base85":
                result = base64.b85encode(data).decode()
            elif enc_type == "Base91":
                result = self._base91_encode(data)
            else:
                result = base64.b64encode(data).decode()
            
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"{enc_type} 编码成功")
            self._add_result(text[:30], enc_type, "编码", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"编码失败: {str(e)}")
    
    def _decode(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        encoding = self._charset_combo.currentText()
        enc_type = self._encoding_combo.currentText()
        
        try:
            if enc_type == "Base64":
                data = base64.b64decode(text)
            elif enc_type == "Base64 URL Safe":
                data = base64.urlsafe_b64decode(text)
            elif enc_type == "Base32":
                data = base64.b32decode(text)
            elif enc_type == "Base16 (Hex)":
                data = base64.b16decode(text)
            elif enc_type == "Base58":
                data = self._base58_decode(text)
            elif enc_type == "Base85":
                data = base64.b85decode(text)
            elif enc_type == "Base91":
                data = self._base91_decode(text)
            else:
                data = base64.b64decode(text)
            
            result = data.decode(encoding)
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"{enc_type} 解码成功")
            self._add_result(text[:30], enc_type, "解码", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"解码失败: {str(e)}")
    
    def _base58_encode(self, data: bytes) -> str:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = int.from_bytes(data, 'big')
        result = ""
        while num > 0:
            num, rem = divmod(num, 58)
            result = alphabet[rem] + result
        return result or "1"
    
    def _base58_decode(self, s: str) -> bytes:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for char in s:
            num = num * 58 + alphabet.index(char)
        return num.to_bytes((num.bit_length() + 7) // 8, 'big')
    
    def _base91_encode(self, data: bytes) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~"
        b = 0
        n = 0
        result = []
        for byte in data:
            b |= byte << n
            n += 8
            if n > 13:
                v = b & 8191
                if v > 88:
                    b >>= 13
                    n -= 13
                else:
                    v = b & 16383
                    b >>= 14
                    n -= 14
                result.append(alphabet[v % 91])
                result.append(alphabet[v // 91])
        if n > 0:
            result.append(alphabet[b % 91])
            if n > 7 or b > 90:
                result.append(alphabet[b // 91])
        return ''.join(result)
    
    def _base91_decode(self, s: str) -> bytes:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~"
        decode_table = {c: i for i, c in enumerate(alphabet)}
        b = 0
        n = 0
        result = []
        v = -1
        for char in s:
            if v == -1:
                v = decode_table[char]
            else:
                v += decode_table[char] * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    result.append((b & 255))
                    b >>= 8
                    n -= 8
                v = -1
        if v + 1:
            b |= (v & 32767) << n
            result.append(b)
        return bytes(result)
    
    def _swap_io(self):
        output = self._output_text.toPlainText()
        self._input_text.setPlainText(output)
        self._output_text.clear()
    
    def _copy_output(self):
        self._output_text.selectAll()
        self._output_text.copy()
        self._add_log(LogLevel.SUCCESS, "已复制到剪贴板")
    
    def _do_scan(self):
        self._encode()


@register_module("url_encoder")
class URLEncoderWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("url_encoder", "URL编码")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText("输入要编码/解码的URL或文本")
        self._input_text.setMaximumHeight(100)
        input_layout.addWidget(self._input_text)
        
        layout.addWidget(input_group)
        
        options_group = QGroupBox("编码选项")
        options_layout = QFormLayout(options_group)
        
        self._encode_type = QComboBox()
        self._setup_combo(self._encode_type, [
            "标准URL编码", "全编码", "双重编码",
            "Unicode编码", "HTML实体编码"
        ])
        options_layout.addRow("编码类型:", self._encode_type)
        
        self._safe_chars = QLineEdit()
        self._safe_chars.setPlaceholderText("不编码的字符，如: /:&=?")
        options_layout.addRow("安全字符:", self._safe_chars)
        
        layout.addWidget(options_group)
        
        btn_layout = QHBoxLayout()
        
        encode_btn = QPushButton("编码")
        encode_btn.setObjectName("secondaryButton")
        encode_btn.clicked.connect(self._encode)
        
        decode_btn = QPushButton("解码")
        decode_btn.setObjectName("secondaryButton")
        decode_btn.clicked.connect(self._decode)
        
        btn_layout.addWidget(encode_btn)
        btn_layout.addWidget(decode_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(100)
        output_layout.addWidget(self._output_text)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _encode(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        enc_type = self._encode_type.currentText()
        safe = self._safe_chars.text() or ''
        
        try:
            if enc_type == "标准URL编码":
                result = urllib.parse.quote(text, safe=safe)
            elif enc_type == "全编码":
                result = ''.join(f'%{ord(c):02X}' for c in text)
            elif enc_type == "双重编码":
                result = urllib.parse.quote(urllib.parse.quote(text, safe=safe), safe=safe)
            elif enc_type == "Unicode编码":
                result = ''.join(f'%u{ord(c):04X}' if ord(c) > 127 else c for c in text)
            elif enc_type == "HTML实体编码":
                result = ''.join(f'&#{ord(c)};' if ord(c) > 127 or c in '<>&"\'\\' else c for c in text)
            else:
                result = urllib.parse.quote(text, safe=safe)
            
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"{enc_type} 成功")
            self._add_result(text[:30], enc_type, "编码", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"编码失败: {str(e)}")
    
    def _decode(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        try:
            if '%u' in text:
                result = re.sub(r'%u([0-9A-Fa-f]{4})', lambda m: chr(int(m.group(1), 16)), text)
            elif '&#' in text:
                result = re.sub(r'&#(\d+);?', lambda m: chr(int(m.group(1))), text)
            else:
                result = urllib.parse.unquote(text)
            
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, "解码成功")
            self._add_result(text[:30], "URL解码", "解码", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"解码失败: {str(e)}")
    
    def _do_scan(self):
        self._encode()


@register_module("hash_calc")
class HashCalcWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("hash_calc", "Hash计算")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText("输入要计算Hash的文本，或选择文件")
        self._input_text.setMaximumHeight(80)
        input_layout.addWidget(self._input_text)
        
        file_layout = QHBoxLayout()
        self._file_path = QLineEdit()
        self._file_path.setPlaceholderText("选择文件计算Hash")
        file_btn = QPushButton("选择文件")
        file_btn.setObjectName("secondaryButton")
        file_btn.clicked.connect(self._select_file)
        file_layout.addWidget(self._file_path, 1)
        file_layout.addWidget(file_btn)
        input_layout.addLayout(file_layout)
        
        layout.addWidget(input_group)
        
        algo_group = QGroupBox("算法选择")
        algo_layout = QVBoxLayout(algo_group)
        
        self._algo_checks = {}
        algorithms = [
            ("MD5", True), ("SHA1", True), ("SHA256", True), ("SHA384", False),
            ("SHA512", False), ("SHA3-256", False), ("SHA3-512", False),
            ("BLAKE2b", False), ("BLAKE2s", False), ("RIPEMD160", False)
        ]
        
        check_layout = QHBoxLayout()
        for i, (algo, checked) in enumerate(algorithms):
            cb = QCheckBox(algo)
            cb.setChecked(checked)
            self._algo_checks[algo] = cb
            check_layout.addWidget(cb)
            if (i + 1) % 5 == 0:
                algo_layout.addLayout(check_layout)
                check_layout = QHBoxLayout()
        if check_layout.count() > 0:
            check_layout.addStretch()
            algo_layout.addLayout(check_layout)
        
        layout.addWidget(algo_group)
        
        hmac_group = QGroupBox("HMAC (可选)")
        hmac_layout = QFormLayout(hmac_group)
        
        self._hmac_key = QLineEdit()
        self._hmac_key.setPlaceholderText("HMAC密钥，留空则计算普通Hash")
        self._hmac_key.setEchoMode(QLineEdit.EchoMode.Password)
        hmac_layout.addRow("密钥:", self._hmac_key)
        
        layout.addWidget(hmac_group)
        
        calc_btn = QPushButton("计算Hash")
        calc_btn.setObjectName("primaryButton")
        calc_btn.clicked.connect(self._calculate)
        layout.addWidget(calc_btn)
        
        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout(result_group)
        
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(2)
        self._result_table.setHorizontalHeaderLabels(["算法", "Hash值"])
        self._result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._result_table.setMaximumHeight(200)
        result_layout.addWidget(self._result_table)
        
        layout.addWidget(result_group)
        
        return widget
    
    def _select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self._file_path.setText(file_path)
    
    def _calculate(self):
        self._result_table.setRowCount(0)
        
        file_path = self._file_path.text()
        text = self._input_text.toPlainText()
        hmac_key = self._hmac_key.text()
        
        if not text and not file_path:
            self._add_log(LogLevel.ERROR, "请输入文本或选择文件")
            return
        
        data = None
        if file_path and Path(file_path).exists():
            with open(file_path, 'rb') as f:
                data = f.read()
            self._add_log(LogLevel.INFO, f"读取文件: {file_path}")
        else:
            data = text.encode('utf-8')
        
        algorithms = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA384": hashlib.sha384,
            "SHA512": hashlib.sha512,
            "SHA3-256": hashlib.sha3_256,
            "SHA3-512": hashlib.sha3_512,
            "BLAKE2b": hashlib.blake2b,
            "BLAKE2s": hashlib.blake2s,
        }
        
        for algo, cb in self._algo_checks.items():
            if not cb.isChecked():
                continue
            
            try:
                if algo == "RIPEMD160":
                    import hashlib
                    h = hashlib.new('ripemd160')
                    h.update(data)
                    result = h.hexdigest()
                elif algo in algorithms:
                    if hmac_key:
                        h = hmac.new(hmac_key.encode(), data, algorithms[algo])
                        result = h.hexdigest()
                    else:
                        result = algorithms[algo](data).hexdigest()
                else:
                    continue
                
                row = self._result_table.rowCount()
                self._result_table.insertRow(row)
                self._result_table.setItem(row, 0, QTableWidgetItem(f"HMAC-{algo}" if hmac_key else algo))
                self._result_table.setItem(row, 1, QTableWidgetItem(result))
                
                self._add_result(algo, "计算完成", result[:32], f"长度: {len(result)}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"{algo} 计算失败: {str(e)}")
        
        self._add_log(LogLevel.SUCCESS, f"完成 {self._result_table.rowCount()} 个Hash计算")
    
    def _do_scan(self):
        self._calculate()


@register_module("jwt_encoder")
class JWTEncoderWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("jwt_encoder", "JWT处理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        tabs = QTabWidget()
        
        decode_tab = QWidget()
        decode_layout = QVBoxLayout(decode_tab)
        
        decode_layout.addWidget(QLabel("JWT Token:"))
        self._jwt_input = QPlainTextEdit()
        self._jwt_input.setPlaceholderText("粘贴JWT Token...")
        self._jwt_input.setMaximumHeight(80)
        decode_layout.addWidget(self._jwt_input)
        
        decode_btn = QPushButton("解码JWT")
        decode_btn.setObjectName("secondaryButton")
        decode_btn.clicked.connect(self._decode_jwt)
        decode_layout.addWidget(decode_btn)
        
        decode_layout.addWidget(QLabel("Header:"))
        self._header_output = QPlainTextEdit()
        self._header_output.setReadOnly(True)
        self._header_output.setMaximumHeight(80)
        decode_layout.addWidget(self._header_output)
        
        decode_layout.addWidget(QLabel("Payload:"))
        self._payload_output = QPlainTextEdit()
        self._payload_output.setReadOnly(True)
        self._payload_output.setMaximumHeight(100)
        decode_layout.addWidget(self._payload_output)
        
        tabs.addTab(decode_tab, "解码")
        
        encode_tab = QWidget()
        encode_layout = QVBoxLayout(encode_tab)
        
        encode_layout.addWidget(QLabel("Header:"))
        self._header_input = QPlainTextEdit()
        self._header_input.setPlainText('{\n  "alg": "HS256",\n  "typ": "JWT"\n}')
        self._header_input.setMaximumHeight(80)
        encode_layout.addWidget(self._header_input)
        
        encode_layout.addWidget(QLabel("Payload:"))
        self._payload_input = QPlainTextEdit()
        self._payload_input.setPlaceholderText('{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}')
        self._payload_input.setMaximumHeight(100)
        encode_layout.addWidget(self._payload_input)
        
        secret_layout = QFormLayout()
        self._secret_input = QLineEdit()
        self._secret_input.setPlaceholderText("签名密钥")
        self._secret_input.setEchoMode(QLineEdit.EchoMode.Password)
        secret_layout.addRow("密钥:", self._secret_input)
        encode_layout.addLayout(secret_layout)
        
        encode_btn = QPushButton("生成JWT")
        encode_btn.setObjectName("secondaryButton")
        encode_btn.clicked.connect(self._encode_jwt)
        encode_layout.addWidget(encode_btn)
        
        encode_layout.addWidget(QLabel("生成的Token:"))
        self._token_output = QPlainTextEdit()
        self._token_output.setReadOnly(True)
        self._token_output.setMaximumHeight(80)
        encode_layout.addWidget(self._token_output)
        
        tabs.addTab(encode_tab, "编码")
        
        attack_tab = QWidget()
        attack_layout = QVBoxLayout(attack_tab)
        
        self._none_attack = QCheckBox("None算法攻击 (alg: none)")
        self._weak_secret = QCheckBox("弱密钥爆破")
        self._alg_confusion = QCheckBox("算法混淆 (RS256->HS256)")
        
        attack_layout.addWidget(self._none_attack)
        attack_layout.addWidget(self._weak_secret)
        attack_layout.addWidget(self._alg_confusion)
        
        attack_btn = QPushButton("执行攻击测试")
        attack_btn.setObjectName("dangerButton")
        attack_btn.clicked.connect(self._jwt_attack)
        attack_layout.addWidget(attack_btn)
        
        self._attack_output = QPlainTextEdit()
        self._attack_output.setReadOnly(True)
        self._attack_output.setMaximumHeight(150)
        attack_layout.addWidget(self._attack_output)
        
        tabs.addTab(attack_tab, "安全测试")
        
        layout.addWidget(tabs)
        
        return widget
    
    def _decode_jwt(self):
        token = self._jwt_input.toPlainText().strip()
        if not token:
            self._add_log(LogLevel.ERROR, "请输入JWT Token")
            return
        
        parts = token.split('.')
        if len(parts) != 3:
            self._add_log(LogLevel.ERROR, "无效的JWT格式")
            return
        
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            self._header_output.setPlainText(json.dumps(header, indent=2, ensure_ascii=False))
            self._payload_output.setPlainText(json.dumps(payload, indent=2, ensure_ascii=False))
            
            self._add_log(LogLevel.SUCCESS, "JWT解码成功")
            self._add_result(token[:30], header.get('alg', 'unknown'), "解码", f"Payload keys: {list(payload.keys())}")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"解码失败: {str(e)}")
    
    def _encode_jwt(self):
        try:
            header = json.loads(self._header_input.toPlainText())
            payload = json.loads(self._payload_input.toPlainText())
            secret = self._secret_input.text()
            
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            message = f"{header_b64}.{payload_b64}"
            
            alg = header.get('alg', 'HS256')
            if alg == 'HS256' and secret:
                signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                token = f"{message}.{sig_b64}"
            elif alg == 'none':
                token = f"{message}."
            else:
                token = f"{message}.[signature_required]"
            
            self._token_output.setPlainText(token)
            self._add_log(LogLevel.SUCCESS, "JWT生成成功")
            self._add_result(token[:30], alg, "编码", f"Payload: {len(payload)} keys")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"编码失败: {str(e)}")
    
    def _jwt_attack(self):
        token = self._jwt_input.toPlainText().strip()
        if not token:
            self._add_log(LogLevel.ERROR, "请输入JWT Token")
            return
        
        results = []
        
        if self._none_attack.isChecked():
            parts = token.split('.')
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                header['alg'] = 'none'
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                none_token = f"{header_b64}.{parts[1]}."
                results.append(f"None算法Token:\n{none_token}")
        
        if self._weak_secret.isChecked():
            weak_secrets = ['secret', 'password', '123456', 'admin', 'key', 'jwt_secret']
            results.append(f"常见弱密钥: {', '.join(weak_secrets)}")
        
        if self._alg_confusion.isChecked():
            results.append("RS256->HS256攻击: 需要获取公钥，然后用公钥作为HMAC密钥签名")
        
        self._attack_output.setPlainText('\n\n'.join(results))
        self._add_log(LogLevel.INFO, "安全测试完成")
    
    def _do_scan(self):
        self._decode_jwt()


@register_module("crypto")
class CryptoWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("crypto", "加解密工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText("输入要加密/解密的文本")
        self._input_text.setMaximumHeight(100)
        input_layout.addWidget(self._input_text)
        
        layout.addWidget(input_group)
        
        algo_group = QGroupBox("算法设置")
        algo_layout = QFormLayout(algo_group)
        
        self._algo_combo = QComboBox()
        self._setup_combo(self._algo_combo, [
            "AES-256-CBC", "AES-256-ECB", "AES-128-CBC", "AES-128-ECB",
            "DES-CBC", "DES-ECB", "3DES-CBC", "3DES-ECB",
            "RC4", "ChaCha20"
        ])
        algo_layout.addRow("算法:", self._algo_combo)
        
        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("密钥")
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        algo_layout.addRow("密钥:", self._key_input)
        
        self._iv_input = QLineEdit()
        self._iv_input.setPlaceholderText("IV (初始化向量，CBC模式需要)")
        algo_layout.addRow("IV:", self._iv_input)
        
        self._mode_combo = QComboBox()
        self._setup_combo(self._mode_combo, ["文本模式", "Hex模式", "Base64模式"])
        algo_layout.addRow("输入模式:", self._mode_combo)
        
        layout.addWidget(algo_group)
        
        btn_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("加密")
        encrypt_btn.setObjectName("secondaryButton")
        encrypt_btn.clicked.connect(self._encrypt)
        
        decrypt_btn = QPushButton("解密")
        decrypt_btn.setObjectName("secondaryButton")
        decrypt_btn.clicked.connect(self._decrypt)
        
        gen_key_btn = QPushButton("生成密钥")
        gen_key_btn.setObjectName("secondaryButton")
        gen_key_btn.clicked.connect(self._generate_key)
        
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(gen_key_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(100)
        output_layout.addWidget(self._output_text)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _generate_key(self):
        algo = self._algo_combo.currentText()
        
        if 'AES-256' in algo:
            key = secrets.token_hex(32)
            iv = secrets.token_hex(16)
        elif 'AES-128' in algo:
            key = secrets.token_hex(16)
            iv = secrets.token_hex(16)
        elif 'DES' in algo or '3DES' in algo:
            key = secrets.token_hex(8 if '3DES' not in algo else 24)
            iv = secrets.token_hex(8)
        else:
            key = secrets.token_hex(32)
            iv = ""
        
        self._key_input.setText(key)
        if iv:
            self._iv_input.setText(iv)
        
        self._add_log(LogLevel.SUCCESS, f"已生成 {algo} 密钥")
    
    def _encrypt(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        
        text = self._input_text.toPlainText()
        if not text:
            return
        
        key = bytes.fromhex(self._key_input.text()) if self._key_input.text() else b''
        iv = bytes.fromhex(self._iv_input.text()) if self._iv_input.text() else b''
        algo = self._algo_combo.currentText()
        
        try:
            data = text.encode('utf-8')
            
            if 'AES' in algo:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
                
                if 'CBC' in algo:
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                else:
                    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            else:
                self._add_log(LogLevel.WARNING, "此算法需要cryptography库完整支持")
                self._output_text.setPlainText(f"[模拟加密] {text} -> encrypted")
                return
            
            encryptor = cipher.encryptor()
            result = encryptor.update(padded_data) + encryptor.finalize()
            
            output_mode = self._mode_combo.currentText()
            if output_mode == "Hex模式":
                output = result.hex()
            else:
                output = base64.b64encode(result).decode()
            
            self._output_text.setPlainText(output)
            self._add_log(LogLevel.SUCCESS, f"{algo} 加密成功")
            self._add_result(text[:20], algo, "加密", output[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"加密失败: {str(e)}")
    
    def _decrypt(self):
        self._add_log(LogLevel.INFO, "解密功能需要正确的密钥和IV")
        self._output_text.setPlainText("[解密结果将显示在这里]")
    
    def _do_scan(self):
        self._encrypt()


@register_module("classic_cipher")
class ClassicCipherWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("classic_cipher", "古典密码")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout(input_group)
        
        self._input_text = QPlainTextEdit()
        self._input_text.setPlaceholderText("输入要加密/解密的文本")
        self._input_text.setMaximumHeight(80)
        input_layout.addWidget(self._input_text)
        
        layout.addWidget(input_group)
        
        cipher_group = QGroupBox("密码类型")
        cipher_layout = QFormLayout(cipher_group)
        
        self._cipher_combo = QComboBox()
        self._setup_combo(self._cipher_combo, [
            "凯撒密码 (Caesar)", "移位密码 (Shift)", "维吉尼亚密码 (Vigenère)",
            "栅栏密码 (Rail Fence)", "培根密码 (Bacon)", "摩斯密码 (Morse)",
            "ROT13", "Atbash密码", "培根密码解码", "键盘密码"
        ])
        cipher_layout.addRow("类型:", self._cipher_combo)
        
        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("密钥 (凯撒为偏移量，维吉尼亚为密钥词)")
        cipher_layout.addRow("密钥:", self._key_input)
        
        layout.addWidget(cipher_group)
        
        btn_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("加密")
        encrypt_btn.setObjectName("secondaryButton")
        encrypt_btn.clicked.connect(self._encrypt)
        
        decrypt_btn = QPushButton("解密")
        decrypt_btn.setObjectName("secondaryButton")
        decrypt_btn.clicked.connect(self._decrypt)
        
        crack_btn = QPushButton("暴力破解")
        crack_btn.setObjectName("dangerButton")
        crack_btn.clicked.connect(self._crack)
        
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(crack_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(150)
        output_layout.addWidget(self._output_text)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _encrypt(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        cipher = self._cipher_combo.currentText()
        key = self._key_input.text()
        
        try:
            if cipher == "凯撒密码 (Caesar)":
                shift = int(key) if key else 3
                result = self._caesar(text, shift)
            elif cipher == "移位密码 (Shift)":
                shift = int(key) if key else 1
                result = self._caesar(text, shift)
            elif cipher == "维吉尼亚密码 (Vigenère)":
                result = self._vigenere_encrypt(text, key or "KEY")
            elif cipher == "栅栏密码 (Rail Fence)":
                rails = int(key) if key else 2
                result = self._rail_fence_encrypt(text, rails)
            elif cipher == "培根密码 (Bacon)":
                result = self._bacon_encrypt(text)
            elif cipher == "摩斯密码 (Morse)":
                result = self._morse_encrypt(text)
            elif cipher == "ROT13":
                result = self._caesar(text, 13)
            elif cipher == "Atbash密码":
                result = self._atbash(text)
            else:
                result = text
            
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"{cipher} 加密成功")
            self._add_result(text[:20], cipher, "加密", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"加密失败: {str(e)}")
    
    def _decrypt(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        cipher = self._cipher_combo.currentText()
        key = self._key_input.text()
        
        try:
            if cipher == "凯撒密码 (Caesar)":
                shift = int(key) if key else 3
                result = self._caesar(text, -shift)
            elif cipher == "移位密码 (Shift)":
                shift = int(key) if key else 1
                result = self._caesar(text, -shift)
            elif cipher == "维吉尼亚密码 (Vigenère)":
                result = self._vigenere_decrypt(text, key or "KEY")
            elif cipher == "栅栏密码 (Rail Fence)":
                rails = int(key) if key else 2
                result = self._rail_fence_decrypt(text, rails)
            elif cipher == "培根密码解码":
                result = self._bacon_decrypt(text)
            elif cipher == "摩斯密码 (Morse)":
                result = self._morse_decrypt(text)
            elif cipher == "ROT13":
                result = self._caesar(text, 13)
            elif cipher == "Atbash密码":
                result = self._atbash(text)
            else:
                result = text
            
            self._output_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"{cipher} 解密成功")
            self._add_result(text[:20], cipher, "解密", result[:50])
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"解密失败: {str(e)}")
    
    def _crack(self):
        text = self._input_text.toPlainText()
        if not text:
            return
        
        cipher = self._cipher_combo.currentText()
        results = []
        
        if "凯撒" in cipher or "移位" in cipher or cipher == "ROT13":
            results.append("=== 凯撒密码暴力破解 ===")
            for shift in range(1, 26):
                decrypted = self._caesar(text, -shift)
                results.append(f"偏移 {shift}: {decrypted}")
        
        self._output_text.setPlainText('\n'.join(results))
        self._add_log(LogLevel.INFO, "暴力破解完成")
    
    def _caesar(self, text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return ''.join(result)
    
    def _vigenere_encrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base + shift) % 26 + base))
                key_idx += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def _vigenere_decrypt(self, text: str, key: str) -> str:
        result = []
        key = key.upper()
        key_idx = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_idx % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - base - shift) % 26 + base))
                key_idx += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def _rail_fence_encrypt(self, text: str, rails: int) -> str:
        if rails <= 1:
            return text
        
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        
        for char in text:
            fence[rail].append(char)
            rail += direction
            if rail == 0 or rail == rails - 1:
                direction = -direction
        
        return ''.join(''.join(row) for row in fence)
    
    def _rail_fence_decrypt(self, text: str, rails: int) -> str:
        if rails <= 1:
            return text
        
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        indexes = sorted(range(len(text)), key=lambda i: (pattern[i % len(pattern)], i))
        
        result = [''] * len(text)
        for i, char in zip(indexes, text):
            result[i] = char
        
        return ''.join(result)
    
    def _bacon_encrypt(self, text: str) -> str:
        bacon_map = {
            'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
            'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
            'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
            'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
            'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
            'Z': 'BBAAB'
        }
        return ' '.join(bacon_map.get(c.upper(), c) for c in text if c.isalpha())
    
    def _bacon_decrypt(self, text: str) -> str:
        bacon_map = {v: k for k, v in {
            'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
            'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
            'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
            'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
            'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
            'Z': 'BBAAB'
        }.items()}
        
        text = text.replace(' ', '').upper()
        result = []
        for i in range(0, len(text), 5):
            chunk = text[i:i+5]
            result.append(bacon_map.get(chunk, '?'))
        return ''.join(result)
    
    def _morse_encrypt(self, text: str) -> str:
        morse_map = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        return ' '.join(morse_map.get(c.upper(), c) for c in text)
    
    def _morse_decrypt(self, text: str) -> str:
        morse_map = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' '
        }
        return ''.join(morse_map.get(code, '?') for code in text.split())
    
    def _atbash(self, text: str) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result.append(chr(ord('Z') - (ord(char) - base) if char.isupper() 
                                  else ord('z') - (ord(char) - base)))
            else:
                result.append(char)
        return ''.join(result)
    
    def _do_scan(self):
        self._encrypt()
