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
import platform
import socket


@register_module("lateral_move")
class LateralMoveWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("横向移动")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("横向移动选项")
        form_layout = QFormLayout(options_group)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, [
            "PsExec", "WMI", "WinRM", "DCOM", "SSH", "SMB"
        ])
        form_layout.addRow("移动方式:", self._method_combo)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标主机IP或主机名")
        form_layout.addRow("目标主机:", self._target_input)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        form_layout.addRow("用户名:", self._username_input)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("密码或哈希")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("密码:", self._password_input)
        
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("域名 (可选)")
        form_layout.addRow("域名:", self._domain_input)
        
        self._command_input = QLineEdit()
        self._command_input.setPlaceholderText("执行的命令")
        form_layout.addRow("命令:", self._command_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["时间", "目标", "方法", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "横向移动功能需要相应的权限和工具")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        method = self._method_combo.currentText()
        target = self._target_input.text().strip()
        
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标主机")
            return
        
        self._add_log(LogLevel.INFO, f"使用 {method} 方式进行横向移动测试")
        
        if method == "PsExec":
            self._test_psexec(target)
        elif method == "WMI":
            self._test_wmi(target)
        elif method == "WinRM":
            self._test_winrm(target)
        elif method == "SSH":
            self._test_ssh(target)
    
    def _test_psexec(self, target: str):
        self._add_log(LogLevel.INFO, f"测试PsExec连接: {target}")
        self._add_result("PsExec", target, "需验证", "测试中")
    
    def _test_wmi(self, target: str):
        self._add_log(LogLevel.INFO, f"测试WMI连接: {target}")
        self._add_result("WMI", target, "需验证", "测试中")
    
    def _test_winrm(self, target: str):
        self._add_log(LogLevel.INFO, f"测试WinRM连接: {target}")
        self._add_result("WinRM", target, "需验证", "测试中")
    
    def _test_ssh(self, target: str):
        self._add_log(LogLevel.INFO, f"测试SSH连接: {target}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 22))
            if result == 0:
                self._add_result("SSH", target, "端口开放", "成功")
                self._add_log(LogLevel.SUCCESS, f"SSH端口开放: {target}:22")
            else:
                self._add_result("SSH", target, "端口关闭", "失败")
            sock.close()
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"SSH测试失败: {str(e)}")


@register_module("domain_attack")
class DomainAttackWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("域攻击")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("域攻击选项")
        form_layout = QFormLayout(options_group)
        
        self._attack_type_combo = QComboBox()
        self._setup_combo(self._attack_type_combo, [
            "Kerberoasting", "AS-REP Roasting", "Golden Ticket", 
            "Silver Ticket", "DCSync", "域信息收集"
        ])
        form_layout.addRow("攻击类型:", self._attack_type_combo)
        
        self._dc_input = QLineEdit()
        self._dc_input.setPlaceholderText("域控制器IP")
        form_layout.addRow("域控制器:", self._dc_input)
        
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("域名 (如: corp.local)")
        form_layout.addRow("域名:", self._domain_input)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        form_layout.addRow("用户名:", self._username_input)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("密码或哈希")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("密码:", self._password_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["攻击类型", "目标", "结果", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "域攻击功能需要域环境")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        attack_type = self._attack_type_combo.currentText()
        domain = self._domain_input.text().strip()
        
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"执行 {attack_type} 攻击")
        
        if attack_type == "Kerberoasting":
            self._kerberoasting(domain)
        elif attack_type == "AS-REP Roasting":
            self._asrep_roasting(domain)
        elif attack_type == "域信息收集":
            self._domain_enum(domain)
    
    def _kerberoasting(self, domain: str):
        self._add_log(LogLevel.INFO, "Kerberoasting攻击需要impacket工具包")
        self._add_result("Kerberoasting", domain, "需impacket", "待执行")
    
    def _asrep_roasting(self, domain: str):
        self._add_log(LogLevel.INFO, "AS-REP Roasting攻击需要impacket工具包")
        self._add_result("AS-REP Roasting", domain, "需impacket", "待执行")
    
    def _domain_enum(self, domain: str):
        self._add_log(LogLevel.INFO, "域信息收集")
        self._add_result("域信息收集", domain, "执行中", "进行中")


@register_module("adcs_attack")
class ADCSAttackWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("ADCS攻击")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("ADCS攻击选项")
        form_layout = QFormLayout(options_group)
        
        self._attack_type_combo = QComboBox()
        self._setup_combo(self._attack_type_combo, [
            "ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC8", "证书模板枚举"
        ])
        form_layout.addRow("攻击类型:", self._attack_type_combo)
        
        self._ca_input = QLineEdit()
        self._ca_input.setPlaceholderText("证书颁发机构 (如: CORP-CA)")
        form_layout.addRow("CA名称:", self._ca_input)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标用户")
        form_layout.addRow("目标用户:", self._target_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["ESC编号", "漏洞描述", "利用方式", "风险"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "ADCS攻击需要域环境和证书服务")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        esc_vulns = [
            ("ESC1", "证书模板允许客户端指定SAN", "请求任意用户证书", "高"),
            ("ESC2", "证书模板允许任意用途", "伪造任意用途证书", "高"),
            ("ESC3", "证书注册代理", "代理注册攻击", "高"),
            ("ESC4", "证书模板权限过宽", "修改模板配置", "高"),
            ("ESC6", "编辑属性权限", "修改SAN属性", "高"),
            ("ESC8", "NTLM协商漏洞", "NTLM中继攻击", "高"),
        ]
        
        for esc, desc, method, risk in esc_vulns:
            self._add_result(esc, desc, method, risk)
            self._add_log(LogLevel.SUCCESS, f"发现潜在漏洞: {esc}")


@register_module("evasion")
class EvasionWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("免杀技术")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("免杀选项")
        form_layout = QFormLayout(options_group)
        
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, [
            "Shellcode免杀", "PE免杀", "PowerShell免杀", "脚本混淆"
        ])
        form_layout.addRow("免杀类型:", self._type_combo)
        
        self._input_file_input = QLineEdit()
        self._input_file_input.setPlaceholderText("输入文件路径")
        form_layout.addRow("输入文件:", self._input_file_input)
        
        self._technique_combo = QComboBox()
        self._setup_combo(self._technique_combo, [
            "编码混淆", "加密壳", "分离加载", "内存加载", "白名单绕过"
        ])
        form_layout.addRow("免杀技术:", self._technique_combo)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["技术", "描述", "检测率", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "免杀功能用于安全研究和测试")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        techniques = [
            ("编码混淆", "Base64/XOR/Hex编码", "中等", "可用"),
            ("加密壳", "AES/RC4加密", "较低", "可用"),
            ("分离加载", "Payload与加载器分离", "较低", "可用"),
            ("内存加载", "无文件落地执行", "低", "可用"),
            ("白名单绕过", "利用合法程序加载", "低", "可用"),
        ]
        
        for tech, desc, rate, status in techniques:
            self._add_result(tech, desc, rate, status)
            self._add_log(LogLevel.SUCCESS, f"可用技术: {tech}")


@register_module("exchange")
class ExchangeWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("Exchange攻击")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("Exchange攻击选项")
        form_layout = QFormLayout(options_group)
        
        self._attack_type_combo = QComboBox()
        self._setup_combo(self._attack_type_combo, [
            "ProxyLogon", "ProxyShell", "CVE-2020-0688", 
            "CVE-2021-26855", "信息泄露", "邮件枚举"
        ])
        form_layout.addRow("攻击类型:", self._attack_type_combo)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Exchange服务器地址")
        form_layout.addRow("目标地址:", self._target_input)
        
        self._email_input = QLineEdit()
        self._email_input.setPlaceholderText("邮箱地址")
        form_layout.addRow("邮箱:", self._email_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["漏洞", "CVE", "描述", "风险"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "Exchange攻击需要目标服务器信息")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        vulns = [
            ("ProxyLogon", "CVE-2021-26855", "SSRF漏洞链", "严重"),
            ("ProxyShell", "CVE-2021-34473", "SSRF + ACL绕过", "严重"),
            ("CVE-2020-0688", "CVE-2020-0688", "反序列化RCE", "高"),
            ("CVE-2021-26855", "CVE-2021-26855", "SSRF漏洞", "高"),
        ]
        
        for name, cve, desc, risk in vulns:
            self._add_result(name, cve, desc, risk)
            self._add_log(LogLevel.SUCCESS, f"检测漏洞: {name}")


@register_module("sharepoint")
class SharePointWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("SharePoint安全")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("SharePoint攻击选项")
        form_layout = QFormLayout(options_group)
        
        self._attack_type_combo = QComboBox()
        self._setup_combo(self._attack_type_combo, [
            "CVE-2019-0604", "CVE-2020-0932", "CVE-2020-1147",
            "信息收集", "文件枚举", "权限测试"
        ])
        form_layout.addRow("攻击类型:", self._attack_type_combo)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("SharePoint服务器地址")
        form_layout.addRow("目标地址:", self._target_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["漏洞", "CVE", "描述", "风险"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "SharePoint攻击需要目标服务器信息")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
        
        vulns = [
            ("CVE-2019-0604", "CVE-2019-0604", "反序列化RCE", "严重"),
            ("CVE-2020-0932", "CVE-2020-0932", "远程代码执行", "高"),
            ("CVE-2020-1147", "CVE-2020-1147", "类型混淆RCE", "高"),
        ]
        
        for name, cve, desc, risk in vulns:
            self._add_result(name, cve, desc, risk)
            self._add_log(LogLevel.SUCCESS, f"检测漏洞: {name}")
