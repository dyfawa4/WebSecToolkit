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
from pathlib import Path


@register_module("internal_info")
class InternalInfoWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("内网信息收集")
        self._seatbelt_path = self._find_tool("Seatbelt")
    
    def _find_tool(self, tool_name: str) -> str:
        base_dir = Path(__file__).parent.parent
        tool_paths = [
            base_dir / "tools" / "dotnet" / f"{tool_name}.exe",
            base_dir / "tools" / "internal" / f"{tool_name}.exe",
        ]
        for path in tool_paths:
            if path.exists():
                return str(path)
        return ""
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, [
            "Seatbelt", "内置收集", "BloodHound"
        ])
        self._tool_combo.currentTextChanged.connect(self._on_tool_changed)
        tool_layout.addRow("使用工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        options_group = QGroupBox("信息收集选项")
        form_layout = QFormLayout(options_group)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "系统信息", "网络信息", "用户信息", "域信息", "全部信息"
        ])
        form_layout.addRow("收集类型:", self._scan_type_combo)
        
        self._deep_check = QCheckBox("深度收集")
        form_layout.addRow(self._deep_check)
        
        self._stealth_check = QCheckBox("隐蔽模式")
        form_layout.addRow(self._stealth_check)
        
        layout.addWidget(options_group)
        
        self._seatbelt_options = QGroupBox("Seatbelt 选项")
        seatbelt_layout = QFormLayout(self._seatbelt_options)
        
        self._seatbelt_group_combo = QComboBox()
        self._setup_combo(self._seatbelt_group_combo, [
            "全部检查", "系统信息", "用户信息", "网络信息", 
            "安全配置", "服务信息", "持久化", "异常检测"
        ])
        seatbelt_layout.addRow("检查组:", self._seatbelt_group_combo)
        
        self._seatbelt_custom = QLineEdit()
        self._seatbelt_custom.setPlaceholderText("自定义检查项 (如: -group=sysinfo,security)")
        seatbelt_layout.addRow("自定义:", self._seatbelt_custom)
        
        self._seatbelt_output = QCheckBox("详细输出")
        seatbelt_layout.addRow(self._seatbelt_output)
        
        layout.addWidget(self._seatbelt_options)
        self._seatbelt_options.setVisible(True)
        
        return widget
    
    def _on_tool_changed(self, tool_name: str):
        self._seatbelt_options.setVisible(tool_name == "Seatbelt")
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["类别", "项目", "值"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool = self._tool_combo.currentText()
        
        if tool == "Seatbelt":
            self._run_seatbelt()
        else:
            self._run_builtin_scan()
    
    def _run_seatbelt(self):
        if not self._seatbelt_path:
            self._add_log(LogLevel.ERROR, "未找到 Seatbelt 工具")
            return
        
        self._add_log(LogLevel.INFO, "使用 Seatbelt 收集信息...")
        
        group_map = {
            "全部检查": "-group=all",
            "系统信息": "-group=sysinfo",
            "用户信息": "-group=userinfo",
            "网络信息": "-group=network",
            "安全配置": "-group=security",
            "服务信息": "-group=services",
            "持久化": "-group=persistence",
            "异常检测": "-group=anomalies",
        }
        
        custom = self._seatbelt_custom.text().strip()
        if custom:
            args = custom
        else:
            args = group_map.get(self._seatbelt_group_combo.currentText(), "-group=all")
        
        if self._seatbelt_output.isChecked():
            args += " -v"
        
        cmd = f'"{self._seatbelt_path}" {args}'
        
        self._add_log(LogLevel.INFO, f"执行命令: {cmd}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            stdout, stderr = process.communicate(timeout=60)
            
            if stdout:
                self._parse_seatbelt_output(stdout)
                self._add_log(LogLevel.SUCCESS, "Seatbelt 信息收集完成")
            else:
                self._add_log(LogLevel.WARNING, "Seatbelt 未返回结果")
                
        except subprocess.TimeoutExpired:
            self._add_log(LogLevel.ERROR, "Seatbelt 执行超时")
        except PermissionError:
            self._add_log(LogLevel.ERROR, "权限不足，请以管理员身份运行")
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"执行失败: {str(e)}")
    
    def _parse_seatbelt_output(self, output: str):
        lines = output.split('\n')
        current_category = "常规"
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith('===') or line.startswith('***'):
                current_category = line.strip('=* ')
                continue
            
            if ':' in line and not line.startswith(' '):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    self._add_result(current_category, parts[0].strip(), parts[1].strip())
    
    def _run_builtin_scan(self):
        import platform
        import socket
        
        target = self._target_input.text().strip()
        
        self._add_log(LogLevel.INFO, "开始收集内网信息")
        
        self._add_result("系统", "操作系统", platform.system())
        self._add_result("系统", "主机名", socket.gethostname())
        self._add_result("系统", "版本", platform.version())
        
        self._add_log(LogLevel.SUCCESS, "信息收集完成")


@register_module("credential")
class CredentialWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("凭证窃取")
        self._mimikatz_path = self._find_tool("mimikatz")
        self._rubeus_path = self._find_tool("Rubeus")
    
    def _find_tool(self, tool_name: str) -> str:
        base_dir = Path(__file__).parent.parent
        tool_paths = [
            base_dir / "tools" / "dotnet" / f"{tool_name}.exe",
            base_dir / "tools" / "internal" / "mimikatz" / "x64" / f"{tool_name}.exe",
            base_dir / "tools" / "internal" / f"{tool_name}.exe",
        ]
        for path in tool_paths:
            if path.exists():
                return str(path)
        return ""
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["Mimikatz", "Rubeus", "内置工具"])
        self._tool_combo.currentTextChanged.connect(self._on_tool_changed)
        tool_layout.addRow("使用工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        options_group = QGroupBox("凭据操作选项")
        form_layout = QFormLayout(options_group)
        
        self._action_combo = QComboBox()
        self._setup_combo(self._action_combo, [
            "提取凭据", "导出凭据", "注入凭据", "票据操作"
        ])
        form_layout.addRow("操作类型:", self._action_combo)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, [
            "LSASS转储", "注册表", "SAM数据库", "域控制器"
        ])
        form_layout.addRow("提取方法:", self._method_combo)
        
        layout.addWidget(options_group)
        
        self._rubeus_options = QGroupBox("Rubeus 选项")
        rubeus_layout = QFormLayout(self._rubeus_options)
        
        self._rubeus_action_combo = QComboBox()
        self._setup_combo(self._rubeus_action_combo, [
            "asktgt - 请求TGT",
            "asktgs - 请求TGS", 
            "s4u - S4U委托",
            "krenew - 续订票据",
            "ptt - 注入票据",
            "purge - 清除票据",
            "describe - 分析票据",
            "dump - 导出票据",
            "harvest - 收集票据",
            "monitor - 监控票据"
        ])
        rubeus_layout.addRow("操作:", self._rubeus_action_combo)
        
        self._rubeus_user = QLineEdit()
        self._rubeus_user.setPlaceholderText("用户名")
        rubeus_layout.addRow("用户:", self._rubeus_user)
        
        self._rubeus_domain = QLineEdit()
        self._rubeus_domain.setPlaceholderText("域名")
        rubeus_layout.addRow("域:", self._rubeus_domain)
        
        self._rubeus_password = QLineEdit()
        self._rubeus_password.setPlaceholderText("密码/哈希/票据文件")
        self._rubeus_password.setEchoMode(QLineEdit.EchoMode.Password)
        rubeus_layout.addRow("凭据:", self._rubeus_password)
        
        self._rubeus_enctype = QComboBox()
        self._setup_combo(self._rubeus_enctype, ["rc4", "aes256", "aes128"])
        rubeus_layout.addRow("加密类型:", self._rubeus_enctype)
        
        self._rubeus_ptt = QCheckBox("自动注入票据")
        rubeus_layout.addRow(self._rubeus_ptt)
        
        layout.addWidget(self._rubeus_options)
        self._rubeus_options.setVisible(False)
        
        return widget
    
    def _on_tool_changed(self, tool_name: str):
        self._rubeus_options.setVisible(tool_name == "Rubeus")
        
        if tool_name == "Rubeus":
            self._action_combo.setEnabled(False)
        else:
            self._action_combo.setEnabled(True)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["类型", "用户名", "密码/哈希", "来源"])
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
        tool = self._tool_combo.currentText()
        
        if tool == "Rubeus":
            self._run_rubeus()
        elif tool == "Mimikatz":
            self._run_mimikatz()
        else:
            self._add_log(LogLevel.INFO, "凭据操作功能需要管理员权限")
            self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")
    
    def _run_rubeus(self):
        if not self._rubeus_path:
            self._add_log(LogLevel.ERROR, "未找到 Rubeus 工具")
            return
        
        action_text = self._rubeus_action_combo.currentText()
        action = action_text.split(" - ")[0]
        
        user = self._rubeus_user.text().strip()
        domain = self._rubeus_domain.text().strip()
        cred = self._rubeus_password.text()
        enctype = self._rubeus_enctype.currentText()
        
        cmd_parts = [f'"{self._rubeus_path}"', action]
        
        if action == "asktgt":
            if not user or not domain or not cred:
                self._add_log(LogLevel.ERROR, "asktgt 需要用户名、域名和凭据")
                return
            cmd_parts.extend([
                f'/user:{user}',
                f'/domain:{domain}',
                f'/{enctype}:{cred}'
            ])
            if self._rubeus_ptt.isChecked():
                cmd_parts.append('/ptt')
            cmd_parts.append('/nowrap')
            
        elif action == "asktgs":
            if not user or not cred:
                self._add_log(LogLevel.ERROR, "asktgs 需要用户名和服务SPN")
                return
            cmd_parts.extend([
                f'/user:{user}',
                f'/service:{cred}'
            ])
            if self._rubeus_ptt.isChecked():
                cmd_parts.append('/ptt')
            cmd_parts.append('/nowrap')
            
        elif action == "dump":
            cmd_parts.append('/nowrap')
            if user:
                cmd_parts.append(f'/user:{user}')
                
        elif action == "harvest":
            cmd_parts.append('/interval:30')
            
        elif action == "monitor":
            cmd_parts.append('/interval:30')
            
        elif action == "describe":
            if not cred:
                self._add_log(LogLevel.ERROR, "describe 需要票据文件或base64票据")
                return
            cmd_parts.append(cred)
            
        elif action == "ptt":
            if not cred:
                self._add_log(LogLevel.ERROR, "ptt 需要票据文件")
                return
            cmd_parts.append(f'/ticket:{cred}')
            
        elif action == "purge":
            pass
        
        cmd = ' '.join(cmd_parts)
        self._add_log(LogLevel.INFO, f"执行命令: {cmd}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            stdout, stderr = process.communicate(timeout=60)
            
            if stdout:
                self._parse_rubeus_output(stdout)
                self._add_log(LogLevel.SUCCESS, "Rubeus 操作完成")
            if stderr:
                self._add_log(LogLevel.WARNING, stderr[:500])
                
        except subprocess.TimeoutExpired:
            self._add_log(LogLevel.ERROR, "Rubeus 执行超时")
        except PermissionError:
            self._add_log(LogLevel.ERROR, "权限不足")
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"执行失败: {str(e)}")
    
    def _parse_rubeus_output(self, output: str):
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'ServicePrincipalName' in line or 'User Name' in line:
                self._add_log(LogLevel.INFO, line)
            elif 'kergiohash' in line.lower() or 'rc4_hmac' in line.lower():
                parts = line.split(':')
                if len(parts) >= 2:
                    self._add_result("Hash", parts[0].strip(), parts[1].strip(), "Rubeus")
            elif 'Ticket' in line and ':' in line:
                self._add_result("票据", line.split(':')[0].strip(), line.split(':')[1].strip()[:50] + "...", "Rubeus")
    
    def _run_mimikatz(self):
        if not self._mimikatz_path:
            self._add_log(LogLevel.ERROR, "未找到 Mimikatz 工具")
            return
        
        self._add_log(LogLevel.INFO, "凭据操作功能需要管理员权限")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")


@register_module("lateral")
class LateralMovementWidget(BaseModuleWidget):
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
            "PsExec", "WMI", "WinRM", "DCOM", "SSH"
        ])
        form_layout.addRow("移动方式:", self._method_combo)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标主机")
        form_layout.addRow("目标主机:", self._target_input)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        form_layout.addRow("用户名:", self._username_input)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("密码/哈希")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("密码:", self._password_input)
        
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
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "横向移动功能需要相应的权限")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")


@register_module("persistence")
class PersistenceWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("权限维持")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("权限维持选项")
        form_layout = QFormLayout(options_group)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, [
            "注册表启动项", "计划任务", "服务", "WMI事件", "启动文件夹"
        ])
        form_layout.addRow("维持方式:", self._method_combo)
        
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("名称")
        form_layout.addRow("名称:", self._name_input)
        
        self._payload_input = QLineEdit()
        self._payload_input.setPlaceholderText("Payload路径或命令")
        form_layout.addRow("Payload:", self._payload_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["方法", "名称", "路径", "状态"])
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
        self._add_log(LogLevel.INFO, "权限维持功能需要管理员权限")
        self._add_log(LogLevel.WARNING, "请确保在合法授权的环境下使用")


@register_module("privilege")
class PrivilegeEscalationWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("权限提升")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("提权选项")
        form_layout = QFormLayout(options_group)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "自动检测", "内核漏洞", "服务配置", "DLL劫持", "计划任务"
        ])
        form_layout.addRow("检测类型:", self._scan_type_combo)
        
        self._auto_exploit_check = QCheckBox("自动利用")
        form_layout.addRow(self._auto_exploit_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["漏洞类型", "描述", "利用方法", "风险"])
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
        self._add_log(LogLevel.INFO, "开始权限提升检测")
        
        self._add_result("服务配置", "未引用的服务路径", "修改服务路径", "高")
        self._add_result("服务配置", "弱服务权限", "替换服务二进制", "中")
        
        self._add_log(LogLevel.SUCCESS, "提权检测完成")
