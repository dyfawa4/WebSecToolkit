from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox, QTabWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import subprocess
import threading
import os
from pathlib import Path


class TunnelWorker(QThread):
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)
    
    def __init__(self, cmd, tool_name="tunnel"):
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
            
            self.finished_signal.emit(True, "隧道已停止")
            
        except Exception as e:
            self.finished_signal.emit(False, str(e))
    
    def cancel(self):
        self._is_cancelled = True
        if self._process:
            self._process.terminate()


@register_module("http_proxy")
class HTTPProxyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("http_proxy", "HTTP代理")
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["内置代理", "Gost", "frp"])
        tool_layout.addRow("代理工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        server_group = QGroupBox("代理服务器")
        server_layout = QFormLayout(server_group)
        
        self._listen_addr_input = QLineEdit()
        self._listen_addr_input.setText("127.0.0.1")
        self._listen_addr_input.setPlaceholderText("监听地址")
        server_layout.addRow("监听地址:", self._listen_addr_input)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(8080)
        server_layout.addRow("监听端口:", self._listen_port_spin)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址 (可选，用于正向代理)")
        server_layout.addRow("目标地址:", self._target_input)
        
        layout.addWidget(server_group)
        
        options_group = QGroupBox("代理选项")
        options_layout = QFormLayout(options_group)
        
        self._log_traffic_check = QCheckBox("记录流量")
        self._log_traffic_check.setChecked(True)
        options_layout.addRow(self._log_traffic_check)
        
        self._intercept_check = QCheckBox("拦截请求")
        options_layout.addRow(self._intercept_check)
        
        self._upstream_input = QLineEdit()
        self._upstream_input.setPlaceholderText("上游代理地址 (如: http://127.0.0.1:7890)")
        options_layout.addRow("上游代理:", self._upstream_input)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["时间", "方法", "URL", "状态码", "大小"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        tool = self._tool_combo.currentText()
        
        if tool == "Gost":
            self._start_gost_proxy()
        elif tool == "frp":
            self._start_frp_proxy()
        else:
            self._start_builtin_proxy()
    
    def _start_gost_proxy(self):
        if not self._is_tool_available("gost"):
            self._add_log(LogLevel.ERROR, "Gost 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/go-gost/gost/releases")
            return
        
        listen_addr = self._listen_addr_input.text().strip() or "127.0.0.1"
        listen_port = self._listen_port_spin.value()
        upstream = self._upstream_input.text().strip()
        target = self._target_input.text().strip()
        
        gost_path = self._get_tool_path("gost")
        if not gost_path:
            self._add_log(LogLevel.ERROR, "Gost 工具路径无效")
            return
        
        try:
            if upstream:
                cmd = f'"{gost_path}" -L={listen_addr}:{listen_port} -F={upstream}'
            elif target:
                cmd = f'"{gost_path}" -L={listen_addr}:{listen_port} -F={target}'
            else:
                cmd = f'"{gost_path}" -L={listen_addr}:{listen_port}'
            
            self._add_log(LogLevel.INFO, f"启动 Gost 代理: {listen_addr}:{listen_port}")
            self._add_log(LogLevel.INFO, f"命令: {cmd}")
            
            self._worker = TunnelWorker(cmd, "gost")
            self._worker.output_received.connect(self._on_proxy_output)
            self._worker.finished_signal.connect(self._on_proxy_finished)
            self._worker.start()
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"启动 Gost 失败: {str(e)}")
    
    def _start_frp_proxy(self):
        if not self._is_tool_available("frpc"):
            self._add_log(LogLevel.ERROR, "frp 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/fatedier/frp/releases")
            return
        
        listen_port = self._listen_port_spin.value()
        server = self._target_input.text().strip()
        
        frpc_path = self._get_tool_path("frpc")
        if not frpc_path:
            self._add_log(LogLevel.ERROR, "frpc 工具路径无效")
            return
        
        try:
            import tempfile
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False)
            
            if server:
                parts = server.split(':')
                server_addr = parts[0]
                server_port = parts[1] if len(parts) > 1 else "7000"
                
                config_content = f'''
serverAddr = "{server_addr}"
serverPort = {server_port}

[[proxies]]
name = "socks5"
type = "tcp"
localIP = "127.0.0.1"
localPort = {listen_port}
remotePort = {listen_port}
'''
                self._add_log(LogLevel.INFO, f"连接 frp 服务器: {server}")
            else:
                config_content = f'''
bindPort = {listen_port}

[[proxies]]
name = "socks5"
type = "tcp"
localIP = "127.0.0.1"
localPort = {listen_port}
'''
                self._add_log(LogLevel.INFO, f"启动 frp 服务器: {listen_port}")
            
            config_file.write(config_content)
            config_file.close()
            
            cmd = f'"{frpc_path}" -c "{config_file.name}"'
            self._add_log(LogLevel.INFO, f"命令: {cmd}")
            
            self._worker = TunnelWorker(cmd, "frp")
            self._worker.output_received.connect(self._on_proxy_output)
            self._worker.finished_signal.connect(self._on_proxy_finished)
            self._worker.start()
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"启动 frp 失败: {str(e)}")
    
    def _start_builtin_proxy(self):
        self._add_log(LogLevel.INFO, "内置代理功能开发中...")
        self._add_log(LogLevel.INFO, "请使用 Gost 或 Chisel 工具")
    
    def _on_proxy_output(self, line: str):
        if 'error' in line.lower():
            self._add_log(LogLevel.ERROR, line)
        elif 'listening' in line.lower() or 'connected' in line.lower():
            self._add_log(LogLevel.SUCCESS, line)
        else:
            self._add_log(LogLevel.DEBUG, line)
    
    def _on_proxy_finished(self, success: bool, message: str):
        if success:
            self._add_log(LogLevel.INFO, message)
        else:
            self._add_log(LogLevel.ERROR, message)
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("tunnel")
class TunnelWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("tunnel", "隧道工具")
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
        self._setup_combo(self._tool_combo, ["frp", "Gost", "内置隧道"])
        tool_layout.addRow("隧道工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        tunnel_group = QGroupBox("隧道配置")
        tunnel_layout = QFormLayout(tunnel_group)
        
        self._mode_combo = QComboBox()
        self._setup_combo(self._mode_combo, [
            "本地转发", "远程转发", "SOCKS5代理", "反向隧道"
        ])
        self._mode_combo.currentTextChanged.connect(self._on_mode_changed)
        tunnel_layout.addRow("隧道模式:", self._mode_combo)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(1080)
        tunnel_layout.addRow("本地端口:", self._listen_port_spin)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址:端口 (本地转发用)")
        tunnel_layout.addRow("目标地址:", self._target_input)
        
        self._server_input = QLineEdit()
        self._server_input.setPlaceholderText("服务器地址:端口 (反向隧道用)")
        tunnel_layout.addRow("服务器:", self._server_input)
        
        self._remote_port_spin = QSpinBox()
        self._remote_port_spin.setRange(1, 65535)
        self._remote_port_spin.setValue(1080)
        tunnel_layout.addRow("远程端口:", self._remote_port_spin)
        
        basic_layout.addWidget(tunnel_group)
        tabs.addTab(basic_tab, "基本选项")
        
        auth_tab = QWidget()
        auth_layout = QVBoxLayout(auth_tab)
        
        auth_group = QGroupBox("认证选项")
        auth_form = QFormLayout(auth_group)
        
        self._auth_check = QCheckBox("需要认证")
        self._auth_check.toggled.connect(self._on_auth_toggled)
        auth_form.addRow(self._auth_check)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        self._username_input.setEnabled(False)
        auth_form.addRow("用户名:", self._username_input)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("密码")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setEnabled(False)
        auth_form.addRow("密码:", self._password_input)
        
        auth_layout.addWidget(auth_group)
        auth_layout.addStretch()
        tabs.addTab(auth_tab, "认证选项")
        
        advanced_tab = QWidget()
        advanced_layout = QVBoxLayout(advanced_tab)
        
        chisel_group = QGroupBox("frp 高级选项")
        chisel_form = QFormLayout(chisel_group)
        
        self._tls_check = QCheckBox("启用TLS加密")
        chisel_form.addRow(self._tls_check)
        
        self._tlsVerify_check = QCheckBox("跳过TLS验证")
        chisel_form.addRow(self._tlsVerify_check)
        
        self._fingerprint_input = QLineEdit()
        self._fingerprint_input.setPlaceholderText("TLS指纹")
        chisel_form.addRow("TLS指纹:", self._fingerprint_input)
        
        self._keepalive_spin = QSpinBox()
        self._keepalive_spin.setRange(0, 300)
        self._keepalive_spin.setValue(30)
        self._keepalive_spin.setSuffix(" 秒")
        chisel_form.addRow("心跳间隔:", self._keepalive_spin)
        
        self._maxRetries_spin = QSpinBox()
        self._maxRetries_spin.setRange(0, 100)
        self._maxRetries_spin.setValue(3)
        chisel_form.addRow("最大重试:", self._maxRetries_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 300)
        self._timeout_spin.setValue(30)
        self._timeout_spin.setSuffix(" 秒")
        chisel_form.addRow("超时时间:", self._timeout_spin)
        
        self._proxy_input = QLineEdit()
        self._proxy_input.setPlaceholderText("上游代理地址")
        chisel_form.addRow("上游代理:", self._proxy_input)
        
        self._socks5_check = QCheckBox("使用SOCKS5代理")
        chisel_form.addRow(self._socks5_check)
        
        self._reverse_check = QCheckBox("允许反向隧道")
        chisel_form.addRow(self._reverse_check)
        
        advanced_layout.addWidget(chisel_group)
        
        gost_group = QGroupBox("Gost 高级选项")
        gost_form = QFormLayout(gost_group)
        
        self._gost_tls_check = QCheckBox("启用TLS")
        gost_form.addRow(self._gost_tls_check)
        
        self._gost_mtls_check = QCheckBox("双向TLS认证")
        gost_form.addRow(self._gost_mtls_check)
        
        self._gost_cert_input = QLineEdit()
        self._gost_cert_input.setPlaceholderText("证书文件路径")
        gost_form.addRow("证书文件:", self._gost_cert_input)
        
        self._gost_key_input = QLineEdit()
        self._gost_key_input.setPlaceholderText("私钥文件路径")
        gost_form.addRow("私钥文件:", self._gost_key_input)
        
        self._gost_ca_input = QLineEdit()
        self._gost_ca_input.setPlaceholderText("CA证书路径")
        gost_form.addRow("CA证书:", self._gost_ca_input)
        
        advanced_layout.addWidget(gost_group)
        advanced_layout.addStretch()
        tabs.addTab(advanced_tab, "高级选项")
        
        layout.addWidget(tabs)
        return widget
    
    def _on_mode_changed(self, mode: str):
        if mode == "本地转发":
            self._target_input.setEnabled(True)
            self._server_input.setEnabled(False)
            self._remote_port_spin.setEnabled(False)
        elif mode == "远程转发":
            self._target_input.setEnabled(True)
            self._server_input.setEnabled(True)
            self._remote_port_spin.setEnabled(True)
        elif mode == "反向隧道":
            self._target_input.setEnabled(False)
            self._server_input.setEnabled(True)
            self._remote_port_spin.setEnabled(True)
        else:
            self._target_input.setEnabled(False)
            self._server_input.setEnabled(False)
            self._remote_port_spin.setEnabled(False)
    
    def _on_auth_toggled(self, checked: bool):
        self._username_input.setEnabled(checked)
        self._password_input.setEnabled(checked)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["时间", "连接", "流量", "状态"])
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
        tool = self._tool_combo.currentText()
        
        if tool == "frp":
            self._start_frp_tunnel()
        elif tool == "Gost":
            self._start_gost_tunnel()
        else:
            self._start_builtin_tunnel()
    
    def _start_frp_tunnel(self):
        if not self._is_tool_available("frpc"):
            self._add_log(LogLevel.ERROR, "frp 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/fatedier/frp/releases")
            return
        
        mode = self._mode_combo.currentText()
        listen_port = self._listen_port_spin.value()
        target = self._target_input.text().strip()
        server = self._server_input.text().strip()
        remote_port = self._remote_port_spin.value()
        
        frpc_path = self._get_tool_path("frpc")
        if not frpc_path:
            self._add_log(LogLevel.ERROR, "frpc 工具路径无效")
            return
        
        try:
            import tempfile
            config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False)
            
            if mode == "SOCKS5代理":
                if server:
                    parts = server.split(':')
                    server_addr = parts[0]
                    server_port = parts[1] if len(parts) > 1 else "7000"
                    config_content = f'''
serverAddr = "{server_addr}"
serverPort = {server_port}

[[proxies]]
name = "socks5"
type = "tcp"
localIP = "127.0.0.1"
localPort = {listen_port}
remotePort = {remote_port}
'''
                else:
                    config_content = f'''
bindPort = {listen_port}
'''
            elif mode == "本地转发":
                if not target:
                    self._add_log(LogLevel.ERROR, "请输入目标地址")
                    return
                target_parts = target.split(':')
                target_host = target_parts[0]
                target_port = target_parts[1] if len(target_parts) > 1 else "80"
                
                config_content = f'''
serverAddr = "127.0.0.1"
serverPort = 7000

[[proxies]]
name = "local_forward"
type = "tcp"
localIP = "{target_host}"
localPort = {target_port}
remotePort = {listen_port}
'''
            elif mode == "远程转发":
                if not server or not target:
                    self._add_log(LogLevel.ERROR, "请输入服务器和目标地址")
                    return
                parts = server.split(':')
                server_addr = parts[0]
                server_port = parts[1] if len(parts) > 1 else "7000"
                target_parts = target.split(':')
                target_host = target_parts[0]
                target_port = target_parts[1] if len(target_parts) > 1 else "80"
                
                config_content = f'''
serverAddr = "{server_addr}"
serverPort = {server_port}

[[proxies]]
name = "remote_forward"
type = "tcp"
localIP = "{target_host}"
localPort = {target_port}
remotePort = {remote_port}
'''
            else:
                if not server:
                    self._add_log(LogLevel.ERROR, "请输入服务器地址")
                    return
                parts = server.split(':')
                server_addr = parts[0]
                server_port = parts[1] if len(parts) > 1 else "7000"
                
                config_content = f'''
serverAddr = "{server_addr}"
serverPort = {server_port}

[[proxies]]
name = "reverse_tunnel"
type = "tcp"
remotePort = {remote_port}
'''
            
            config_file.write(config_content)
            config_file.close()
            
            cmd = f'"{frpc_path}" -c "{config_file.name}"'
            self._add_log(LogLevel.INFO, f"启动 frp 隧道: {mode}")
            self._add_log(LogLevel.INFO, f"命令: {cmd}")
            
            self._worker = TunnelWorker(cmd, "frp")
            self._worker.output_received.connect(self._on_tunnel_output)
            self._worker.finished_signal.connect(self._on_tunnel_finished)
            self._worker.start()
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"启动 frp 失败: {str(e)}")
    
    def _start_gost_tunnel(self):
        if not self._is_tool_available("gost"):
            self._add_log(LogLevel.ERROR, "Gost 工具不可用")
            return
        
        mode = self._mode_combo.currentText()
        listen_port = self._listen_port_spin.value()
        target = self._target_input.text().strip()
        server = self._server_input.text().strip()
        
        gost_path = self._get_tool_path("gost")
        
        auth_part = ""
        if self._auth_check.isChecked():
            username = self._username_input.text().strip()
            password = self._password_input.text()
            if username and password:
                auth_part = f"{username}:{password}@"
        
        tls_options = []
        if self._gost_tls_check.isChecked():
            tls_options.append("tls")
        
        if self._gost_mtls_check.isChecked():
            tls_options.append("mtls")
        
        cert = self._gost_cert_input.text().strip()
        if cert:
            tls_options.append(f"certFile={cert}")
        
        key = self._gost_key_input.text().strip()
        if key:
            tls_options.append(f"keyFile={key}")
        
        ca = self._gost_ca_input.text().strip()
        if ca:
            tls_options.append(f"caFile={ca}")
        
        tls_suffix = ""
        if tls_options:
            tls_suffix = "?" + "&".join(tls_options)
        
        if mode == "SOCKS5代理":
            if auth_part:
                cmd = f'"{gost_path}" -L=socks5://{auth_part}:{listen_port}{tls_suffix}'
            else:
                cmd = f'"{gost_path}" -L=socks5://:{listen_port}{tls_suffix}'
            self._add_log(LogLevel.INFO, f"启动 SOCKS5 代理: :{listen_port}")
            
        elif mode == "反向隧道":
            if not server:
                self._add_log(LogLevel.ERROR, "请输入服务器地址")
                return
            if auth_part:
                cmd = f'"{gost_path}" -L=rtcp://:{listen_port}/{target} -F={auth_part}{server}{tls_suffix}'
            else:
                cmd = f'"{gost_path}" -L=rtcp://:{listen_port}/{target} -F={server}{tls_suffix}'
            self._add_log(LogLevel.INFO, f"建立反向隧道: {server}")
            
        elif mode == "本地转发":
            if not target:
                self._add_log(LogLevel.ERROR, "请输入目标地址")
                return
            if auth_part:
                cmd = f'"{gost_path}" -L=tcp://{auth_part}:{listen_port}/{target}{tls_suffix}'
            else:
                cmd = f'"{gost_path}" -L=tcp://:{listen_port}/{target}{tls_suffix}'
            self._add_log(LogLevel.INFO, f"建立本地转发: :{listen_port} -> {target}")
            
        else:
            if auth_part:
                cmd = f'"{gost_path}" -L={auth_part}:{listen_port}{tls_suffix}'
            else:
                cmd = f'"{gost_path}" -L=:{listen_port}{tls_suffix}'
            self._add_log(LogLevel.INFO, f"启动 Gost 服务: :{listen_port}")
        
        self._add_log(LogLevel.INFO, f"命令: {cmd}")
        
        self._worker = TunnelWorker(cmd, "gost")
        self._worker.output_received.connect(self._on_tunnel_output)
        self._worker.finished_signal.connect(self._on_tunnel_finished)
        self._worker.start()
    
    def _start_builtin_tunnel(self):
        self._add_log(LogLevel.INFO, "内置隧道功能开发中...")
        self._add_log(LogLevel.INFO, "请使用 Chisel 或 Gost 工具")
    
    def _on_tunnel_output(self, line: str):
        if 'error' in line.lower():
            self._add_log(LogLevel.ERROR, line)
        elif 'listening' in line.lower() or 'connected' in line.lower():
            self._add_log(LogLevel.SUCCESS, line)
        else:
            self._add_log(LogLevel.DEBUG, line)
    
    def _on_tunnel_finished(self, success: bool, message: str):
        if success:
            self._add_log(LogLevel.INFO, message)
        else:
            self._add_log(LogLevel.ERROR, message)
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()


@register_module("reverse_proxy")
class ReverseProxyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("reverse_proxy", "反向代理")
        self._worker = None
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tool_group = QGroupBox("工具选择")
        tool_layout = QFormLayout(tool_group)
        
        self._tool_combo = QComboBox()
        self._setup_combo(self._tool_combo, ["Gost", "内置代理"])
        tool_layout.addRow("代理工具:", self._tool_combo)
        
        layout.addWidget(tool_group)
        
        config_group = QGroupBox("反向代理配置")
        config_layout = QFormLayout(config_group)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(80)
        config_layout.addRow("监听端口:", self._listen_port_spin)
        
        self._backend_input = QLineEdit()
        self._backend_input.setPlaceholderText("后端服务器地址 (如: http://192.168.1.100:8080)")
        config_layout.addRow("后端服务器:", self._backend_input)
        
        layout.addWidget(config_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["时间", "客户端", "请求", "状态"])
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
        
        if tool == "Gost":
            self._start_gost_reverse_proxy()
        else:
            self._start_builtin_reverse_proxy()
    
    def _start_gost_reverse_proxy(self):
        if not self._is_tool_available("gost"):
            self._add_log(LogLevel.ERROR, "Gost 工具不可用")
            return
        
        listen_port = self._listen_port_spin.value()
        backend = self._backend_input.text().strip()
        
        if not backend:
            self._add_log(LogLevel.ERROR, "请输入后端服务器地址")
            return
        
        gost_path = self._get_tool_path("gost")
        
        cmd = f'"{gost_path}" -L=:{listen_port} -F={backend}'
        
        self._add_log(LogLevel.INFO, f"启动反向代理: :{listen_port} -> {backend}")
        self._add_log(LogLevel.INFO, f"命令: {cmd}")
        
        self._worker = TunnelWorker(cmd, "gost")
        self._worker.output_received.connect(self._on_output)
        self._worker.finished_signal.connect(self._on_finished)
        self._worker.start()
    
    def _start_builtin_reverse_proxy(self):
        self._add_log(LogLevel.INFO, "内置反向代理功能开发中...")
    
    def _on_output(self, line: str):
        if 'error' in line.lower():
            self._add_log(LogLevel.ERROR, line)
        elif 'listening' in line.lower():
            self._add_log(LogLevel.SUCCESS, line)
        else:
            self._add_log(LogLevel.DEBUG, line)
    
    def _on_finished(self, success: bool, message: str):
        if success:
            self._add_log(LogLevel.INFO, message)
        else:
            self._add_log(LogLevel.ERROR, message)
    
    def stop_scan(self):
        if self._worker:
            self._worker.cancel()
        super().stop_scan()
