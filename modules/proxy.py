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


@register_module("http_proxy")
class HTTPProxyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("HTTP代理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        server_group = QGroupBox("代理服务器")
        server_layout = QFormLayout(server_group)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(8080)
        server_layout.addRow("监听端口:", self._listen_port_spin)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址 (可选)")
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
        self._upstream_input.setPlaceholderText("上游代理地址 (可选)")
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
        self._add_log(LogLevel.INFO, "HTTP代理功能需要启动代理服务器")
        self._add_log(LogLevel.INFO, "此功能需要配合Burp Suite等工具使用")


@register_module("tunnel")
class TunnelWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("隧道工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tunnel_group = QGroupBox("隧道配置")
        tunnel_layout = QFormLayout(tunnel_group)
        
        self._mode_combo = QComboBox()
        self._setup_combo(self._mode_combo, [
            "本地转发", "远程转发", "动态转发 (SOCKS)", "反向隧道"
        ])
        tunnel_layout.addRow("隧道模式:", self._mode_combo)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(1080)
        tunnel_layout.addRow("本地端口:", self._listen_port_spin)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址:端口")
        tunnel_layout.addRow("目标地址:", self._target_input)
        
        self._server_input = QLineEdit()
        self._server_input.setPlaceholderText("服务器地址 (反向隧道)")
        tunnel_layout.addRow("服务器:", self._server_input)
        
        layout.addWidget(tunnel_group)
        
        options_group = QGroupBox("高级选项")
        options_layout = QFormLayout(options_group)
        
        self._socks_version_combo = QComboBox()
        self._setup_combo(self._socks_version_combo, ["SOCKS5", "SOCKS4"])
        options_layout.addRow("SOCKS版本:", self._socks_version_combo)
        
        self._auth_check = QCheckBox("需要认证")
        options_layout.addRow(self._auth_check)
        
        self._username_input = QLineEdit()
        self._username_input.setPlaceholderText("用户名")
        options_layout.addRow("用户名:", self._username_input)
        
        self._password_input = QLineEdit()
        self._password_input.setPlaceholderText("密码")
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        options_layout.addRow("密码:", self._password_input)
        
        layout.addWidget(options_group)
        return widget
    
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
        mode = self._mode_combo.currentText()
        listen_port = self._listen_port_spin.value()
        target = self._target_input.text().strip()
        
        self._add_log(LogLevel.INFO, f"隧道模式: {mode}")
        self._add_log(LogLevel.INFO, f"监听端口: {listen_port}")
        
        if self._is_tool_available("chisel"):
            self._start_chisel_tunnel()
        elif self._is_tool_available("gost"):
            self._start_gost_tunnel()
        else:
            self._add_log(LogLevel.WARNING, "请先下载Chisel或GOST工具")
    
    def _start_chisel_tunnel(self):
        self._add_log(LogLevel.INFO, "使用Chisel建立隧道")
    
    def _start_gost_tunnel(self):
        self._add_log(LogLevel.INFO, "使用GOST建立隧道")


@register_module("reverse_proxy")
class ReverseProxyWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("反向代理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        config_group = QGroupBox("反向代理配置")
        config_layout = QFormLayout(config_group)
        
        self._listen_port_spin = QSpinBox()
        self._listen_port_spin.setRange(1, 65535)
        self._listen_port_spin.setValue(80)
        config_layout.addRow("监听端口:", self._listen_port_spin)
        
        self._backend_input = QLineEdit()
        self._backend_input.setPlaceholderText("后端服务器地址")
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
        self._add_log(LogLevel.INFO, "反向代理功能需要启动代理服务器")
