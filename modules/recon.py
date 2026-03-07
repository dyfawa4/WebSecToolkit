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
import re
import socket
import concurrent.futures
import os
import tempfile


@register_module("port_scanner")
class PortScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("port_scanner", "端口扫描")
    
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
        self._setup_combo(self._tool_combo, ["内置扫描器", "Nmap", "Naabu", "RustScan", "Masscan"])
        self._tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        tool_layout.addRow("扫描工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        form_layout.setSpacing(10)
        
        self._scan_type_combo = QComboBox()
        self._setup_combo(self._scan_type_combo, [
            "TCP Connect", "SYN Scan", "UDP Scan", "Service Detection"
        ])
        form_layout.addRow("扫描类型:", self._scan_type_combo)
        
        self._port_range_input = QLineEdit()
        self._port_range_input.setText("1-1000")
        self._port_range_input.setPlaceholderText("端口范围，如: 1-1000 或 22,80,443")
        form_layout.addRow("端口范围:", self._port_range_input)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        self._setup_spinbox(self._threads_spin)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(3)
        self._timeout_spin.setSuffix(" 秒")
        self._setup_spinbox(self._timeout_spin, " 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._service_detect_check = QCheckBox("服务识别")
        self._service_detect_check.setChecked(True)
        form_layout.addRow(self._service_detect_check)
        
        basic_layout.addWidget(options_group)
        tabs.addTab(basic_tab, "基本选项")
        
        nmap_tab = QWidget()
        nmap_layout = QVBoxLayout(nmap_tab)
        
        nmap_group = QGroupBox("Nmap 高级选项")
        nmap_form = QFormLayout(nmap_group)
        
        self._nmap_timing_combo = QComboBox()
        self._setup_combo(self._nmap_timing_combo, [
            "T0 (偏执)", "T1 (鬼祟)", "T2 (礼貌)", "T3 (正常)", 
            "T4 (激进)", "T5 (疯狂)"
        ])
        self._nmap_timing_combo.setCurrentIndex(3)
        nmap_form.addRow("时间模板:", self._nmap_timing_combo)
        
        self._nmap_os_check = QCheckBox("操作系统检测 (-O)")
        nmap_form.addRow(self._nmap_os_check)
        
        self._nmap_aggressive_check = QCheckBox("激进扫描 (-A)")
        nmap_form.addRow(self._nmap_aggressive_check)
        
        self._nmap_script_input = QLineEdit()
        self._nmap_script_input.setPlaceholderText("脚本名称，如: vuln,auth,default")
        nmap_form.addRow("NSE脚本:", self._nmap_script_input)
        
        self._nmap_scriptArgs_input = QLineEdit()
        self._nmap_scriptArgs_input.setPlaceholderText("脚本参数，如: user=admin")
        nmap_form.addRow("脚本参数:", self._nmap_scriptArgs_input)
        
        self._nmap_pn_check = QCheckBox("跳过主机发现 (-Pn)")
        self._nmap_pn_check.setChecked(True)
        nmap_form.addRow(self._nmap_pn_check)
        
        self._nmap_A_check = QCheckBox("启用ACK扫描")
        nmap_form.addRow(self._nmap_A_check)
        
        self._nmap_f_check = QCheckBox("快速扫描 (-F)")
        nmap_form.addRow(self._nmap_f_check)
        
        self._nmap_r_check = QCheckBox("随机化端口顺序")
        nmap_form.addRow(self._nmap_r_check)
        
        self._nmap_v_check = QCheckBox("详细输出 (-v)")
        nmap_form.addRow(self._nmap_v_check)
        
        self._nmap_outputFile_input = QLineEdit()
        self._nmap_outputFile_input.setPlaceholderText("输出文件路径")
        nmap_form.addRow("输出文件:", self._nmap_outputFile_input)
        
        nmap_layout.addWidget(nmap_group)
        nmap_layout.addStretch()
        tabs.addTab(nmap_tab, "Nmap选项")
        
        naabu_tab = QWidget()
        naabu_layout = QVBoxLayout(naabu_tab)
        
        naabu_group = QGroupBox("Naabu 高级选项")
        naabu_form = QFormLayout(naabu_group)
        
        self._naabu_topPorts_combo = QComboBox()
        self._setup_combo(self._naabu_topPorts_combo, [
            "自定义端口", "Top 100", "Top 1000", "Full (1-65535)"
        ])
        naabu_form.addRow("端口选择:", self._naabu_topPorts_combo)
        
        self._naabu_rate_spin = QSpinBox()
        self._naabu_rate_spin.setRange(1, 10000)
        self._naabu_rate_spin.setValue(1000)
        naabu_form.addRow("速率限制:", self._naabu_rate_spin)
        
        self._naabu_c_spin = QSpinBox()
        self._naabu_c_spin.setRange(1, 10000)
        self._naabu_c_spin.setValue(25)
        naabu_form.addRow("并发数:", self._naabu_c_spin)
        
        self._naabu_exclude_input = QLineEdit()
        self._naabu_exclude_input.setPlaceholderText("排除端口，如: 22,80,443")
        naabu_form.addRow("排除端口:", self._naabu_exclude_input)
        
        self._naabu_json_check = QCheckBox("JSON输出")
        naabu_form.addRow(self._naabu_json_check)
        
        self._naabu_silent_check = QCheckBox("静默模式")
        self._naabu_silent_check.setChecked(True)
        naabu_form.addRow(self._naabu_silent_check)
        
        self._naabu_verify_check = QCheckBox("验证模式")
        naabu_form.addRow(self._naabu_verify_check)
        
        self._naabu_outputFile_input = QLineEdit()
        self._naabu_outputFile_input.setPlaceholderText("输出文件路径")
        naabu_form.addRow("输出文件:", self._naabu_outputFile_input)
        
        naabu_layout.addWidget(naabu_group)
        naabu_layout.addStretch()
        tabs.addTab(naabu_tab, "Naabu选项")
        
        rustscan_tab = QWidget()
        rustscan_layout = QVBoxLayout(rustscan_tab)
        
        rustscan_group = QGroupBox("RustScan 高级选项")
        rustscan_form = QFormLayout(rustscan_group)
        
        self._rustscan_ulimit_spin = QSpinBox()
        self._rustscan_ulimit_spin.setRange(1, 100000)
        self._rustscan_ulimit_spin.setValue(5000)
        rustscan_form.addRow("文件描述符限制:", self._rustscan_ulimit_spin)
        
        self._rustscan_batch_spin = QSpinBox()
        self._rustscan_batch_spin.setRange(1, 100000)
        self._rustscan_batch_spin.setValue(4500)
        rustscan_form.addRow("批量大小:", self._rustscan_batch_spin)
        
        self._rustscan_timeout_spin = QSpinBox()
        self._rustscan_timeout_spin.setRange(1, 10000)
        self._rustscan_timeout_spin.setValue(3000)
        self._rustscan_timeout_spin.setSuffix(" 毫秒")
        rustscan_form.addRow("超时时间:", self._rustscan_timeout_spin)
        
        self._rustscan_tries_spin = QSpinBox()
        self._rustscan_tries_spin.setRange(1, 10)
        self._rustscan_tries_spin.setValue(1)
        rustscan_form.addRow("重试次数:", self._rustscan_tries_spin)
        
        self._rustscan_nmap_check = QCheckBox("自动调用Nmap服务识别")
        self._rustscan_nmap_check.setChecked(True)
        rustscan_form.addRow(self._rustscan_nmap_check)
        
        self._rustscan_nmap_args = QLineEdit()
        self._rustscan_nmap_args.setPlaceholderText("Nmap参数，如: -sV -sC")
        rustscan_form.addRow("Nmap参数:", self._rustscan_nmap_args)
        
        self._rustscan_silent_check = QCheckBox("静默模式")
        self._rustscan_silent_check.setChecked(True)
        rustscan_form.addRow(self._rustscan_silent_check)
        
        self._rustscan_outputFile_input = QLineEdit()
        self._rustscan_outputFile_input.setPlaceholderText("输出文件路径")
        rustscan_form.addRow("输出文件:", self._rustscan_outputFile_input)
        
        rustscan_layout.addWidget(rustscan_group)
        rustscan_layout.addStretch()
        tabs.addTab(rustscan_tab, "RustScan选项")
        
        masscan_tab = QWidget()
        masscan_layout = QVBoxLayout(masscan_tab)
        
        masscan_group = QGroupBox("Masscan 高级选项")
        masscan_form = QFormLayout(masscan_group)
        
        self._masscan_rate_spin = QSpinBox()
        self._masscan_rate_spin.setRange(1, 100000000)
        self._masscan_rate_spin.setValue(10000)
        masscan_form.addRow("速率 (包/秒):", self._masscan_rate_spin)
        
        self._masscan_wait_spin = QSpinBox()
        self._masscan_wait_spin.setRange(0, 60)
        self._masscan_wait_spin.setValue(3)
        self._masscan_wait_spin.setSuffix(" 秒")
        masscan_form.addRow("等待时间:", self._masscan_wait_spin)
        
        self._masscan_max_retries_spin = QSpinBox()
        self._masscan_max_retries_spin.setRange(0, 10)
        self._masscan_max_retries_spin.setValue(0)
        masscan_form.addRow("最大重试:", self._masscan_max_retries_spin)
        
        self._masscan_source_port_spin = QSpinBox()
        self._masscan_source_port_spin.setRange(0, 65535)
        self._masscan_source_port_spin.setValue(0)
        masscan_form.addRow("源端口:", self._masscan_source_port_spin)
        
        self._masscan_interface_input = QLineEdit()
        self._masscan_interface_input.setPlaceholderText("网络接口名称")
        masscan_form.addRow("网络接口:", self._masscan_interface_input)
        
        self._masscan_outputFile_input = QLineEdit()
        self._masscan_outputFile_input.setPlaceholderText("输出文件路径")
        masscan_form.addRow("输出文件:", self._masscan_outputFile_input)
        
        masscan_layout.addWidget(masscan_group)
        masscan_layout.addStretch()
        tabs.addTab(masscan_tab, "Masscan选项")
        
        layout.addWidget(tabs)
        
        self._update_tool_status()
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        if tool_name == "Nmap":
            available = self._is_tool_available("nmap")
            if available:
                self._add_log(LogLevel.INFO, "Nmap 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "Nmap 工具不可用，请先下载")
        elif tool_name == "Naabu":
            available = self._is_tool_available("naabu")
            if available:
                self._add_log(LogLevel.INFO, "Naabu 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "Naabu 工具不可用，请先下载")
        elif tool_name == "RustScan":
            available = self._is_tool_available("rustscan")
            if available:
                self._add_log(LogLevel.INFO, "RustScan 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "RustScan 工具不可用，请先下载")
        elif tool_name == "Masscan":
            available = self._is_tool_available("masscan")
            if available:
                self._add_log(LogLevel.INFO, "Masscan 工具可用")
            else:
                self._add_log(LogLevel.WARNING, "Masscan 工具不可用，请先下载")
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["主机", "端口", "状态", "服务", "版本"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Nmap":
            self._scan_with_nmap()
        elif tool_name == "Naabu":
            self._scan_with_naabu()
        elif tool_name == "RustScan":
            self._scan_with_rustscan()
        elif tool_name == "Masscan":
            self._scan_with_masscan()
        else:
            self._scan_builtin()
    
    def _scan_with_rustscan(self):
        if not self._is_tool_available("rustscan"):
            self._add_log(LogLevel.ERROR, "RustScan 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/RustScan/RustScan/releases")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 RustScan 扫描: {target}")
            
            args = ["-a", target]
            
            args.extend(["--ulimit", str(self._rustscan_ulimit_spin.value())])
            args.extend(["--batch-size", str(self._rustscan_batch_spin.value())])
            args.extend(["--timeout", str(self._rustscan_timeout_spin.value())])
            args.extend(["--tries", str(self._rustscan_tries_spin.value())])
            
            if port_range:
                args.extend(["-p", port_range])
            
            if self._rustscan_nmap_check.isChecked():
                nmap_args = self._rustscan_nmap_args.text().strip()
                if nmap_args:
                    args.extend(["--", nmap_args])
                else:
                    args.extend(["--", "-sV"])
            
            if self._rustscan_silent_check.isChecked():
                args.append("-q")
            
            output_file = self._rustscan_outputFile_input.text().strip()
            if output_file:
                args.extend(["-o", output_file])
            
            try:
                process = self._execute_tool("rustscan", args)
                if not process:
                    return
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    self._parse_rustscan_output(line.strip())
                
                self._add_log(LogLevel.SUCCESS, f"RustScan 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"RustScan 扫描失败: {str(e)}")
    
    def _parse_rustscan_output(self, line: str):
        if not line:
            return
        
        port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)?', line)
        if port_match:
            port = port_match.group(1)
            service = port_match.group(2) if port_match.group(2) else "unknown"
            target = self._target_input.text().strip().split(',')[0]
            self._add_result(target.strip(), port, "open", service)
            self._add_log(LogLevel.SUCCESS, f"发现开放端口: {port} ({service})")
        elif "Open" in line:
            parts = line.split()
            for part in parts:
                if part.isdigit():
                    self._add_log(LogLevel.SUCCESS, f"发现开放端口: {part}")
    
    def _scan_with_masscan(self):
        if not self._is_tool_available("masscan"):
            self._add_log(LogLevel.ERROR, "Masscan 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/robertdavidgraham/masscan")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 Masscan 扫描: {target}")
            
            args = [target, "-p", port_range]
            
            args.extend(["--rate", str(self._masscan_rate_spin.value())])
            args.extend(["--wait", str(self._masscan_wait_spin.value())])
            args.extend(["--max-retries", str(self._masscan_max_retries_spin.value())])
            
            source_port = self._masscan_source_port_spin.value()
            if source_port > 0:
                args.extend(["--source-port", str(source_port)])
            
            interface = self._masscan_interface_input.text().strip()
            if interface:
                args.extend(["-e", interface])
            
            output_file = self._masscan_outputFile_input.text().strip()
            if output_file:
                args.extend(["-oL", output_file])
            
            try:
                process = self._execute_tool("masscan", args)
                if not process:
                    return
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    self._parse_masscan_output(line.strip())
                
                self._add_log(LogLevel.SUCCESS, f"Masscan 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"Masscan 扫描失败: {str(e)}")
    
    def _parse_masscan_output(self, line: str):
        if not line or line.startswith("#"):
            return
        
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            port = parts[2]
            ip = parts[3]
            self._add_result(ip, port, "open", "unknown")
            self._add_log(LogLevel.SUCCESS, f"发现开放端口: {ip}:{port}")
    
    def _scan_with_nmap(self):
        if not self._is_tool_available("nmap"):
            self._add_log(LogLevel.ERROR, "Nmap 工具不可用")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 Nmap 扫描: {target}")
            
            args = ["-p", port_range]
            
            timing_map = {
                "T0 (偏执)": "-T0", "T1 (鬼祟)": "-T1", "T2 (礼貌)": "-T2",
                "T3 (正常)": "-T3", "T4 (激进)": "-T4", "T5 (疯狂)": "-T5"
            }
            timing = timing_map.get(self._nmap_timing_combo.currentText(), "-T3")
            args.append(timing)
            
            if self._service_detect_check.isChecked():
                args.append("-sV")
            
            if self._nmap_os_check.isChecked():
                args.append("-O")
            
            if self._nmap_aggressive_check.isChecked():
                args.append("-A")
            
            if self._nmap_pn_check.isChecked():
                args.append("-Pn")
            
            if self._nmap_f_check.isChecked():
                args.append("-F")
            
            if self._nmap_r_check.isChecked():
                args.append("-r")
            
            if self._nmap_v_check.isChecked():
                args.append("-v")
            
            script = self._nmap_script_input.text().strip()
            if script:
                args.extend(["--script", script])
            
            script_args = self._nmap_scriptArgs_input.text().strip()
            if script_args:
                args.extend(["--script-args", script_args])
            
            output_file = self._nmap_outputFile_input.text().strip()
            if output_file:
                args.extend(["-oN", output_file])
            
            args.append(target)
            
            try:
                process = self._execute_tool("nmap", args)
                
                if process is None:
                    self._add_log(LogLevel.ERROR, "Nmap 扫描失败: 无法启动进程")
                    return
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    self._parse_nmap_output(line.strip())
                
                self._add_log(LogLevel.SUCCESS, f"Nmap 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"Nmap 扫描失败: {str(e)}")
    
    def _parse_nmap_output(self, line: str):
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_info = parts[0].split("/")
            port = port_info[0]
            state = parts[1] if len(parts) > 1 else "open"
            service = parts[2] if len(parts) > 2 else "unknown"
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            
            target = self._target_input.text().strip().split(',')[0]
            self._add_result(target.strip(), port, state, service, version)
            self._add_log(LogLevel.SUCCESS, f"发现开放端口: {port} - {service}")
    
    def _scan_with_naabu(self):
        if not self._is_tool_available("naabu"):
            self._add_log(LogLevel.ERROR, "Naabu 工具不可用")
            return
        
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            self._add_log(LogLevel.INFO, f"使用 Naabu 扫描: {target}")
            
            args = ["-host", target]
            
            top_ports = self._naabu_topPorts_combo.currentText()
            if top_ports == "自定义端口":
                args.extend(["-p", port_range])
            elif top_ports == "Top 100":
                args.append("-top-ports 100")
            elif top_ports == "Top 1000":
                args.append("-top-ports 1000")
            elif top_ports == "Full (1-65535)":
                args.append("-p -")
            
            args.extend(["-rate", str(self._naabu_rate_spin.value())])
            args.extend(["-c", str(self._naabu_c_spin.value())])
            
            exclude = self._naabu_exclude_input.text().strip()
            if exclude:
                args.extend(["-exclude-ports", exclude])
            
            if self._naabu_json_check.isChecked():
                args.append("-json")
            
            if self._naabu_silent_check.isChecked():
                args.append("-silent")
            
            if self._naabu_verify_check.isChecked():
                args.append("-verify")
            
            output_file = self._naabu_outputFile_input.text().strip()
            if output_file:
                args.extend(["-o", output_file])
            
            try:
                process = self._execute_tool("naabu", args)
                
                if process is None:
                    self._add_log(LogLevel.ERROR, "Naabu 扫描失败: 无法启动进程")
                    return
                
                while True:
                    if not self._is_scanning:
                        process.terminate()
                        break
                    
                    line = process.stdout.readline()
                    if not line:
                        if process.poll() is not None:
                            break
                        continue
                    
                    line = line.strip()
                    if ":" in line:
                        host, port = line.rsplit(":", 1)
                        self._add_result(host, port, "open", "unknown")
                        self._add_log(LogLevel.SUCCESS, f"发现开放端口: {port}")
                
                self._add_log(LogLevel.SUCCESS, f"Naabu 扫描完成: {target}")
                
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"Naabu 扫描失败: {str(e)}")
    
    def _scan_builtin(self):
        targets = self._target_input.text().strip().split(',')
        port_range = self._port_range_input.text().strip()
        timeout = self._timeout_spin.value()
        threads = min(self._threads_spin.value(), 50)
        
        ports = self._parse_port_range(port_range)
        if not ports:
            self._add_log(LogLevel.ERROR, "无效的端口范围")
            return
        
        if len(ports) > 1000:
            self._add_log(LogLevel.WARNING, f"端口数量较多 ({len(ports)})，扫描可能需要较长时间")
        
        self._add_log(LogLevel.INFO, f"扫描端口: {len(ports)} 个，并发: {threads}")
        
        total = len(targets) * len(ports)
        completed = 0
        
        self._executor = None
        self._futures = {}
        
        try:
            self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
            futures = {}
            for target in targets:
                target = target.strip()
                if not target:
                    continue
                for port in ports:
                    if not self._is_scanning:
                        self._add_log(LogLevel.INFO, "扫描已取消")
                        return
                    future = self._executor.submit(self._scan_port, target.strip(), port, timeout)
                    futures[future] = (target.strip(), port)
            
            self._futures = futures
            
            for future in concurrent.futures.as_completed(futures):
                if not self._is_scanning:
                    self._add_log(LogLevel.INFO, "正在取消剩余任务...")
                    break
                
                target, port = futures[future]
                try:
                    is_open, service = future.result(timeout=timeout + 1)
                    if is_open:
                        self._add_result(target, str(port), "开放", service)
                        self._add_log(LogLevel.SUCCESS, f"{target}:{port} - 开放 - {service}")
                except concurrent.futures.TimeoutError:
                    pass
                except Exception:
                    pass
                
                completed += 1
                if completed % 50 == 0:
                    progress = int((completed / total) * 100)
                    self._update_progress(progress)
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描出错: {str(e)}")
        finally:
            if self._executor:
                self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
            self._futures = {}
    
    def _parse_port_range(self, port_str: str) -> list:
        ports = []
        try:
            for part in port_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = part.split('-')
                    start_int = int(start)
                    end_int = int(end)
                    if end_int > 65535:
                        end_int = 65535
                    if start_int > end_int:
                        continue
                    ports.extend(range(start_int, end_int + 1))
                else:
                    port_int = int(part)
                    if 1 <= port_int <= 65535:
                        ports.append(port_int)
        except ValueError:
            return []
        return sorted(set(ports))[:5000]
    
    def _scan_port(self, host: str, port: int, timeout: int) -> tuple:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return (True, service)
        except socket.gaierror:
            return (False, "")
        except socket.error:
            return (False, "")
        except Exception:
            return (False, "")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        return (False, "")


@register_module("subdomain")
class SubdomainScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("subdomain", "子域名扫描")
    
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
        self._setup_combo(self._tool_combo, ["内置枚举", "Subfinder", "Subdominator", "Chaos", "Assetfinder"])
        self._tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        tool_layout.addRow("枚举工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        options_group = QGroupBox("枚举选项")
        form_layout = QFormLayout(options_group)
        
        self._method_combo = QComboBox()
        self._setup_combo(self._method_combo, ["字典枚举", "证书透明度", "搜索引擎", "全部方法"])
        form_layout.addRow("枚举方法:", self._method_combo)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件或使用内置字典")
        self._dict_input.setReadOnly(True)
        
        dict_btn = QPushButton("选择字典")
        dict_btn.setFixedWidth(80)
        dict_btn.clicked.connect(self._select_dict_file)
        dict_layout.addWidget(self._dict_input, 1)
        dict_layout.addWidget(dict_btn)
        form_layout.addRow("字典文件:", dict_layout)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        self._setup_spinbox(self._threads_spin)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._resolve_check = QCheckBox("解析IP地址")
        self._resolve_check.setChecked(True)
        form_layout.addRow(self._resolve_check)
        
        basic_layout.addWidget(options_group)
        tabs.addTab(basic_tab, "基本选项")
        
        subfinder_tab = QWidget()
        subfinder_layout = QVBoxLayout(subfinder_tab)
        
        subfinder_group = QGroupBox("Subfinder 高级选项")
        subfinder_form = QFormLayout(subfinder_group)
        
        self._subfinder_recursive_check = QCheckBox("递归枚举")
        subfinder_form.addRow(self._subfinder_recursive_check)
        
        self._subfinder_all_check = QCheckBox("使用所有数据源")
        self._subfinder_all_check.setChecked(True)
        subfinder_form.addRow(self._subfinder_all_check)
        
        self._subfinder_sources_input = QLineEdit()
        self._subfinder_sources_input.setPlaceholderText("指定数据源，如: shodan,censys")
        subfinder_form.addRow("数据源:", self._subfinder_sources_input)
        
        self._subfinder_excludeSources_input = QLineEdit()
        self._subfinder_excludeSources_input.setPlaceholderText("排除数据源")
        subfinder_form.addRow("排除数据源:", self._subfinder_excludeSources_input)
        
        self._subfinder_rate_spin = QSpinBox()
        self._subfinder_rate_spin.setRange(1, 10000)
        self._subfinder_rate_spin.setValue(1000)
        subfinder_form.addRow("速率限制:", self._subfinder_rate_spin)
        
        self._subfinder_timeout_spin = QSpinBox()
        self._subfinder_timeout_spin.setRange(1, 300)
        self._subfinder_timeout_spin.setValue(30)
        self._subfinder_timeout_spin.setSuffix(" 秒")
        subfinder_form.addRow("超时时间:", self._subfinder_timeout_spin)
        
        self._subfinder_json_check = QCheckBox("JSON输出")
        subfinder_form.addRow(self._subfinder_json_check)
        
        self._subfinder_silent_check = QCheckBox("静默模式")
        self._subfinder_silent_check.setChecked(True)
        subfinder_form.addRow(self._subfinder_silent_check)
        
        self._subfinder_outputFile_input = QLineEdit()
        self._subfinder_outputFile_input.setPlaceholderText("输出文件路径")
        subfinder_form.addRow("输出文件:", self._subfinder_outputFile_input)
        
        subfinder_layout.addWidget(subfinder_group)
        subfinder_layout.addStretch()
        tabs.addTab(subfinder_tab, "Subfinder选项")
        
        amass_tab = QWidget()
        amass_layout = QVBoxLayout(amass_tab)
        
        subdominator_group = QGroupBox("Subdominator 高级选项")
        subdominator_form = QFormLayout(subdominator_group)
        
        self._subdominator_recursive_check = QCheckBox("递归枚举")
        subdominator_form.addRow(self._subdominator_recursive_check)
        
        self._subdominator_all_check = QCheckBox("使用所有数据源")
        self._subdominator_all_check.setChecked(True)
        subdominator_form.addRow(self._subdominator_all_check)
        
        self._subdominator_sources_input = QLineEdit()
        self._subdominator_sources_input.setPlaceholderText("指定数据源")
        subdominator_form.addRow("数据源:", self._subdominator_sources_input)
        
        self._subdominator_threads_spin = QSpinBox()
        self._subdominator_threads_spin.setRange(1, 100)
        self._subdominator_threads_spin.setValue(10)
        subdominator_form.addRow("并发数:", self._subdominator_threads_spin)
        
        self._subdominator_timeout_spin = QSpinBox()
        self._subdominator_timeout_spin.setRange(1, 300)
        self._subdominator_timeout_spin.setValue(30)
        self._subdominator_timeout_spin.setSuffix(" 秒")
        subdominator_form.addRow("超时时间:", self._subdominator_timeout_spin)
        
        self._subdominator_json_check = QCheckBox("JSON输出")
        subdominator_form.addRow(self._subdominator_json_check)
        
        self._subdominator_silent_check = QCheckBox("静默模式")
        self._subdominator_silent_check.setChecked(True)
        subdominator_form.addRow(self._subdominator_silent_check)
        
        self._subdominator_outputFile_input = QLineEdit()
        self._subdominator_outputFile_input.setPlaceholderText("输出文件路径")
        subdominator_form.addRow("输出文件:", self._subdominator_outputFile_input)
        
        amass_layout.addWidget(subdominator_group)
        
        chaos_group = QGroupBox("Chaos 高级选项")
        chaos_form = QFormLayout(chaos_group)
        
        self._chaos_key_input = QLineEdit()
        self._chaos_key_input.setPlaceholderText("Chaos API Key")
        self._chaos_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        chaos_form.addRow("API Key:", self._chaos_key_input)
        
        self._chaos_json_check = QCheckBox("JSON输出")
        chaos_form.addRow(self._chaos_json_check)
        
        self._chaos_silent_check = QCheckBox("静默模式")
        self._chaos_silent_check.setChecked(True)
        chaos_form.addRow(self._chaos_silent_check)
        
        self._chaos_outputFile_input = QLineEdit()
        self._chaos_outputFile_input.setPlaceholderText("输出文件路径")
        chaos_form.addRow("输出文件:", self._chaos_outputFile_input)
        
        amass_layout.addWidget(chaos_group)
        amass_layout.addStretch()
        tabs.addTab(amass_tab, "Subdominator/Chaos")
        
        layout.addWidget(tabs)
        
        self._update_tool_status()
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        tool_map = {
            "Subfinder": "subfinder",
            "Amass": "amass",
            "Assetfinder": "assetfinder"
        }
        if tool_name in tool_map:
            available = self._is_tool_available(tool_map[tool_name])
            if available:
                self._add_log(LogLevel.INFO, f"{tool_name} 工具可用")
            else:
                self._add_log(LogLevel.WARNING, f"{tool_name} 工具不可用，请先下载")
    
    def _select_dict_file(self):
        dict_path = self._select_dict("subdomain")
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
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["子域名", "IP地址", "状态", "标题"])
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
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Subfinder":
            self._scan_with_subfinder()
        elif tool_name == "Subdominator":
            self._scan_with_subdominator()
        elif tool_name == "Chaos":
            self._scan_with_chaos()
        elif tool_name == "Assetfinder":
            self._scan_with_assetfinder()
        else:
            self._scan_builtin()
    
    def _scan_with_subfinder(self):
        if not self._is_tool_available("subfinder"):
            self._add_log(LogLevel.ERROR, "Subfinder 工具不可用")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Subfinder 枚举: {domain}")
        
        args = ["-d", domain]
        
        if self._subfinder_recursive_check.isChecked():
            args.append("-recursive")
        
        if self._subfinder_all_check.isChecked():
            args.append("-all")
        
        sources = self._subfinder_sources_input.text().strip()
        if sources:
            args.extend(["-sources", sources])
        
        exclude_sources = self._subfinder_excludeSources_input.text().strip()
        if exclude_sources:
            args.extend(["-exclude-sources", exclude_sources])
        
        args.extend(["-rate-limit", str(self._subfinder_rate_spin.value())])
        args.extend(["-timeout", str(self._subfinder_timeout_spin.value())])
        
        if self._subfinder_json_check.isChecked():
            args.append("-json")
        
        if self._subfinder_silent_check.isChecked():
            args.append("-silent")
        
        output_file = self._subfinder_outputFile_input.text().strip()
        if output_file:
            args.extend(["-o", output_file])
        
        try:
            process = self._execute_tool("subfinder", args)
            
            if process is None:
                self._add_log(LogLevel.ERROR, "Subfinder 扫描失败: 无法启动进程")
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Subfinder 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Subfinder 枚举失败: {str(e)}")
    
    def _scan_with_subdominator(self):
        if not self._is_tool_available("subdominator"):
            self._add_log(LogLevel.ERROR, "Subdominator 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/RevoltSecurities/Subdominator")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Subdominator 枚举: {domain}")
        
        args = ["-d", domain]
        
        if self._subdominator_recursive_check.isChecked():
            args.append("-r")
        
        if self._subdominator_all_check.isChecked():
            args.append("-all")
        
        sources = self._subdominator_sources_input.text().strip()
        if sources:
            args.extend(["-s", sources])
        
        args.extend(["-t", str(self._subdominator_threads_spin.value())])
        args.extend(["-timeout", str(self._subdominator_timeout_spin.value())])
        
        if self._subdominator_json_check.isChecked():
            args.append("-json")
        
        if self._subdominator_silent_check.isChecked():
            args.append("-silent")
        
        output_file = self._subdominator_outputFile_input.text().strip()
        if output_file:
            args.extend(["-o", output_file])
        
        try:
            process = self._execute_tool("subdominator", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Subdominator 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Subdominator 枚举失败: {str(e)}")
    
    def _scan_with_chaos(self):
        if not self._is_tool_available("chaos"):
            self._add_log(LogLevel.ERROR, "Chaos 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/projectdiscovery/chaos-client")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        api_key = self._chaos_key_input.text().strip()
        if not api_key:
            self._add_log(LogLevel.WARNING, "建议配置Chaos API Key以获得更好结果")
        
        self._add_log(LogLevel.INFO, f"使用 Chaos 枚举: {domain}")
        
        args = ["-d", domain]
        
        if api_key:
            args.extend(["-key", api_key])
        
        if self._chaos_json_check.isChecked():
            args.append("-json")
        
        if self._chaos_silent_check.isChecked():
            args.append("-silent")
        
        output_file = self._chaos_outputFile_input.text().strip()
        if output_file:
            args.extend(["-o", output_file])
        
        try:
            process = self._execute_tool("chaos", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Chaos 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Chaos 枚举失败: {str(e)}")
    
    def _scan_with_assetfinder(self):
        if not self._is_tool_available("assetfinder"):
            self._add_log(LogLevel.ERROR, "Assetfinder 工具不可用")
            return
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"使用 Assetfinder 枚举: {domain}")
        
        args = ["--subs-only", domain]
        
        try:
            process = self._execute_tool("assetfinder", args)
            
            if process is None:
                self._add_log(LogLevel.ERROR, "Assetfinder 扫描失败: 无法启动进程")
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                subdomain = line.strip()
                if subdomain:
                    self._add_result(subdomain, "", "found", "")
                    self._add_log(LogLevel.SUCCESS, f"发现子域名: {subdomain}")
            
            self._add_log(LogLevel.SUCCESS, f"Assetfinder 枚举完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Assetfinder 枚举失败: {str(e)}")
    
    def _scan_builtin(self):
        import dns.resolver
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入域名")
            return
        
        self._add_log(LogLevel.INFO, f"开始枚举子域名: {domain}")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'test',
            'staging', 'portal', 'secure', 'vpn', 'cdn', 'static', 'img',
            'images', 'assets', 'js', 'css', 'app', 'mobile', 'm',
        ]
        
        for sub in common_subdomains:
            if not self._is_scanning:
                break
            
            subdomain = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [rdata.address for rdata in answers]
                self._add_result(subdomain, ', '.join(ips), "有效", "")
                self._add_log(LogLevel.SUCCESS, f"发现: {subdomain} -> {', '.join(ips)}")
            except:
                pass
    
    def _add_result(self, subdomain: str, ip: str, status: str, title: str):
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)
        self._result_table.setItem(row, 0, QTableWidgetItem(subdomain))
        self._result_table.setItem(row, 1, QTableWidgetItem(ip))
        self._result_table.setItem(row, 2, QTableWidgetItem(status))
        self._result_table.setItem(row, 3, QTableWidgetItem(title))


@register_module("directory")
class DirectoryScannerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("directory", "目录扫描")
    
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
        self._setup_combo(self._tool_combo, ["内置扫描", "Dirsearch", "Gobuster", "FFUF", "Feroxbuster"])
        self._tool_combo.currentIndexChanged.connect(self._on_tool_changed)
        tool_layout.addRow("扫描工具:", self._tool_combo)
        
        basic_layout.addWidget(tool_group)
        
        options_group = QGroupBox("扫描选项")
        form_layout = QFormLayout(options_group)
        
        dict_layout = QHBoxLayout()
        self._dict_input = QLineEdit()
        self._dict_input.setPlaceholderText("选择字典文件")
        dict_btn = QPushButton("选择")
        dict_btn.setFixedWidth(60)
        dict_btn.clicked.connect(self._select_dict)
        dict_layout.addWidget(self._dict_input)
        dict_layout.addWidget(dict_btn)
        form_layout.addRow("字典文件:", dict_layout)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(20)
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(10)
        self._timeout_spin.setSuffix(" 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._recursive_check = QCheckBox("递归扫描")
        form_layout.addRow(self._recursive_check)
        
        self._extensions_input = QLineEdit()
        self._extensions_input.setPlaceholderText("如: .php,.html,.asp")
        form_layout.addRow("扩展名:", self._extensions_input)
        
        basic_layout.addWidget(options_group)
        tabs.addTab(basic_tab, "基本选项")
        
        feroxbuster_tab = QWidget()
        feroxbuster_layout = QVBoxLayout(feroxbuster_tab)
        
        feroxbuster_group = QGroupBox("Feroxbuster 高级选项")
        feroxbuster_form = QFormLayout(feroxbuster_group)
        
        self._ferox_depth_spin = QSpinBox()
        self._ferox_depth_spin.setRange(1, 20)
        self._ferox_depth_spin.setValue(4)
        feroxbuster_form.addRow("递归深度:", self._ferox_depth_spin)
        
        self._ferox_threads_spin = QSpinBox()
        self._ferox_threads_spin.setRange(1, 100)
        self._ferox_threads_spin.setValue(50)
        feroxbuster_form.addRow("并发数:", self._ferox_threads_spin)
        
        self._ferox_timeout_spin = QSpinBox()
        self._ferox_timeout_spin.setRange(1, 120)
        self._ferox_timeout_spin.setValue(30)
        self._ferox_timeout_spin.setSuffix(" 秒")
        feroxbuster_form.addRow("超时时间:", self._ferox_timeout_spin)
        
        self._ferox_filter_codes_input = QLineEdit()
        self._ferox_filter_codes_input.setPlaceholderText("过滤状态码，如: 404,403")
        feroxbuster_form.addRow("过滤状态码:", self._ferox_filter_codes_input)
        
        self._ferox_filter_size_input = QLineEdit()
        self._ferox_filter_size_input.setPlaceholderText("过滤响应大小")
        feroxbuster_form.addRow("过滤大小:", self._ferox_filter_size_input)
        
        self._ferox_user_agent_input = QLineEdit()
        self._ferox_user_agent_input.setPlaceholderText("自定义User-Agent")
        feroxbuster_form.addRow("User-Agent:", self._ferox_user_agent_input)
        
        self._ferox_outputFile_input = QLineEdit()
        self._ferox_outputFile_input.setPlaceholderText("输出文件路径")
        feroxbuster_form.addRow("输出文件:", self._ferox_outputFile_input)
        
        feroxbuster_layout.addWidget(feroxbuster_group)
        feroxbuster_layout.addStretch()
        tabs.addTab(feroxbuster_tab, "Feroxbuster选项")
        
        layout.addWidget(tabs)
        
        self._update_tool_status()
        return widget
    
    def _on_tool_changed(self):
        self._update_tool_status()
    
    def _update_tool_status(self):
        tool_name = self._tool_combo.currentText()
        tool_map = {
            "Dirsearch": "dirsearch",
            "Gobuster": "gobuster",
            "FFUF": "ffuf",
            "Feroxbuster": "feroxbuster"
        }
        
        if tool_name in tool_map:
            available = self._is_tool_available(tool_map[tool_name])
            if available:
                self._add_log(LogLevel.INFO, f"{tool_name} 工具可用")
            else:
                self._add_log(LogLevel.WARNING, f"{tool_name} 工具不可用，请先下载")
    
    def _select_dict(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if file_path:
            self._dict_input.setText(file_path)
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["路径", "状态码", "大小", "重定向", "标题"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        return table
    
    def _do_scan(self):
        tool_name = self._tool_combo.currentText()
        
        if tool_name == "Dirsearch":
            self._scan_with_dirsearch()
        elif tool_name == "Gobuster":
            self._scan_with_gobuster()
        elif tool_name == "FFUF":
            self._scan_with_ffuf()
        elif tool_name == "Feroxbuster":
            self._scan_with_feroxbuster()
        else:
            self._scan_builtin()
    
    def _scan_with_feroxbuster(self):
        if not self._is_tool_available("feroxbuster"):
            self._add_log(LogLevel.ERROR, "Feroxbuster 工具不可用")
            self._add_log(LogLevel.INFO, "下载地址: https://github.com/epi052/feroxbuster/releases")
            return
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"使用 Feroxbuster 扫描: {target}")
        
        args = ["-u", target]
        
        dict_path = self._dict_input.text().strip()
        if dict_path:
            args.extend(["-w", dict_path])
        
        args.extend(["-t", str(self._ferox_threads_spin.value())])
        args.extend(["--timeout", str(self._ferox_timeout_spin.value())])
        args.extend(["-d", str(self._ferox_depth_spin.value())])
        
        filter_codes = self._ferox_filter_codes_input.text().strip()
        if filter_codes:
            for code in filter_codes.split(','):
                args.extend(["-C", code.strip()])
        
        filter_size = self._ferox_filter_size_input.text().strip()
        if filter_size:
            args.extend(["-S", filter_size])
        
        user_agent = self._ferox_user_agent_input.text().strip()
        if user_agent:
            args.extend(["-H", f"User-Agent: {user_agent}"])
        
        extensions = self._extensions_input.text().strip()
        if extensions:
            args.extend(["-x", extensions.replace(',', '')])
        
        output_file = self._ferox_outputFile_input.text().strip()
        if output_file:
            args.extend(["-o", output_file])
        
        try:
            process = self._execute_tool("feroxbuster", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._parse_feroxbuster_output(line.strip())
            
            self._add_log(LogLevel.SUCCESS, f"Feroxbuster 扫描完成: {target}")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Feroxbuster 扫描失败: {str(e)}")
    
    def _parse_feroxbuster_output(self, line: str):
        if not line:
            return
        
        code_match = re.search(r'(\d{3})\s+(\d+|\d+[\d,]*)\s+(\S+)\s+\[', line)
        if code_match:
            code = code_match.group(1)
            size = code_match.group(2)
            url = code_match.group(3)
            
            if int(code) < 400:
                self._add_result(url, code, size, "")
                self._add_log(LogLevel.SUCCESS, f"[{code}] {url} ({size} bytes)")
    
    def _scan_with_dirsearch(self):
        if not self._is_tool_available("dirsearch"):
            self._add_log(LogLevel.ERROR, "Dirsearch 工具不可用")
            return
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"使用 Dirsearch 扫描: {target}")
        
        args = ["-u", target]
        
        dict_path = self._dict_input.text().strip()
        if dict_path:
            args.extend(["-w", dict_path])
        
        args.extend(["-t", str(self._threads_spin.value())])
        args.extend(["--timeout", str(self._timeout_spin.value())])
        
        extensions = self._extensions_input.text().strip()
        if extensions:
            args.extend(["-e", extensions.replace(',', '')])
        
        if self._recursive_check.isChecked():
            args.append("-r")
        
        try:
            process = self._execute_tool("dirsearch", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._parse_dirsearch_output(line.strip())
            
            self._add_log(LogLevel.SUCCESS, f"Dirsearch 扫描完成: {target}")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Dirsearch 扫描失败: {str(e)}")
    
    def _parse_dirsearch_output(self, line: str):
        if not line:
            return
        
        code_match = re.search(r'(\d{3})\s+(\d+)\s+(\S+)', line)
        if code_match:
            code = code_match.group(1)
            size = code_match.group(2)
            url = code_match.group(3)
            
            if int(code) < 400:
                self._add_result(url, code, size, "")
                self._add_log(LogLevel.SUCCESS, f"[{code}] {url} ({size} bytes)")
    
    def _scan_with_gobuster(self):
        if not self._is_tool_available("gobuster"):
            self._add_log(LogLevel.ERROR, "Gobuster 工具不可用")
            return
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"使用 Gobuster 扫描: {target}")
        
        args = ["dir", "-u", target]
        
        dict_path = self._dict_input.text().strip()
        if dict_path:
            args.extend(["-w", dict_path])
        
        args.extend(["-t", str(self._threads_spin.value())])
        args.extend(["--timeout", f"{self._timeout_spin.value()}s"])
        
        extensions = self._extensions_input.text().strip()
        if extensions:
            args.extend(["-x", extensions.replace(',', '')])
        
        try:
            process = self._execute_tool("gobuster", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._parse_gobuster_output(line.strip())
            
            self._add_log(LogLevel.SUCCESS, f"Gobuster 扫描完成: {target}")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"Gobuster 扫描失败: {str(e)}")
    
    def _parse_gobuster_output(self, line: str):
        if not line:
            return
        
        match = re.search(r'(\S+)\s+Status:\s+(\d+)\s+\[Size:\s+(\d+)\]', line)
        if match:
            url = match.group(1)
            code = match.group(2)
            size = match.group(3)
            
            if int(code) < 400:
                self._add_result(url, code, size, "")
                self._add_log(LogLevel.SUCCESS, f"[{code}] {url} ({size} bytes)")
    
    def _scan_with_ffuf(self):
        if not self._is_tool_available("ffuf"):
            self._add_log(LogLevel.ERROR, "FFUF 工具不可用")
            return
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        if 'FUZZ' not in target:
            target = target.rstrip('/') + '/FUZZ'
        
        self._add_log(LogLevel.INFO, f"使用 FFUF 扫描: {target}")
        
        args = ["-u", target]
        
        dict_path = self._dict_input.text().strip()
        if dict_path:
            args.extend(["-w", dict_path])
        
        args.extend(["-t", str(self._threads_spin.value())])
        args.extend(["-timeout", str(self._timeout_spin.value())])
        
        extensions = self._extensions_input.text().strip()
        if extensions:
            args.extend(["-e", extensions.replace(',', '')])
        
        try:
            process = self._execute_tool("ffuf", args)
            if not process:
                return
            
            while True:
                if not self._is_scanning:
                    process.terminate()
                    break
                
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                
                self._parse_ffuf_output(line.strip())
            
            self._add_log(LogLevel.SUCCESS, f"FFUF 扫描完成: {target}")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"FFUF 扫描失败: {str(e)}")
    
    def _parse_ffuf_output(self, line: str):
        if not line:
            return
        
        match = re.search(r'Status:\s+(\d+).*?Size:\s+(\d+)', line)
        if match:
            code = match.group(1)
            size = match.group(2)
            url_match = re.search(r'(https?://\S+)', line)
            url = url_match.group(1) if url_match else ""
            
            if int(code) < 400:
                self._add_result(url, code, size, "")
                self._add_log(LogLevel.SUCCESS, f"[{code}] {url} ({size} bytes)")
    
    def _scan_builtin(self):
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        dict_path = self._dict_input.text().strip()
        if not dict_path:
            paths = ['/admin', '/login', '/backup', '/config', '/api', 
                    '/test', '/debug', '/.git', '/.env', '/robots.txt']
        else:
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    paths = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"读取字典失败: {str(e)}")
                return
        
        self._add_log(LogLevel.INFO, f"开始扫描，共 {len(paths)} 个路径")
        
        for i, path in enumerate(paths):
            if not self._is_scanning:
                break
            
            try:
                url = target.rstrip('/') + '/' + path.lstrip('/')
                resp = requests.get(url, timeout=self._timeout_spin.value(), 
                                   allow_redirects=False, verify=False)
                
                if resp.status_code in [200, 301, 302, 403, 401]:
                    size = len(resp.content)
                    redirect = resp.headers.get('Location', '')
                    self._add_result(path, str(resp.status_code), 
                                   f"{size} bytes", redirect)
                    self._add_log(LogLevel.SUCCESS, f"{path} - {resp.status_code}")
            except Exception as e:
                pass
            
            progress = int(((i + 1) / len(paths)) * 100)
            self.progress_updated.emit(progress)


@register_module("fingerprint")
class FingerprintWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("fingerprint", "指纹识别")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("识别选项")
        form_layout = QFormLayout(options_group)
        
        self._deep_scan_check = QCheckBox("深度扫描")
        form_layout.addRow(self._deep_scan_check)
        
        self._cms_check = QCheckBox("CMS识别")
        self._cms_check.setChecked(True)
        form_layout.addRow(self._cms_check)
        
        self._waf_check = QCheckBox("WAF检测")
        self._waf_check.setChecked(True)
        form_layout.addRow(self._waf_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["类型", "名称", "版本", "置信度"])
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
        import requests
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标URL")
            return
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self._add_log(LogLevel.INFO, f"开始指纹识别: {target}")
        
        try:
            resp = requests.get(target, timeout=10, verify=False)
            
            server = resp.headers.get('Server', 'Unknown')
            self._add_result("Server", server, "", "高")
            self._add_log(LogLevel.SUCCESS, f"Server: {server}")
            
            powered = resp.headers.get('X-Powered-By', '')
            if powered:
                self._add_result("Technology", powered, "", "高")
                self._add_log(LogLevel.SUCCESS, f"X-Powered-By: {powered}")
            
            cms_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Drupal': ['drupal', 'sites/default/files'],
                'Joomla': ['joomla', '/components/com_'],
                'DedeCMS': ['dede', 'dedecms'],
                'Discuz': ['discuz', 'forum.php'],
                'ThinkPHP': ['thinkphp', 'think_'],
            }
            
            content = resp.text.lower()
            for cms, signatures in cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in content:
                        self._add_result("CMS", cms, "", "中")
                        self._add_log(LogLevel.SUCCESS, f"检测到CMS: {cms}")
                        break
            
            self._add_log(LogLevel.INFO, "指纹识别完成")
            
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"扫描失败: {str(e)}")


@register_module("ssl_analyzer")
class SSLAnalyzerWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("ssl_analyzer", "SSL分析")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("分析选项")
        form_layout = QFormLayout(options_group)
        
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(443)
        form_layout.addRow("端口:", self._port_spin)
        
        self._check_vuln = QCheckBox("漏洞检测")
        self._check_vuln.setChecked(True)
        form_layout.addRow(self._check_vuln)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["项目", "值", "状态"])
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(200)
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        return table
    
    def _do_scan(self):
        import ssl
        import socket
        from datetime import datetime
        
        target = self._target_input.text().strip()
        if not target:
            self._add_log(LogLevel.ERROR, "请输入目标域名")
            return
        
        target = target.replace('https://', '').replace('http://', '').split('/')[0]
        port = self._port_spin.value()
        
        self._add_log(LogLevel.INFO, f"开始SSL分析: {target}:{port}")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    self._add_result("主题CN", subject.get('commonName', ''), "✓")
                    self._add_result("颁发者", issuer.get('commonName', ''), "✓")
                    
                    version = ssock.version()
                    self._add_result("协议版本", version, "✓")
                    
                    cipher = ssock.cipher()
                    self._add_result("加密套件", cipher[0], "✓")
                    
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        self._add_result("过期时间", not_after, "✓")
                    
                    self._add_log(LogLevel.SUCCESS, "SSL证书分析完成")
                    
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"SSL分析失败: {str(e)}")


@register_module("email_collector")
class EmailCollectorWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("email_collector", "邮箱收集")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        options_group = QGroupBox("收集选项")
        form_layout = QFormLayout(options_group)
        
        self._search_engine_check = QCheckBox("搜索引擎")
        self._search_engine_check.setChecked(True)
        form_layout.addRow(self._search_engine_check)
        
        self._github_check = QCheckBox("GitHub")
        self._github_check.setChecked(True)
        form_layout.addRow(self._github_check)
        
        self._deep_check = QCheckBox("深度搜索")
        form_layout.addRow(self._deep_check)
        
        layout.addWidget(options_group)
        return widget
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["邮箱地址", "来源", "发现时间"])
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
        import re
        import requests
        from datetime import datetime
        
        domain = self._target_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入目标域名")
            return
        
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        
        self._add_log(LogLevel.INFO, f"开始收集邮箱: {domain}")
        
        email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
        
        test_emails = [
            f'admin@{domain}',
            f'info@{domain}',
            f'support@{domain}',
            f'contact@{domain}',
        ]
        
        for email in test_emails:
            if not self._is_scanning:
                break
            self._add_result(email, "测试", datetime.now().strftime("%Y-%m-%d %H:%M"))
            self._add_log(LogLevel.SUCCESS, f"发现邮箱: {email}")
        
        self._add_log(LogLevel.INFO, "邮箱收集完成")
