import json
import re
import socket
import struct
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
import ipaddress

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QSpinBox, QFileDialog, QMessageBox, QListView, QDialog,
    QListWidget, QDialogButtonBox, QFormLayout, QRadioButton,
    QButtonGroup, QPlainTextEdit, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtGui import QFont

from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel


@register_module("ip_tool")
class IPToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("ip_tool", "IP工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("IP输入")
        input_layout = QVBoxLayout(input_group)
        
        self._ip_input = QLineEdit()
        self._ip_input.setPlaceholderText("输入IP地址或CIDR，如: 192.168.1.1 或 192.168.1.0/24")
        input_layout.addWidget(self._ip_input)
        
        layout.addWidget(input_group)
        
        mode_group = QGroupBox("操作模式")
        mode_layout = QVBoxLayout(mode_group)
        
        self._mode_group = QButtonGroup()
        modes = [
            ("IP信息查询", True),
            ("CIDR计算", False),
            ("IP范围转换", False),
            ("子网计算", False),
            ("IP转换", False),
        ]
        
        for i, (mode, checked) in enumerate(modes):
            rb = QRadioButton(mode)
            rb.setChecked(checked)
            self._mode_group.addButton(rb, i)
            mode_layout.addWidget(rb)
        
        layout.addWidget(mode_group)
        
        btn_layout = QHBoxLayout()
        
        calc_btn = QPushButton("计算")
        calc_btn.clicked.connect(self._calculate)
        
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("secondaryButton")
        copy_btn.clicked.connect(self._copy_result)
        
        btn_layout.addWidget(calc_btn)
        btn_layout.addWidget(copy_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout(result_group)
        
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(2)
        self._result_table.setHorizontalHeaderLabels(["属性", "值"])
        self._result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._result_table.setMaximumHeight(250)
        result_layout.addWidget(self._result_table)
        
        layout.addWidget(result_group)
        
        return widget
    
    def _calculate(self):
        self._result_table.setRowCount(0)
        
        ip_input = self._ip_input.text().strip()
        if not ip_input:
            self._add_log(LogLevel.ERROR, "请输入IP地址")
            return
        
        mode_id = self._mode_group.checkedId()
        
        try:
            if mode_id == 0:
                self._ip_info(ip_input)
            elif mode_id == 1:
                self._cidr_calc(ip_input)
            elif mode_id == 2:
                self._ip_range(ip_input)
            elif mode_id == 3:
                self._subnet_calc(ip_input)
            elif mode_id == 4:
                self._ip_convert(ip_input)
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"计算错误: {str(e)}")
    
    def _add_result_row(self, prop: str, value: str):
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)
        self._result_table.setItem(row, 0, QTableWidgetItem(prop))
        self._result_table.setItem(row, 1, QTableWidgetItem(str(value)))
    
    def _ip_info(self, ip_str: str):
        ip = ipaddress.ip_address(ip_str)
        
        self._add_result_row("IP地址", str(ip))
        self._add_result_row("IP版本", f"IPv{ip.version}")
        self._add_result_row("是否私有", "是" if ip.is_private else "否")
        self._add_result_row("是否保留", "是" if ip.is_reserved else "否")
        self._add_result_row("是否环回", "是" if ip.is_loopback else "否")
        self._add_result_row("是否多播", "是" if ip.is_multicast else "否")
        self._add_result_row("是否链路本地", "是" if ip.is_link_local else "否")
        
        if ip.version == 4:
            packed = ip.packed
            self._add_result_row("整数表示", str(int(ip)))
            self._add_result_row("十六进制", ip.packed.hex())
            self._add_result_row("二进制", bin(int(ip))[2:].zfill(32))
            self._add_result_row("反向DNS", f"{'.'.join(str(b) for b in reversed(packed))}.in-addr.arpa")
        
        self._add_log(LogLevel.SUCCESS, "IP信息查询完成")
    
    def _cidr_calc(self, cidr_str: str):
        network = ipaddress.ip_network(cidr_str, strict=False)
        
        self._add_result_row("网络地址", str(network.network_address))
        self._add_result_row("广播地址", str(network.broadcast_address))
        self._add_result_row("子网掩码", str(network.netmask))
        self._add_result_row("主机位数", str(network.hostmask))
        self._add_result_row("前缀长度", f"/{network.prefixlen}")
        self._add_result_row("地址总数", str(network.num_addresses))
        self._add_result_row("可用主机数", str(max(0, network.num_addresses - 2)))
        self._add_result_row("第一个可用IP", str(network.network_address + 1) if network.num_addresses > 2 else "N/A")
        self._add_result_row("最后一个可用IP", str(network.broadcast_address - 1) if network.num_addresses > 2 else "N/A")
        
        self._add_log(LogLevel.SUCCESS, "CIDR计算完成")
    
    def _ip_range(self, ip_str: str):
        if '/' in ip_str:
            network = ipaddress.ip_network(ip_str, strict=False)
            start = network.network_address
            end = network.broadcast_address
        elif '-' in ip_str:
            parts = ip_str.split('-')
            start = ipaddress.ip_address(parts[0].strip())
            end = ipaddress.ip_address(parts[1].strip())
        else:
            self._add_log(LogLevel.ERROR, "请输入CIDR或IP范围 (如: 192.168.1.1-192.168.1.100)")
            return
        
        self._add_result_row("起始IP", str(start))
        self._add_result_row("结束IP", str(end))
        self._add_result_row("IP总数", str(int(end) - int(start) + 1))
        
        if isinstance(start, ipaddress.IPv4Address):
            self._add_result_row("CIDR表示", self._range_to_cidr(start, end))
        
        self._add_log(LogLevel.SUCCESS, "IP范围计算完成")
    
    def _range_to_cidr(self, start, end) -> str:
        cidrs = []
        start_int = int(start)
        end_int = int(end)
        
        while start_int <= end_int:
            max_size = 32
            while max_size > 0:
                mask = (1 << (32 - max_size + 1)) - 1
                if (start_int & mask) != 0:
                    break
                max_size -= 1
            
            max_diff = 32 - start_int.bit_length()
            max_size = min(max_size, max_diff + 1) if max_diff >= 0 else max_size
            
            current_size = max_size
            while current_size > 0:
                if start_int + (1 << (32 - current_size)) - 1 > end_int:
                    current_size -= 1
                else:
                    break
            
            cidrs.append(f"{ipaddress.IPv4Address(start_int)}/{current_size}")
            start_int += (1 << (32 - current_size))
        
        return ', '.join(cidrs[:5]) + ('...' if len(cidrs) > 5 else '')
    
    def _subnet_calc(self, ip_str: str):
        if '/' not in ip_str:
            ip_str = f"{ip_str}/24"
        
        network = ipaddress.ip_network(ip_str, strict=False)
        
        self._add_result_row("网络", str(network))
        self._add_result_row("子网掩码", str(network.netmask))
        self._add_result_row("通配符掩码", str(network.hostmask))
        
        subnet_bits = network.prefixlen
        host_bits = 32 - subnet_bits if network.version == 4 else 128 - subnet_bits
        
        self._add_result_row("子网位数", str(subnet_bits))
        self._add_result_row("主机位数", str(host_bits))
        self._add_result_row("可能的子网数", str(2 ** subnet_bits))
        self._add_result_row("每子网主机数", str(2 ** host_bits))
        
        self._add_log(LogLevel.SUCCESS, "子网计算完成")
    
    def _ip_convert(self, ip_str: str):
        try:
            ip = ipaddress.ip_address(ip_str)
            
            self._add_result_row("十进制", str(int(ip)))
            self._add_result_row("十六进制", hex(int(ip)))
            self._add_result_row("八进制", oct(int(ip)))
            self._add_result_row("二进制", bin(int(ip))[2:].zfill(32 if ip.version == 4 else 128))
            
            if ip.version == 4:
                packed = ip.packed
                self._add_result_row("点分十进制", str(ip))
                self._add_result_row("点分十六进制", '.'.join(f'{b:02x}' for b in packed))
                self._add_result_row("点分八进制", '.'.join(f'{b:03o}' for b in packed))
                self._add_result_row("整数形式", str(int(ip)))
                self._add_result_row("十六进制形式", '0x' + packed.hex())
        
        except ValueError:
            try:
                if ip_str.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in ip_str):
                    num = int(ip_str, 16)
                    ip = ipaddress.IPv4Address(num)
                    self._add_result_row("十六进制转IP", str(ip))
                elif ip_str.isdigit():
                    num = int(ip_str)
                    ip = ipaddress.IPv4Address(num)
                    self._add_result_row("十进制转IP", str(ip))
            except:
                pass
        
        self._add_log(LogLevel.SUCCESS, "IP转换完成")
    
    def _copy_result(self):
        results = []
        for row in range(self._result_table.rowCount()):
            prop = self._result_table.item(row, 0).text()
            value = self._result_table.item(row, 1).text()
            results.append(f"{prop}: {value}")
        
        text = '\n'.join(results)
        QApplication.clipboard().setText(text)
        self._add_log(LogLevel.SUCCESS, "已复制到剪贴板")
    
    def _do_scan(self):
        self._calculate()


@register_module("http_tool")
class HTTPToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("http_tool", "HTTP工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        tabs = QTabWidget()
        
        encode_tab = QWidget()
        encode_layout = QVBoxLayout(encode_tab)
        
        encode_layout.addWidget(QLabel("输入URL:"))
        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("输入URL进行解析")
        encode_layout.addWidget(self._url_input)
        
        parse_btn = QPushButton("解析URL")
        parse_btn.clicked.connect(self._parse_url)
        encode_layout.addWidget(parse_btn)
        
        encode_layout.addWidget(QLabel("解析结果:"))
        self._url_result = QPlainTextEdit()
        self._url_result.setReadOnly(True)
        self._url_result.setMaximumHeight(150)
        encode_layout.addWidget(self._url_result)
        
        tabs.addTab(encode_tab, "URL解析")
        
        headers_tab = QWidget()
        headers_layout = QVBoxLayout(headers_tab)
        
        headers_layout.addWidget(QLabel("HTTP头部文本:"))
        self._headers_input = QPlainTextEdit()
        self._headers_input.setPlaceholderText("粘贴HTTP请求头:\nHost: example.com\nUser-Agent: Mozilla/5.0\nCookie: session=abc123")
        self._headers_input.setMaximumHeight(100)
        headers_layout.addWidget(self._headers_input)
        
        parse_headers_btn = QPushButton("解析头部")
        parse_headers_btn.clicked.connect(self._parse_headers)
        headers_layout.addWidget(parse_headers_btn)
        
        self._headers_table = QTableWidget()
        self._headers_table.setColumnCount(2)
        self._headers_table.setHorizontalHeaderLabels(["头部名称", "值"])
        self._headers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        headers_layout.addWidget(self._headers_table)
        
        tabs.addTab(headers_tab, "头部解析")
        
        cookie_tab = QWidget()
        cookie_layout = QVBoxLayout(cookie_tab)
        
        cookie_layout.addWidget(QLabel("Cookie字符串:"))
        self._cookie_input = QLineEdit()
        self._cookie_input.setPlaceholderText("name=value; session=abc123; user=admin")
        cookie_layout.addWidget(self._cookie_input)
        
        parse_cookie_btn = QPushButton("解析Cookie")
        parse_cookie_btn.clicked.connect(self._parse_cookie)
        cookie_layout.addWidget(parse_cookie_btn)
        
        self._cookie_table = QTableWidget()
        self._cookie_table.setColumnCount(2)
        self._cookie_table.setHorizontalHeaderLabels(["名称", "值"])
        self._cookie_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        cookie_layout.addWidget(self._cookie_table)
        
        tabs.addTab(cookie_tab, "Cookie解析")
        
        status_tab = QWidget()
        status_layout = QVBoxLayout(status_tab)
        
        status_layout.addWidget(QLabel("HTTP状态码查询:"))
        self._status_input = QLineEdit()
        self._status_input.setPlaceholderText("输入状态码，如: 200, 404, 500")
        status_layout.addWidget(self._status_input)
        
        query_btn = QPushButton("查询")
        query_btn.clicked.connect(self._query_status)
        status_layout.addWidget(query_btn)
        
        self._status_result = QPlainTextEdit()
        self._status_result.setReadOnly(True)
        self._status_result.setMaximumHeight(200)
        status_layout.addWidget(self._status_result)
        
        tabs.addTab(status_tab, "状态码查询")
        
        layout.addWidget(tabs)
        
        return widget
    
    def _parse_url(self):
        from urllib.parse import urlparse, parse_qs
        
        url = self._url_input.text().strip()
        if not url:
            return
        
        parsed = urlparse(url)
        
        result = f"""协议: {parsed.scheme}
主机: {parsed.netloc}
路径: {parsed.path}
查询: {parsed.query}
片段: {parsed.fragment}
"""
        
        if parsed.query:
            params = parse_qs(parsed.query)
            result += "\n查询参数:\n"
            for key, values in params.items():
                result += f"  {key}: {', '.join(values)}\n"
        
        self._url_result.setPlainText(result)
        self._add_log(LogLevel.SUCCESS, "URL解析完成")
        self._add_result(url, "URL解析", "完成", f"主机: {parsed.netloc}")
    
    def _parse_headers(self):
        self._headers_table.setRowCount(0)
        
        text = self._headers_input.toPlainText()
        if not text:
            return
        
        for line in text.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                row = self._headers_table.rowCount()
                self._headers_table.insertRow(row)
                self._headers_table.setItem(row, 0, QTableWidgetItem(key.strip()))
                self._headers_table.setItem(row, 1, QTableWidgetItem(value.strip()))
        
        self._add_log(LogLevel.SUCCESS, f"解析了 {self._headers_table.rowCount()} 个头部")
    
    def _parse_cookie(self):
        self._cookie_table.setRowCount(0)
        
        cookie_str = self._cookie_input.text().strip()
        if not cookie_str:
            return
        
        for pair in cookie_str.split(';'):
            pair = pair.strip()
            if '=' in pair:
                key, value = pair.split('=', 1)
                row = self._cookie_table.rowCount()
                self._cookie_table.insertRow(row)
                self._cookie_table.setItem(row, 0, QTableWidgetItem(key.strip()))
                self._cookie_table.setItem(row, 1, QTableWidgetItem(value.strip()))
        
        self._add_log(LogLevel.SUCCESS, f"解析了 {self._cookie_table.rowCount()} 个Cookie")
    
    def _query_status(self):
        status_codes = {
            '100': 'Continue - 继续',
            '101': 'Switching Protocols - 切换协议',
            '200': 'OK - 成功',
            '201': 'Created - 已创建',
            '202': 'Accepted - 已接受',
            '204': 'No Content - 无内容',
            '301': 'Moved Permanently - 永久重定向',
            '302': 'Found - 临时重定向',
            '304': 'Not Modified - 未修改',
            '307': 'Temporary Redirect - 临时重定向',
            '308': 'Permanent Redirect - 永久重定向',
            '400': 'Bad Request - 错误请求',
            '401': 'Unauthorized - 未授权',
            '403': 'Forbidden - 禁止访问',
            '404': 'Not Found - 未找到',
            '405': 'Method Not Allowed - 方法不允许',
            '408': 'Request Timeout - 请求超时',
            '409': 'Conflict - 冲突',
            '410': 'Gone - 已删除',
            '413': 'Payload Too Large - 请求实体过大',
            '429': 'Too Many Requests - 请求过多',
            '500': 'Internal Server Error - 服务器内部错误',
            '501': 'Not Implemented - 未实现',
            '502': 'Bad Gateway - 网关错误',
            '503': 'Service Unavailable - 服务不可用',
            '504': 'Gateway Timeout - 网关超时',
        }
        
        code = self._status_input.text().strip()
        
        if code in status_codes:
            self._status_result.setPlainText(f"{code}: {status_codes[code]}")
        else:
            self._status_result.setPlainText(f"未找到状态码 {code} 的定义")
        
        self._add_log(LogLevel.INFO, f"查询状态码: {code}")
    
    def _do_scan(self):
        self._parse_url()


@register_module("json_tool")
class JSONToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("json_tool", "JSON工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_group = QGroupBox("JSON输入")
        input_layout = QVBoxLayout(input_group)
        
        self._json_input = QPlainTextEdit()
        self._json_input.setPlaceholderText('{"key": "value", "array": [1, 2, 3]}')
        self._json_input.setMaximumHeight(150)
        input_layout.addWidget(self._json_input)
        
        layout.addWidget(input_group)
        
        action_layout = QHBoxLayout()
        
        format_btn = QPushButton("格式化")
        format_btn.clicked.connect(self._format_json)
        
        compress_btn = QPushButton("压缩")
        compress_btn.clicked.connect(self._compress_json)
        
        validate_btn = QPushButton("验证")
        validate_btn.clicked.connect(self._validate_json)
        
        escape_btn = QPushButton("转义")
        escape_btn.clicked.connect(self._escape_json)
        
        unescape_btn = QPushButton("反转义")
        unescape_btn.clicked.connect(self._unescape_json)
        
        action_layout.addWidget(format_btn)
        action_layout.addWidget(compress_btn)
        action_layout.addWidget(validate_btn)
        action_layout.addWidget(escape_btn)
        action_layout.addWidget(unescape_btn)
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout(output_group)
        
        self._json_output = QPlainTextEdit()
        self._json_output.setReadOnly(True)
        self._json_output.setMaximumHeight(200)
        output_layout.addWidget(self._json_output)
        
        layout.addWidget(output_group)
        
        path_group = QGroupBox("JSONPath查询")
        path_layout = QHBoxLayout(path_group)
        
        self._jsonpath_input = QLineEdit()
        self._jsonpath_input.setPlaceholderText("$.key 或 $..value")
        path_layout.addWidget(self._jsonpath_input)
        
        query_btn = QPushButton("查询")
        query_btn.clicked.connect(self._query_jsonpath)
        path_layout.addWidget(query_btn)
        
        layout.addWidget(path_group)
        
        return widget
    
    def _format_json(self):
        text = self._json_input.toPlainText()
        try:
            data = json.loads(text)
            formatted = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
            self._json_output.setPlainText(formatted)
            self._add_log(LogLevel.SUCCESS, "JSON格式化成功")
        except json.JSONDecodeError as e:
            self._add_log(LogLevel.ERROR, f"JSON格式错误: {str(e)}")
    
    def _compress_json(self):
        text = self._json_input.toPlainText()
        try:
            data = json.loads(text)
            compressed = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
            self._json_output.setPlainText(compressed)
            self._add_log(LogLevel.SUCCESS, f"JSON压缩成功: {len(text)} -> {len(compressed)} 字符")
        except json.JSONDecodeError as e:
            self._add_log(LogLevel.ERROR, f"JSON格式错误: {str(e)}")
    
    def _validate_json(self):
        text = self._json_input.toPlainText()
        try:
            data = json.loads(text)
            self._json_output.setPlainText(f"✓ JSON格式正确\n\n类型: {type(data).__name__}\n大小: {len(text)} 字符")
            if isinstance(data, dict):
                self._json_output.appendPlainText(f"键数量: {len(data)}")
            elif isinstance(data, list):
                self._json_output.appendPlainText(f"元素数量: {len(data)}")
            self._add_log(LogLevel.SUCCESS, "JSON验证通过")
        except json.JSONDecodeError as e:
            self._json_output.setPlainText(f"✗ JSON格式错误\n\n错误: {str(e)}\n行: {e.lineno}, 列: {e.colno}")
            self._add_log(LogLevel.ERROR, f"JSON验证失败: {str(e)}")
    
    def _escape_json(self):
        text = self._json_input.toPlainText()
        escaped = json.dumps(text, ensure_ascii=False)
        self._json_output.setPlainText(escaped)
        self._add_log(LogLevel.SUCCESS, "JSON转义完成")
    
    def _unescape_json(self):
        text = self._json_input.toPlainText()
        try:
            unescaped = json.loads(text)
            if isinstance(unescaped, str):
                self._json_output.setPlainText(unescaped)
            else:
                self._json_output.setPlainText(json.dumps(unescaped, indent=2, ensure_ascii=False))
            self._add_log(LogLevel.SUCCESS, "JSON反转义完成")
        except json.JSONDecodeError as e:
            self._add_log(LogLevel.ERROR, f"反转义失败: {str(e)}")
    
    def _query_jsonpath(self):
        text = self._json_input.toPlainText()
        path = self._jsonpath_input.text().strip()
        
        if not text or not path:
            return
        
        try:
            data = json.loads(text)
            results = self._simple_jsonpath(data, path)
            self._json_output.setPlainText(json.dumps(results, indent=2, ensure_ascii=False))
            self._add_log(LogLevel.SUCCESS, f"找到 {len(results) if isinstance(results, list) else 1} 个结果")
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"查询失败: {str(e)}")
    
    def _simple_jsonpath(self, data, path: str):
        if path.startswith('$.'):
            path = path[2:]
        
        if not path:
            return data
        
        parts = path.split('.')
        current = data
        
        for part in parts:
            if part == '*':
                if isinstance(current, list):
                    return current
                elif isinstance(current, dict):
                    return list(current.values())
            elif part.startswith('[') and part.endswith(']'):
                idx = int(part[1:-1])
                if isinstance(current, list) and 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            elif isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        
        return current
    
    def _do_scan(self):
        self._format_json()


@register_module("regex_tool")
class RegexToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("regex_tool", "正则工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        pattern_group = QGroupBox("正则表达式")
        pattern_layout = QVBoxLayout(pattern_group)
        
        self._regex_input = QLineEdit()
        self._regex_input.setPlaceholderText("输入正则表达式，如: \\d+、[a-zA-Z]+、(https?://\\S+)")
        pattern_layout.addWidget(self._regex_input)
        
        flags_layout = QHBoxLayout()
        self._ignore_case = QCheckBox("忽略大小写")
        self._multiline = QCheckBox("多行模式")
        self._dotall = QCheckBox("点匹配换行")
        flags_layout.addWidget(self._ignore_case)
        flags_layout.addWidget(self._multiline)
        flags_layout.addWidget(self._dotall)
        flags_layout.addStretch()
        pattern_layout.addLayout(flags_layout)
        
        layout.addWidget(pattern_group)
        
        text_group = QGroupBox("测试文本")
        text_layout = QVBoxLayout(text_group)
        
        self._text_input = QPlainTextEdit()
        self._text_input.setPlaceholderText("输入要匹配的文本...")
        self._text_input.setMaximumHeight(100)
        text_layout.addWidget(self._text_input)
        
        layout.addWidget(text_group)
        
        preset_group = QGroupBox("常用正则")
        preset_layout = QHBoxLayout(preset_group)
        
        self._preset_combo = QComboBox()
        self._setup_combo(self._preset_combo, [
            "选择预设...",
            "IP地址", "邮箱", "手机号", "URL",
            "身份证号", "日期(YYYY-MM-DD)", "时间(HH:MM:SS)",
            "HTML标签", "数字", "中文字符", "空白字符"
        ])
        self._preset_combo.currentTextChanged.connect(self._apply_preset)
        preset_layout.addWidget(self._preset_combo)
        preset_layout.addStretch()
        layout.addWidget(preset_group)
        
        btn_layout = QHBoxLayout()
        
        match_btn = QPushButton("匹配")
        match_btn.clicked.connect(self._match)
        
        findall_btn = QPushButton("查找全部")
        findall_btn.clicked.connect(self._findall)
        
        replace_btn = QPushButton("替换")
        replace_btn.clicked.connect(self._replace)
        
        split_btn = QPushButton("分割")
        split_btn.clicked.connect(self._split)
        
        btn_layout.addWidget(match_btn)
        btn_layout.addWidget(findall_btn)
        btn_layout.addWidget(replace_btn)
        btn_layout.addWidget(split_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        replace_layout = QHBoxLayout()
        replace_layout.addWidget(QLabel("替换为:"))
        self._replace_input = QLineEdit()
        self._replace_input.setPlaceholderText("替换文本")
        replace_layout.addWidget(self._replace_input)
        layout.addLayout(replace_layout)
        
        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout(result_group)
        
        self._result_text = QPlainTextEdit()
        self._result_text.setReadOnly(True)
        self._result_text.setMaximumHeight(150)
        result_layout.addWidget(self._result_text)
        
        layout.addWidget(result_group)
        
        return widget
    
    def _apply_preset(self, preset: str):
        presets = {
            "IP地址": r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            "邮箱": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "手机号": r"1[3-9]\d{9}",
            "URL": r"https?://[^\s<>()\"']+",
            "身份证号": r"\d{17}[\dXx]|\d{15}",
            "日期": r"\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])",
            "时间": r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d",
            "HTML标签": r"<[^>]+>",
            "数字": r"-?\d+\.?\d*",
            "中文字符": r"[\u4e00-\u9fa5]+",
            "空白字符": r"\s+",
        }
        
        if preset in presets:
            self._regex_input.setText(presets[preset])
    
    def _get_flags(self):
        flags = 0
        if self._ignore_case.isChecked():
            flags |= re.IGNORECASE
        if self._multiline.isChecked():
            flags |= re.MULTILINE
        if self._dotall.isChecked():
            flags |= re.DOTALL
        return flags
    
    def _match(self):
        pattern = self._regex_input.text()
        text = self._text_input.toPlainText()
        
        if not pattern or not text:
            return
        
        try:
            flags = self._get_flags()
            match = re.search(pattern, text, flags)
            
            if match:
                result = f"匹配成功!\n\n匹配内容: {match.group()}\n位置: {match.start()}-{match.end()}\n\n分组:\n"
                for i, g in enumerate(match.groups()):
                    result += f"  组{i+1}: {g}\n"
                self._result_text.setPlainText(result)
                self._add_log(LogLevel.SUCCESS, f"匹配成功: {match.group()}")
            else:
                self._result_text.setPlainText("未找到匹配")
                self._add_log(LogLevel.WARNING, "未找到匹配")
        except re.error as e:
            self._result_text.setPlainText(f"正则错误: {str(e)}")
            self._add_log(LogLevel.ERROR, f"正则错误: {str(e)}")
    
    def _findall(self):
        pattern = self._regex_input.text()
        text = self._text_input.toPlainText()
        
        if not pattern or not text:
            return
        
        try:
            flags = self._get_flags()
            matches = re.findall(pattern, text, flags)
            
            if matches:
                result = f"找到 {len(matches)} 个匹配:\n\n"
                for i, m in enumerate(matches[:50], 1):
                    result += f"{i}. {m}\n"
                if len(matches) > 50:
                    result += f"... 还有 {len(matches) - 50} 个"
                self._result_text.setPlainText(result)
                self._add_log(LogLevel.SUCCESS, f"找到 {len(matches)} 个匹配")
            else:
                self._result_text.setPlainText("未找到匹配")
                self._add_log(LogLevel.WARNING, "未找到匹配")
        except re.error as e:
            self._result_text.setPlainText(f"正则错误: {str(e)}")
            self._add_log(LogLevel.ERROR, f"正则错误: {str(e)}")
    
    def _replace(self):
        pattern = self._regex_input.text()
        text = self._text_input.toPlainText()
        replacement = self._replace_input.text()
        
        if not pattern or not text:
            return
        
        try:
            flags = self._get_flags()
            result = re.sub(pattern, replacement, text, flags=flags)
            count = len(re.findall(pattern, text, flags))
            
            self._result_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"替换了 {count} 处")
        except re.error as e:
            self._result_text.setPlainText(f"正则错误: {str(e)}")
            self._add_log(LogLevel.ERROR, f"正则错误: {str(e)}")
    
    def _split(self):
        pattern = self._regex_input.text()
        text = self._text_input.toPlainText()
        
        if not pattern or not text:
            return
        
        try:
            flags = self._get_flags()
            parts = re.split(pattern, text, flags=flags)
            
            result = f"分割为 {len(parts)} 部分:\n\n"
            for i, part in enumerate(parts, 1):
                result += f"--- 第{i}部分 ---\n{part}\n\n"
            
            self._result_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"分割为 {len(parts)} 部分")
        except re.error as e:
            self._result_text.setPlainText(f"正则错误: {str(e)}")
            self._add_log(LogLevel.ERROR, f"正则错误: {str(e)}")
    
    def _do_scan(self):
        self._findall()


@register_module("time_tool")
class TimeToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("time_tool", "时间工具")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        current_group = QGroupBox("当前时间")
        current_layout = QVBoxLayout(current_group)
        
        self._current_time = QLabel()
        self._current_time.setStyleSheet("font-size: 18px; font-weight: bold;")
        current_layout.addWidget(self._current_time)
        
        self._current_timestamp = QLabel()
        current_layout.addWidget(self._current_timestamp)
        
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_time)
        current_layout.addWidget(refresh_btn)
        
        layout.addWidget(current_group)
        
        convert_group = QGroupBox("时间转换")
        convert_layout = QFormLayout(convert_group)
        
        self._timestamp_input = QLineEdit()
        self._timestamp_input.setPlaceholderText("输入Unix时间戳")
        convert_layout.addRow("时间戳:", self._timestamp_input)
        
        ts_to_date_btn = QPushButton("时间戳转日期")
        ts_to_date_btn.clicked.connect(self._timestamp_to_date)
        convert_layout.addRow(ts_to_date_btn)
        
        self._date_input = QLineEdit()
        self._date_input.setPlaceholderText("输入日期时间，如: 2024-01-15 10:30:00")
        convert_layout.addRow("日期时间:", self._date_input)
        
        date_to_ts_btn = QPushButton("日期转时间戳")
        date_to_ts_btn.clicked.connect(self._date_to_timestamp)
        convert_layout.addRow(date_to_ts_btn)
        
        layout.addWidget(convert_group)
        
        format_group = QGroupBox("格式化")
        format_layout = QVBoxLayout(format_group)
        
        self._format_input = QLineEdit()
        self._format_input.setText("%Y-%m-%d %H:%M:%S")
        self._format_input.setPlaceholderText("格式字符串，如: %Y-%m-%d %H:%M:%S")
        format_layout.addWidget(QLabel("格式字符串:"))
        format_layout.addWidget(self._format_input)
        
        format_btn = QPushButton("格式化当前时间")
        format_btn.clicked.connect(self._format_time)
        format_layout.addWidget(format_btn)
        
        layout.addWidget(format_group)
        
        result_group = QGroupBox("结果")
        result_layout = QVBoxLayout(result_group)
        
        self._result_text = QPlainTextEdit()
        self._result_text.setReadOnly(True)
        self._result_text.setMaximumHeight(150)
        result_layout.addWidget(self._result_text)
        
        layout.addWidget(result_group)
        
        return widget
    
    def _refresh_time(self):
        now = datetime.now()
        timestamp = int(time.time())
        
        self._current_time.setText(now.strftime("%Y-%m-%d %H:%M:%S"))
        self._current_timestamp.setText(f"Unix时间戳: {timestamp}")
    
    def _timestamp_to_date(self):
        ts_str = self._timestamp_input.text().strip()
        if not ts_str:
            return
        
        try:
            ts = int(ts_str)
            dt = datetime.fromtimestamp(ts)
            
            result = f"""时间戳: {ts}
本地时间: {dt.strftime("%Y-%m-%d %H:%M:%S")}
UTC时间: {datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")}
ISO格式: {dt.isoformat()}
星期: {dt.strftime("%A")}
"""
            self._result_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"转换成功: {dt}")
        except ValueError as e:
            self._add_log(LogLevel.ERROR, f"无效的时间戳: {str(e)}")
    
    def _date_to_timestamp(self):
        date_str = self._date_input.text().strip()
        if not date_str:
            return
        
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d",
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d",
            "%d/%m/%Y",
        ]
        
        dt = None
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                break
            except ValueError:
                continue
        
        if dt:
            ts = int(dt.timestamp())
            result = f"""日期: {dt.strftime("%Y-%m-%d %H:%M:%S")}
Unix时间戳: {ts}
毫秒时间戳: {ts * 1000}
"""
            self._result_text.setPlainText(result)
            self._add_log(LogLevel.SUCCESS, f"转换成功: {ts}")
        else:
            self._add_log(LogLevel.ERROR, "无法解析日期格式")
    
    def _format_time(self):
        fmt = self._format_input.text()
        now = datetime.now()
        
        try:
            formatted = now.strftime(fmt)
            self._result_text.setPlainText(f"格式化结果: {formatted}")
            self._add_log(LogLevel.SUCCESS, f"格式化成功")
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"格式化失败: {str(e)}")
    
    def _do_scan(self):
        self._refresh_time()


@register_module("diff_tool")
class DiffToolWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("diff_tool", "差异对比")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        input_layout = QHBoxLayout()
        
        left_group = QGroupBox("文本A")
        left_layout = QVBoxLayout(left_group)
        self._left_text = QPlainTextEdit()
        self._left_text.setPlaceholderText("输入文本A...")
        left_layout.addWidget(self._left_text)
        input_layout.addWidget(left_group)
        
        right_group = QGroupBox("文本B")
        right_layout = QVBoxLayout(right_group)
        self._right_text = QPlainTextEdit()
        self._right_text.setPlaceholderText("输入文本B...")
        right_layout.addWidget(self._right_text)
        input_layout.addWidget(right_group)
        
        layout.addLayout(input_layout)
        
        options_layout = QHBoxLayout()
        
        self._ignore_case = QCheckBox("忽略大小写")
        self._ignore_whitespace = QCheckBox("忽略空白")
        self._line_by_line = QCheckBox("逐行对比")
        self._line_by_line.setChecked(True)
        
        options_layout.addWidget(self._ignore_case)
        options_layout.addWidget(self._ignore_whitespace)
        options_layout.addWidget(self._line_by_line)
        options_layout.addStretch()
        layout.addLayout(options_layout)
        
        btn_layout = QHBoxLayout()
        
        compare_btn = QPushButton("对比")
        compare_btn.clicked.connect(self._compare)
        
        swap_btn = QPushButton("交换")
        swap_btn.setObjectName("secondaryButton")
        swap_btn.clicked.connect(self._swap)
        
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("secondaryButton")
        clear_btn.clicked.connect(self._clear)
        
        btn_layout.addWidget(compare_btn)
        btn_layout.addWidget(swap_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        result_group = QGroupBox("对比结果")
        result_layout = QVBoxLayout(result_group)
        
        self._result_table = QTableWidget()
        self._result_table.setColumnCount(3)
        self._result_table.setHorizontalHeaderLabels(["状态", "文本A", "文本B"])
        self._result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._result_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        result_layout.addWidget(self._result_table)
        
        self._stats_label = QLabel()
        result_layout.addWidget(self._stats_label)
        
        layout.addWidget(result_group)
        
        return widget
    
    def _compare(self):
        self._result_table.setRowCount(0)
        
        text_a = self._left_text.toPlainText()
        text_b = self._right_text.toPlainText()
        
        if self._ignore_case.isChecked():
            text_a = text_a.lower()
            text_b = text_b.lower()
        
        if self._ignore_whitespace.isChecked():
            text_a = re.sub(r'\s+', ' ', text_a).strip()
            text_b = re.sub(r'\s+', ' ', text_b).strip()
        
        if self._line_by_line.isChecked():
            lines_a = text_a.split('\n')
            lines_b = text_b.split('\n')
            
            added = 0
            removed = 0
            modified = 0
            unchanged = 0
            
            max_lines = max(len(lines_a), len(lines_b))
            
            for i in range(max_lines):
                line_a = lines_a[i] if i < len(lines_a) else ""
                line_b = lines_b[i] if i < len(lines_b) else ""
                
                if not line_a and line_b:
                    status = "新增"
                    added += 1
                elif line_a and not line_b:
                    status = "删除"
                    removed += 1
                elif line_a == line_b:
                    status = "相同"
                    unchanged += 1
                else:
                    status = "修改"
                    modified += 1
                
                row = self._result_table.rowCount()
                self._result_table.insertRow(row)
                self._result_table.setItem(row, 0, QTableWidgetItem(status))
                self._result_table.setItem(row, 1, QTableWidgetItem(line_a))
                self._result_table.setItem(row, 2, QTableWidgetItem(line_b))
            
            self._stats_label.setText(
                f"统计: 相同 {unchanged} | 修改 {modified} | 新增 {added} | 删除 {removed}"
            )
        else:
            if text_a == text_b:
                self._stats_label.setText("文本完全相同")
                self._add_log(LogLevel.SUCCESS, "文本完全相同")
            else:
                self._stats_label.setText("文本存在差异")
                self._add_log(LogLevel.WARNING, "文本存在差异")
        
        self._add_log(LogLevel.INFO, "对比完成")
    
    def _swap(self):
        temp = self._left_text.toPlainText()
        self._left_text.setPlainText(self._right_text.toPlainText())
        self._right_text.setPlainText(temp)
        self._add_log(LogLevel.INFO, "已交换文本")
    
    def _clear(self):
        self._left_text.clear()
        self._right_text.clear()
        self._result_table.setRowCount(0)
        self._stats_label.setText("")
        self._add_log(LogLevel.INFO, "已清空")
    
    def _do_scan(self):
        self._compare()
