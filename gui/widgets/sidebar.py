from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QSpacerItem, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QRect, QEasingCurve
from PyQt6.QtGui import QFont, QColor


MODULE_CATEGORIES = {
    "首页": [
        ("首页", "home"),
    ],
    "AI助手": [
        ("AI助手", "ai_assistant"),
    ],
    "信息收集": [
        ("端口扫描", "port_scanner"),
        ("子域名枚举", "subdomain"),
        ("目录扫描", "directory"),
        ("指纹识别", "fingerprint"),
        ("SSL分析", "ssl_analyzer"),
        ("邮箱收集", "email_collector"),
    ],
    "Web安全": [
        ("SQL注入", "sqli"),
        ("XSS测试", "xss"),
        ("SSRF检测", "ssrf"),
        ("RCE检测", "rce"),
        ("XXE检测", "xxe"),
        ("SSTI检测", "ssti"),
        ("文件包含", "lfi_rfi"),
        ("CSRF检测", "csrf"),
        ("API安全", "api_security"),
        ("框架漏洞", "framework"),
        ("认证漏洞", "auth_vuln"),
        ("文件漏洞", "file_vuln"),
        ("缓存漏洞", "cache_vuln"),
        ("请求走私", "http_smuggling"),
        ("开放重定向", "open_redirect"),
        ("点击劫持", "clickjacking"),
        ("业务逻辑", "business_logic"),
        ("JWT安全", "jwt_security"),
        ("供应链", "supply_chain"),
        ("原型污染", "prototype_pollution"),
        ("云安全", "cloud_security"),
        ("WebSocket", "websocket"),
        ("AI安全", "ai_security"),
    ],
    "内网渗透": [
        ("信息搜集", "internal_info"),
        ("凭据窃取", "credential"),
        ("横向移动", "lateral_move"),
        ("权限提升", "privilege"),
        ("权限维持", "persistence"),
        ("隧道代理", "tunnel"),
        ("域攻击", "domain_attack"),
        ("ADCS攻击", "adcs_attack"),
        ("免杀绕过", "evasion"),
        ("Exchange", "exchange"),
        ("SharePoint", "sharepoint"),
    ],
    "密码攻击": [
        ("Hash识别", "hash_identify"),
        ("Hash破解", "hash_crack"),
        ("在线爆破", "online_brute"),
        ("字典生成", "dict_generator"),
    ],
    "漏洞扫描": [
        ("CVE查询", "cve_search"),
        ("PoC管理", "poc_manager"),
        ("批量扫描", "batch_scan"),
        ("Exploit搜索", "exploit_search"),
    ],
    "Payload生成": [
        ("Reverse Shell", "reverse_shell"),
        ("WebShell", "webshell"),
        ("MSF Payload", "msf_payload"),
        ("编码混淆", "encoder"),
        ("免杀处理", "payload_evasion"),
        ("钓鱼文件", "phishing_file"),
    ],
    "代理工具": [
        ("HTTP代理", "http_proxy"),
        ("请求构造", "request_builder"),
        ("请求重放", "repeater"),
        ("批量请求", "intruder"),
    ],
    "编码转换": [
        ("Base编码", "base_encoder"),
        ("URL编码", "url_encoder"),
        ("Hash计算", "hash_calc"),
        ("JWT处理", "jwt_encoder"),
        ("加密解密", "crypto"),
        ("经典密码", "classic_cipher"),
    ],
    "字典生成": [
        ("密码字典", "password_gen"),
        ("用户名字典", "username_gen"),
        ("目录字典", "dir_gen"),
        ("子域名字典", "subdomain_gen"),
        ("字典管理", "dict_manager"),
    ],
    "报告管理": [
        ("报告生成", "report_gen"),
        ("项目管理", "project_manage"),
        ("数据导出", "data_export"),
        ("漏洞统计", "vuln_stats"),
        ("历史记录", "history"),
    ],
    "实用工具": [
        ("IP工具", "ip_tool"),
        ("HTTP工具", "http_tool"),
        ("JSON工具", "json_tool"),
        ("正则工具", "regex_tool"),
        ("时间工具", "time_tool"),
        ("文本对比", "diff_tool"),
    ],
}


class RunningIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(8, 8)
        self._opacity = 1.0
        self._increasing = False
        
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate)
        
        self._color = QColor("#22C55E")
    
    def start_animation(self):
        self._timer.start(50)
    
    def stop_animation(self):
        self._timer.stop()
        self._opacity = 1.0
        self.update()
    
    def _animate(self):
        if self._increasing:
            self._opacity += 0.05
            if self._opacity >= 1.0:
                self._opacity = 1.0
                self._increasing = False
        else:
            self._opacity -= 0.05
            if self._opacity <= 0.3:
                self._opacity = 0.3
                self._increasing = True
        self.update()
    
    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter, QBrush, QPen
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        color = QColor(self._color)
        color.setAlphaF(self._opacity)
        
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(0, 0, 8, 8)


class NavButton(QPushButton):
    clicked_with_id = pyqtSignal(str)

    def __init__(self, text: str, module_id: str = "", parent=None):
        super().__init__(parent)
        self.module_id = module_id
        self._text = text
        self._is_running = False
        self._indicator = None
        self._setup_ui()
        self.clicked.connect(self._on_clicked)

    def _setup_ui(self):
        self.setObjectName("navButton")
        self.setCheckable(True)
        self.setFixedHeight(42)
        self.setMinimumWidth(200)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._update_text()
        
        self.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding-left: 10px;
                border: none;
                background: transparent;
                color: #374151;
            }
            QPushButton:hover {
                background-color: rgba(0, 0, 0, 0.05);
            }
            QPushButton:checked {
                background-color: #DBEAFE;
                border-left: 3px solid #3B82F6;
                color: #1E40AF;
            }
        """)

    def _update_text(self):
        if self._is_running:
            self.setText(f"  {self._text}  ●")
        else:
            self.setText(f"  {self._text}")

    def set_running(self, running: bool):
        self._is_running = running
        self._update_text()
        
        if running:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #DCFCE7;
                    border-left: 3px solid #22C55E;
                    color: #166534;
                }
            """)
        else:
            self.setStyleSheet("")
    
    def _on_clicked(self):
        self.clicked_with_id.emit(self.module_id)


class Sidebar(QWidget):
    module_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._buttons = {}
        self._running_modules = set()
        self._setup_ui()

    def _setup_ui(self):
        self.setObjectName("sidebar")
        self.setFixedWidth(250)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        header = QFrame()
        header.setStyleSheet("background: transparent;")
        header.setFixedHeight(70)
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 15, 20, 15)

        title = QLabel("WebSec Toolkit")
        title.setObjectName("titleLabel")

        version = QLabel("v1.01")
        version.setStyleSheet("font-size: 11px;")

        header_layout.addWidget(title)
        header_layout.addWidget(version)
        main_layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: transparent;
                width: 6px;
            }
            QScrollBar::handle:vertical {
                background: #D1D5DB;
                border-radius: 3px;
            }
            QScrollBar::handle:vertical:hover {
                background: #9CA3AF;
            }
        """)

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(10, 10, 10, 10)
        scroll_layout.setSpacing(5)

        for category, modules in MODULE_CATEGORIES.items():
            category_label = QLabel(category)
            category_label.setObjectName("categoryLabel")
            category_label.setMinimumHeight(30)
            scroll_layout.addWidget(category_label)

            for module_name, module_id in modules:
                btn = NavButton(module_name, module_id)
                btn.clicked_with_id.connect(self._on_button_clicked)
                self._buttons[module_id] = btn
                scroll_layout.addWidget(btn)

            scroll_layout.addSpacing(10)

        scroll_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))
        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

    def _on_button_clicked(self, module_id: str):
        for btn_id, btn in self._buttons.items():
            btn.setChecked(btn_id == module_id)
        self.module_selected.emit(module_id)

    def select_module(self, module_id: str):
        if module_id in self._buttons:
            btn = self._buttons[module_id]
            btn.setChecked(True)
            self.module_selected.emit(module_id)

    def set_module_running(self, module_id: str, running: bool):
        if module_id in self._buttons:
            self._buttons[module_id].set_running(running)
        
        if running:
            self._running_modules.add(module_id)
        else:
            self._running_modules.discard(module_id)

    def clear_running_status(self, module_id: str):
        if module_id in self._buttons:
            self._buttons[module_id].set_running(False)
        self._running_modules.discard(module_id)

    def is_module_running(self, module_id: str) -> bool:
        return module_id in self._running_modules
