import sys
from typing import Dict, Optional
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QStackedWidget, QStatusBar, QMenuBar, QMenu,
    QToolBar, QMessageBox, QApplication, QSplitter, QPushButton
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QAction, QIcon, QKeySequence, QFont

from gui.gui_styles import StyleSheet
from gui.widgets import Sidebar, StatCard
from gui.widgets.notification import NotificationManager
from gui.dialogs import SettingsDialog, AboutDialog


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._module_widgets: Dict[str, QWidget] = {}
        self._setup_window()
        self._setup_menubar()
        self._setup_toolbar()
        self._setup_ui()
        self._setup_statusbar()
        self._load_modules()
    
    def _setup_window(self):
        self.setWindowTitle("WebSec Toolkit - Web安全集成工具")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)
        self.setStyleSheet(StyleSheet.THEME)
        
        self.setFont(QFont("Microsoft YaHei", 10))
    
    def _setup_menubar(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("文件")
        
        new_project_action = QAction("新建项目", self)
        new_project_action.setShortcut(QKeySequence.StandardKey.New)
        new_project_action.triggered.connect(self._new_project)
        file_menu.addAction(new_project_action)
        
        open_project_action = QAction("打开项目", self)
        open_project_action.setShortcut(QKeySequence.StandardKey.Open)
        open_project_action.triggered.connect(self._open_project)
        file_menu.addAction(open_project_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("导出报告", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        export_action.triggered.connect(self._export_report)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("退出", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        edit_menu = menubar.addMenu("编辑")
        
        settings_action = QAction("设置", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self._show_settings)
        edit_menu.addAction(settings_action)
        
        tools_menu = menubar.addMenu("工具")
        
        tool_manager_action = QAction("工具管理", self)
        tool_manager_action.triggered.connect(self._show_tool_manager)
        tools_menu.addAction(tool_manager_action)
        
        wordlist_manager_action = QAction("字典管理", self)
        wordlist_manager_action.triggered.connect(self._show_wordlist_manager)
        tools_menu.addAction(wordlist_manager_action)
        
        help_menu = menubar.addMenu("帮助")
        
        about_action = QAction("关于", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
        docs_action = QAction("文档", self)
        docs_action.setShortcut(QKeySequence("F1"))
        docs_action.triggered.connect(self._show_docs)
        help_menu.addAction(docs_action)
    
    def _setup_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        toolbar.addAction("新建项目", self._new_project)
        toolbar.addAction("打开项目", self._open_project)
        toolbar.addSeparator()
        toolbar.addAction("开始扫描", self._start_scan)
        toolbar.addAction("停止扫描", self._stop_scan)
        toolbar.addSeparator()
        toolbar.addAction("导出报告", self._export_report)
        toolbar.addAction("设置", self._show_settings)
    
    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        self._sidebar = Sidebar()
        self._sidebar.module_selected.connect(self._on_module_selected)
        main_layout.addWidget(self._sidebar)
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        self._header_frame = self._create_header()
        content_layout.addWidget(self._header_frame)
        
        self._content_stack = QStackedWidget()
        content_layout.addWidget(self._content_stack)
        
        self._home_widget = self._create_home_widget()
        self._content_stack.addWidget(self._home_widget)
        
        main_layout.addWidget(content_widget)
        
        self._notification_manager = NotificationManager(self)
        self._notification_manager.setGeometry(0, 0, self.width(), self.height())
        
        self._current_module_id = None
    
    def _create_header(self) -> QFrame:
        header = QFrame()
        header.setObjectName("titleBar")
        header.setFixedHeight(50)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 0, 20, 0)
        
        self._title_label = QLabel("首页")
        self._title_label.setObjectName("titleLabel")
        layout.addWidget(self._title_label)
        
        layout.addStretch()
        
        project_label = QLabel("当前项目: ")
        
        self._project_name_label = QLabel("未选择")
        
        layout.addWidget(project_label)
        layout.addWidget(self._project_name_label)
        
        return header
    
    def _create_home_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        welcome_label = QLabel("欢迎使用 WebSec Toolkit")
        welcome_label.setStyleSheet("font-size: 28px; font-weight: bold;")
        layout.addWidget(welcome_label)
        
        desc_label = QLabel("一个功能强大的Web安全集成测试工具，集成了信息收集、漏洞扫描、内网渗透等多种安全测试模块。")
        desc_label.setStyleSheet("font-size: 14px; margin-bottom: 20px;")
        desc_label.setWordWrap(True)
        layout.addWidget(desc_label)
        
        stats_frame = QFrame()
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setSpacing(15)
        
        self._stat_projects = StatCard("项目总数", "0", "#89B4FA")
        self._stat_targets = StatCard("目标数量", "0", "#A6E3A1")
        self._stat_vulns = StatCard("发现漏洞", "0", "#F38BA8")
        self._stat_scans = StatCard("扫描次数", "0", "#F9E2AF")
        
        stats_layout.addWidget(self._stat_projects)
        stats_layout.addWidget(self._stat_targets)
        stats_layout.addWidget(self._stat_vulns)
        stats_layout.addWidget(self._stat_scans)
        
        layout.addWidget(stats_frame)
        
        quick_start_frame = QFrame()
        quick_start_frame.setObjectName("card")
        quick_start_layout = QVBoxLayout(quick_start_frame)
        quick_start_layout.setContentsMargins(20, 20, 20, 20)
        
        quick_title = QLabel("快速开始")
        quick_title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        quick_start_layout.addWidget(quick_title)
        
        modules_grid = QHBoxLayout()
        modules_grid.setSpacing(10)
        
        quick_modules = [
            ("端口扫描", "快速扫描目标开放端口", "port_scanner"),
            ("SQL注入", "检测SQL注入漏洞", "sqli"),
            ("XSS测试", "检测跨站脚本漏洞", "xss"),
            ("子域名枚举", "发现目标子域名", "subdomain"),
        ]
        
        for name, desc, module_id in quick_modules:
            btn = QPushButton()
            btn.setObjectName("secondaryButton")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setLayout(QVBoxLayout())
            btn.layout().setContentsMargins(0, 0, 0, 0)
            btn.layout().setSpacing(2)
            
            btn_name = QLabel(name)
            btn_name.setStyleSheet("font-size: 14px; font-weight: bold;")
            
            btn_desc = QLabel(desc)
            btn_desc.setStyleSheet("font-size: 11px;")
            
            btn.layout().addWidget(btn_name)
            btn.layout().addWidget(btn_desc)
            
            btn.clicked.connect(lambda checked, mid=module_id: self._sidebar.select_module(mid))
            
            modules_grid.addWidget(btn)
        
        quick_start_layout.addLayout(modules_grid)
        layout.addWidget(quick_start_frame)
        
        recent_frame = QFrame()
        recent_frame.setObjectName("card")
        recent_layout = QVBoxLayout(recent_frame)
        recent_layout.setContentsMargins(20, 20, 20, 20)
        
        recent_title = QLabel("最近项目")
        recent_title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        recent_layout.addWidget(recent_title)
        
        no_project_label = QLabel("暂无项目，点击\"新建项目\"开始")
        no_project_label.setStyleSheet("padding: 20px;")
        no_project_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        recent_layout.addWidget(no_project_label)
        
        layout.addWidget(recent_frame)
        
        layout.addStretch()
        
        return widget
    
    def _setup_statusbar(self):
        statusbar = QStatusBar()
        self.setStatusBar(statusbar)
        
        self._status_label = QLabel("就绪")
        statusbar.addWidget(self._status_label)
        
        statusbar.addPermanentWidget(QLabel("工具状态: "))
        
        tool_status = QLabel("已就绪")
        statusbar.addPermanentWidget(tool_status)
    
    def _load_modules(self):
        from modules import get_module_widget
        
        module_ids = [
            "ai_assistant",
            "port_scanner", "subdomain", "directory", "fingerprint", 
            "ssl_analyzer", "email_collector",
            "sqli", "xss", "ssrf", "rce", "xxe", "ssti", "lfi_rfi",
            "csrf", "api_security", "framework", "auth_vuln", "file_vuln",
            "cache_vuln", "http_smuggling", "open_redirect", "clickjacking",
            "business_logic", "jwt_security", "supply_chain", "prototype_pollution",
            "cloud_security", "websocket", "ai_security",
            "internal_info", "credential", "lateral_move", "privilege",
            "persistence", "tunnel", "domain_attack", "adcs_attack",
            "evasion", "exchange", "sharepoint",
            "hash_identify", "hash_crack", "online_brute", "dict_generator",
            "cve_search", "poc_manager", "batch_scan", "exploit_search",
            "reverse_shell", "webshell", "msf_payload", "encoder",
            "payload_evasion", "phishing_file",
            "http_proxy", "request_builder", "repeater", "intruder",
            "base_encoder", "url_encoder", "hash_calc", "jwt_encoder",
            "crypto", "classic_cipher",
            "password_gen", "username_gen", "dir_gen", "subdomain_gen", "dict_manager",
            "report_gen", "project_manage", "data_export", "vuln_stats", "history",
            "ip_tool", "http_tool", "json_tool", "regex_tool", "time_tool", "diff_tool",
        ]
        
        for module_id in module_ids:
            widget = get_module_widget(module_id)
            if widget:
                self._module_widgets[module_id] = widget
                self._content_stack.addWidget(widget)
                
                widget.module_running_changed.connect(self._on_module_running_changed)
                widget.module_completed.connect(self._on_module_completed)
    
    def _on_module_selected(self, module_id: str):
        if module_id in self._module_widgets:
            widget = self._module_widgets[module_id]
            self._content_stack.setCurrentWidget(widget)
            self._current_module_id = module_id
            
            if self._sidebar.is_module_running(module_id):
                self._sidebar.clear_running_status(module_id)
            
            module_names = {
                "ai_assistant": "AI助手",
                "port_scanner": "端口扫描",
                "subdomain": "子域名枚举",
                "directory": "目录扫描",
                "fingerprint": "指纹识别",
                "ssl_analyzer": "SSL分析",
                "email_collector": "邮箱收集",
                "sqli": "SQL注入检测",
                "xss": "XSS测试",
                "ssrf": "SSRF检测",
                "rce": "RCE检测",
                "xxe": "XXE检测",
                "ssti": "SSTI检测",
                "lfi_rfi": "文件包含检测",
                "csrf": "CSRF检测",
                "api_security": "API安全测试",
                "framework": "框架漏洞扫描",
                "auth_vuln": "认证漏洞测试",
                "file_vuln": "文件漏洞检测",
                "cache_vuln": "缓存漏洞检测",
                "http_smuggling": "HTTP请求走私",
                "open_redirect": "开放重定向检测",
                "clickjacking": "点击劫持检测",
                "business_logic": "业务逻辑漏洞",
                "jwt_security": "JWT安全测试",
                "supply_chain": "供应链安全",
                "prototype_pollution": "原型链污染",
                "cloud_security": "云安全检测",
                "websocket": "WebSocket安全",
                "ai_security": "AI安全测试",
                "internal_info": "内网信息搜集",
                "credential": "凭据窃取",
                "lateral_move": "横向移动",
                "privilege": "权限提升",
                "persistence": "权限维持",
                "tunnel": "隧道代理",
                "domain_attack": "域攻击",
                "adcs_attack": "ADCS攻击",
                "evasion": "免杀绕过",
                "exchange": "Exchange攻击",
                "sharepoint": "SharePoint攻击",
                "hash_identify": "Hash识别",
                "hash_crack": "Hash破解",
                "online_brute": "在线爆破",
                "dict_generator": "字典生成",
                "cve_search": "CVE查询",
                "poc_manager": "PoC管理",
                "batch_scan": "批量扫描",
                "exploit_search": "Exploit搜索",
                "reverse_shell": "Reverse Shell生成",
                "webshell": "WebShell生成",
                "msf_payload": "MSF Payload生成",
                "encoder": "编码混淆",
                "payload_evasion": "免杀处理",
                "phishing_file": "钓鱼文件生成",
                "http_proxy": "HTTP代理",
                "request_builder": "请求构造器",
                "repeater": "请求重放",
                "intruder": "批量请求",
                "base_encoder": "Base编码",
                "url_encoder": "URL编码",
                "hash_calc": "Hash计算",
                "jwt_encoder": "JWT处理",
                "crypto": "加密解密",
                "classic_cipher": "经典密码",
                "password_gen": "密码字典生成",
                "username_gen": "用户名字典",
                "dir_gen": "目录字典",
                "subdomain_gen": "子域名字典",
                "dict_manager": "字典管理",
                "report_gen": "报告生成",
                "project_manage": "项目管理",
                "data_export": "数据导出",
                "vuln_stats": "漏洞统计",
                "history": "历史记录",
                "ip_tool": "IP工具",
                "http_tool": "HTTP工具",
                "json_tool": "JSON工具",
                "regex_tool": "正则工具",
                "time_tool": "时间工具",
                "diff_tool": "文本对比",
                "settings": "设置",
            }
            self._title_label.setText(module_names.get(module_id, module_id))
        else:
            self._content_stack.setCurrentWidget(self._home_widget)
            self._title_label.setText("首页")
    
    def _new_project(self):
        from gui.dialogs import NewProjectDialog
        dialog = NewProjectDialog(self)
        if dialog.exec():
            project_data = dialog.get_project_data()
            self._project_name_label.setText(project_data.get("name", "新项目"))
            self._status_label.setText(f"已创建项目: {project_data.get('name')}")
    
    def _open_project(self):
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开项目", "", "项目文件 (*.json);;所有文件"
        )
        if file_path:
            self._project_name_label.setText(file_path.split('/')[-1].split('\\')[-1])
            self._status_label.setText(f"已打开项目: {file_path}")
    
    def _export_report(self):
        from gui.dialogs.report_dialog import ReportPreviewDialog
        
        stats_data = {
            "projects": self._stat_projects._value_label.text(),
            "targets": self._stat_targets._value_label.text(),
            "vulnerabilities": self._stat_vulns._value_label.text(),
            "scans": self._stat_scans._value_label.text()
        }
        
        vulnerabilities = [
            {
                "name": "SQL注入漏洞",
                "severity": "高危",
                "target": "http://example.com/page?id=1",
                "description": "在page页面的id参数发现SQL注入漏洞，攻击者可获取数据库敏感信息"
            },
            {
                "name": "XSS跨站脚本",
                "severity": "中危",
                "target": "http://example.com/search?q=test",
                "description": "在search页面的q参数发现反射型XSS漏洞"
            },
            {
                "name": "敏感信息泄露",
                "severity": "低危",
                "target": "http://example.com/config.php.bak",
                "description": "发现备份文件泄露，包含数据库配置信息"
            }
        ]
        
        dialog = ReportPreviewDialog(stats_data, vulnerabilities, self)
        dialog.exec()
    
    def _start_scan(self):
        self._status_label.setText("开始扫描...")
    
    def _stop_scan(self):
        self._status_label.setText("停止扫描...")
    
    def _show_settings(self):
        dialog = SettingsDialog(self)
        dialog.exec()
    
    def _show_about(self):
        dialog = AboutDialog(self)
        dialog.exec()
    
    def _show_tool_manager(self):
        from gui.dialogs import ToolManagerDialog
        dialog = ToolManagerDialog(self)
        dialog.exec()
    
    def _show_wordlist_manager(self):
        from gui.dialogs import WordlistManagerDialog
        dialog = WordlistManagerDialog(self)
        dialog.exec()
    
    def _show_docs(self):
        self._status_label.setText("打开文档...")
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, '_notification_manager'):
            self._notification_manager.setGeometry(0, 0, self.width(), self.height())
    
    def _on_module_running_changed(self, module_id: str, running: bool):
        self._sidebar.set_module_running(module_id, running)
        
        if running:
            self._status_label.setText(f"{module_id} 正在运行...")
        else:
            self._status_label.setText("就绪")
    
    def _on_module_completed(self, module_id: str, module_name: str, success: bool):
        self._sidebar.clear_running_status(module_id)
        
        if success:
            self._notification_manager.show_notification(
                f"{module_name} 完成",
                "模块运行成功完成",
                True
            )
        else:
            self._notification_manager.show_notification(
                f"{module_name} 结束",
                "模块运行已结束",
                False
            )
