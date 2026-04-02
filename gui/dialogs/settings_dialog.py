import json
import os
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QWidget, QFormLayout, QLineEdit, QSpinBox,
    QCheckBox, QComboBox, QGroupBox, QFileDialog, QMessageBox,
    QListView
)
from PyQt6.QtCore import Qt
from gui.widgets.styled_widgets import setup_combo_style

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.json")

DEFAULT_CONFIG = {
    "theme": "dark",
    "language": "zh_CN",
    "check_update": True,
    "restore_session": True,
    "threads": 20,
    "timeout": 30,
    "retry": 3,
    "delay": 0,
    "auto_save": True,
    "show_progress": True,
    "proxy_enabled": False,
    "http_proxy": "",
    "https_proxy": "",
    "socks_proxy": "",
    "nmap_path": "",
    "sqlmap_path": ""
}


def load_config() -> dict:
    config_path = os.path.abspath(CONFIG_FILE)
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> bool:
    config_path = os.path.abspath(CONFIG_FILE)
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"保存配置失败: {e}")
        return False


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._config = load_config()
        self.setWindowTitle("设置")
        self.setMinimumSize(600, 500)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        tabs = QTabWidget()
        
        general_tab = self._create_general_tab()
        tabs.addTab(general_tab, "常规")
        
        scan_tab = self._create_scan_tab()
        tabs.addTab(scan_tab, "扫描")
        
        proxy_tab = self._create_proxy_tab()
        tabs.addTab(proxy_tab, "代理")
        
        tools_tab = self._create_tools_tab()
        tabs.addTab(tools_tab, "工具")
        
        layout.addWidget(tabs)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        save_btn = QPushButton("保存")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_settings)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
    
    def _create_general_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        appearance_group = QGroupBox("外观")
        form_layout = QFormLayout(appearance_group)
        
        self._lang_combo = QComboBox()
        self._setup_combo(self._lang_combo, ["简体中文", "English"])
        self._lang_combo.setCurrentIndex(0 if self._config.get("language") == "zh_CN" else 1)
        form_layout.addRow("语言:", self._lang_combo)
        
        layout.addWidget(appearance_group)
        
        startup_group = QGroupBox("启动")
        startup_layout = QVBoxLayout(startup_group)
        
        self._check_update_check = QCheckBox("启动时检查更新")
        self._check_update_check.setChecked(self._config.get("check_update", True))
        startup_layout.addWidget(self._check_update_check)
        
        self._restore_session_check = QCheckBox("恢复上次会话")
        self._restore_session_check.setChecked(self._config.get("restore_session", True))
        startup_layout.addWidget(self._restore_session_check)
        
        layout.addWidget(startup_group)
        
        layout.addStretch()
        return widget
    
    def _create_scan_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        scan_group = QGroupBox("扫描设置")
        form_layout = QFormLayout(scan_group)
        
        self._threads_spin = QSpinBox()
        self._threads_spin.setRange(1, 100)
        self._threads_spin.setValue(self._config.get("threads", 20))
        form_layout.addRow("并发线程:", self._threads_spin)
        
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 300)
        self._timeout_spin.setValue(self._config.get("timeout", 30))
        self._timeout_spin.setSuffix(" 秒")
        form_layout.addRow("超时时间:", self._timeout_spin)
        
        self._retry_spin = QSpinBox()
        self._retry_spin.setRange(0, 10)
        self._retry_spin.setValue(self._config.get("retry", 3))
        form_layout.addRow("重试次数:", self._retry_spin)
        
        self._delay_spin = QSpinBox()
        self._delay_spin.setRange(0, 10000)
        self._delay_spin.setValue(self._config.get("delay", 0))
        self._delay_spin.setSuffix(" 毫秒")
        form_layout.addRow("请求延迟:", self._delay_spin)
        
        layout.addWidget(scan_group)
        
        options_group = QGroupBox("扫描选项")
        options_layout = QVBoxLayout(options_group)
        
        self._auto_save_check = QCheckBox("自动保存扫描结果")
        self._auto_save_check.setChecked(self._config.get("auto_save", True))
        options_layout.addWidget(self._auto_save_check)
        
        self._show_progress_check = QCheckBox("显示详细进度")
        self._show_progress_check.setChecked(self._config.get("show_progress", True))
        options_layout.addWidget(self._show_progress_check)
        
        layout.addWidget(options_group)
        
        layout.addStretch()
        return widget
    
    def _create_proxy_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        proxy_group = QGroupBox("代理设置")
        form_layout = QFormLayout(proxy_group)
        
        self._proxy_enabled_check = QCheckBox("启用代理")
        self._proxy_enabled_check.setChecked(self._config.get("proxy_enabled", False))
        form_layout.addRow(self._proxy_enabled_check)
        
        self._http_proxy_input = QLineEdit()
        self._http_proxy_input.setText(self._config.get("http_proxy", ""))
        self._http_proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        form_layout.addRow("HTTP代理:", self._http_proxy_input)
        
        self._https_proxy_input = QLineEdit()
        self._https_proxy_input.setText(self._config.get("https_proxy", ""))
        self._https_proxy_input.setPlaceholderText("http://127.0.0.1:8080")
        form_layout.addRow("HTTPS代理:", self._https_proxy_input)
        
        self._socks_proxy_input = QLineEdit()
        self._socks_proxy_input.setText(self._config.get("socks_proxy", ""))
        self._socks_proxy_input.setPlaceholderText("socks5://127.0.0.1:1080")
        form_layout.addRow("SOCKS代理:", self._socks_proxy_input)
        
        layout.addWidget(proxy_group)
        
        layout.addStretch()
        return widget
    
    def _create_tools_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        
        tools_group = QGroupBox("工具路径")
        form_layout = QFormLayout(tools_group)
        
        self._nmap_path_input = QLineEdit()
        self._nmap_path_input.setText(self._config.get("nmap_path", ""))
        self._nmap_path_input.setPlaceholderText("自动检测")
        browse_btn = QPushButton("浏览")
        browse_btn.setObjectName("secondaryButton")
        browse_btn.setFixedWidth(60)
        browse_btn.clicked.connect(lambda: self._browse_tool(self._nmap_path_input))
        nmap_layout = QHBoxLayout()
        nmap_layout.addWidget(self._nmap_path_input)
        nmap_layout.addWidget(browse_btn)
        form_layout.addRow("Nmap:", nmap_layout)
        
        self._sqlmap_path_input = QLineEdit()
        self._sqlmap_path_input.setText(self._config.get("sqlmap_path", ""))
        self._sqlmap_path_input.setPlaceholderText("自动检测")
        browse_btn2 = QPushButton("浏览")
        browse_btn2.setObjectName("secondaryButton")
        browse_btn2.setFixedWidth(60)
        browse_btn2.clicked.connect(lambda: self._browse_tool(self._sqlmap_path_input))
        sqlmap_layout = QHBoxLayout()
        sqlmap_layout.addWidget(self._sqlmap_path_input)
        sqlmap_layout.addWidget(browse_btn2)
        form_layout.addRow("SQLMap:", sqlmap_layout)
        
        layout.addWidget(tools_group)
        
        layout.addStretch()
        return widget
    
    def _setup_combo(self, combo: QComboBox, items: list):
        combo.setView(QListView())
        combo.addItems(items)
        setup_combo_style(combo)
    
    def _browse_tool(self, input_widget: QLineEdit):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择工具路径")
        if file_path:
            input_widget.setText(file_path)
    
    def _save_settings(self):
        old_language = self._config.get("language", "zh_CN")
        
        config = {
            "language": "zh_CN" if self._lang_combo.currentIndex() == 0 else "en",
            "check_update": self._check_update_check.isChecked(),
            "restore_session": self._restore_session_check.isChecked(),
            "threads": self._threads_spin.value(),
            "timeout": self._timeout_spin.value(),
            "retry": self._retry_spin.value(),
            "delay": self._delay_spin.value(),
            "auto_save": self._auto_save_check.isChecked(),
            "show_progress": self._show_progress_check.isChecked(),
            "proxy_enabled": self._proxy_enabled_check.isChecked(),
            "http_proxy": self._http_proxy_input.text(),
            "https_proxy": self._https_proxy_input.text(),
            "socks_proxy": self._socks_proxy_input.text(),
            "nmap_path": self._nmap_path_input.text(),
            "sqlmap_path": self._sqlmap_path_input.text()
        }
        
        if save_config(config):
            self._config = config
            
            from core.i18n import set_language
            set_language(config["language"])
            
            if old_language != config["language"]:
                QMessageBox.information(
                    self, 
                    "成功" if config["language"] == "zh_CN" else "Success",
                    "设置已保存\n\n语言更改需要重启应用才能完全生效" if config["language"] == "zh_CN" 
                    else "Settings saved\n\nLanguage change requires application restart"
                )
            else:
                QMessageBox.information(self, "成功", "设置已保存")
            
            self.accept()
        else:
            QMessageBox.warning(self, "错误", "保存设置失败")


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于")
        self.setFixedSize(400, 300)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        
        title = QLabel("WebSec Toolkit")
        title.setObjectName("titleLabel")
        title.setStyleSheet("font-size: 24px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        version = QLabel("版本 v1.3.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(version)
        
        desc = QLabel(
            "一个功能强大的Web安全集成测试工具\n"
            "集成了信息收集、漏洞扫描、内网渗透等多种安全测试模块"
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        layout.addStretch()
        
        copyright_label = QLabel("© 2026 Security Team")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(copyright_label)
        
        close_btn = QPushButton("关闭")
        close_btn.setFixedWidth(80)
        close_btn.clicked.connect(self.accept)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)


class NewProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._project_data = {}
        self.setWindowTitle("新建项目")
        self.setMinimumSize(450, 300)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("输入项目名称")
        form_layout.addRow("项目名称:", self._name_input)
        
        self._desc_input = QLineEdit()
        self._desc_input.setPlaceholderText("输入项目描述（可选）")
        form_layout.addRow("描述:", self._desc_input)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("输入目标地址，多个用逗号分隔")
        form_layout.addRow("目标:", self._target_input)
        
        layout.addLayout(form_layout)
        
        layout.addStretch()
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        create_btn = QPushButton("创建")
        create_btn.setFixedWidth(80)
        create_btn.clicked.connect(self._create_project)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.setFixedWidth(80)
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(create_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
    
    def _create_project(self):
        name = self._name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "警告", "请输入项目名称")
            return
        
        self._project_data = {
            "name": name,
            "description": self._desc_input.text().strip(),
            "target": self._target_input.text().strip()
        }
        self.accept()
    
    def get_project_data(self) -> dict:
        return self._project_data
