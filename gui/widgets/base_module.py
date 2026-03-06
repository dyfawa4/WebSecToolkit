from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QSpinBox, QFileDialog, QMessageBox, QListView, QDialog,
    QListWidget, QDialogButtonBox, QFormLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QMetaObject
from PyQt6.QtGui import QFont
from typing import Optional, Dict, Any, List, Callable
import threading
import os
import subprocess
from pathlib import Path
from dataclasses import dataclass
from enum import Enum


class LogLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    DEBUG = "DEBUG"


@dataclass
class LogColors:
    COLORS = {
        LogLevel.INFO: "#1E66F5",
        LogLevel.WARNING: "#DF8E1D",
        LogLevel.ERROR: "#D20F39",
        LogLevel.SUCCESS: "#40A02B",
        LogLevel.DEBUG: "#8C8FA1"
    }


class StyleManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
    
    def get_log_color(self, level: LogLevel) -> str:
        return LogColors.COLORS.get(level, "#6C6F85")


_style_manager = StyleManager()


def get_style_manager() -> StyleManager:
    return _style_manager


_tool_manager = None


def get_tool_manager():
    global _tool_manager
    if _tool_manager is None:
        from core.tool_manager import ToolManager
        _tool_manager = ToolManager()
    return _tool_manager


class DictSelectDialog(QDialog):
    def __init__(self, parent=None, dict_type: str = "general"):
        super().__init__(parent)
        self._selected_dict = None
        self._dict_type = dict_type
        self.setWindowTitle("选择字典")
        self.setMinimumSize(500, 400)
        self._setup_ui()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        title = QLabel("选择字典文件")
        title.setObjectName("titleLabel")
        layout.addWidget(title)
        
        tabs = QTabWidget()
        
        builtin_tab = QWidget()
        builtin_layout = QVBoxLayout(builtin_tab)
        
        self._builtin_list = QListWidget()
        self._load_builtin_dicts()
        builtin_layout.addWidget(QLabel("内置字典:"))
        builtin_layout.addWidget(self._builtin_list)
        
        import_btn = QPushButton("导入自定义字典")
        import_btn.setObjectName("secondaryButton")
        import_btn.clicked.connect(self._import_custom_dict)
        builtin_layout.addWidget(import_btn)
        
        tabs.addTab(builtin_tab, "内置字典")
        
        custom_tab = QWidget()
        custom_layout = QVBoxLayout(custom_tab)
        
        self._custom_list = QListWidget()
        custom_layout.addWidget(QLabel("自定义字典:"))
        custom_layout.addWidget(self._custom_list)
        
        add_btn = QPushButton("添加字典文件")
        add_btn.setObjectName("secondaryButton")
        add_btn.clicked.connect(self._add_custom_dict)
        custom_layout.addWidget(add_btn)
        
        tabs.addTab(custom_tab, "自定义字典")
        
        layout.addWidget(tabs)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        select_btn = QPushButton("选择")
        select_btn.clicked.connect(self._on_select)
        
        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(select_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
    
    def _load_builtin_dicts(self):
        builtin_dicts = {
            "general": [
                ("常用密码TOP100", "passwords/common_100.txt", "最常用的100个密码"),
                ("常用密码TOP1000", "passwords/common_1000.txt", "最常用的1000个密码"),
                ("常用用户名", "usernames/common.txt", "常用用户名列表"),
                ("常见目录", "directories/common.txt", "常见Web目录"),
                ("常见子域名", "subdomains/common.txt", "常见子域名前缀"),
            ],
            "password": [
                ("弱密码字典", "passwords/weak.txt", "弱密码集合"),
                ("数字密码", "passwords/numeric.txt", "纯数字密码"),
                ("字母密码", "passwords/alpha.txt", "纯字母密码"),
            ],
            "directory": [
                ("Web目录字典", "directories/web.txt", "常见Web目录"),
                ("备份文件字典", "directories/backup.txt", "常见备份文件名"),
                ("敏感文件字典", "directories/sensitive.txt", "敏感文件路径"),
            ],
            "subdomain": [
                ("子域名字典", "subdomains/common.txt", "常见子域名"),
                ("云服务子域名", "subdomains/cloud.txt", "云服务相关子域名"),
            ]
        }
        
        dicts = builtin_dicts.get(self._dict_type, builtin_dicts["general"])
        for name, path, desc in dicts:
            item_text = f"{name} - {desc}"
            self._builtin_list.addItem(item_text)
            self._builtin_list.setItemData(self._builtin_list.count() - 1, path)
    
    def _import_custom_dict(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self._selected_dict = file_path
            self.accept()
    
    def _add_custom_dict(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "添加字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self._custom_list.addItem(os.path.basename(file_path))
            self._custom_list.setItemData(self._custom_list.count() - 1, file_path)
    
    def _on_select(self):
        if self._builtin_list.currentItem():
            self._selected_dict = self._builtin_list.currentItem().data(Qt.ItemDataRole.UserRole)
            self.accept()
        elif self._custom_list.currentItem():
            self._selected_dict = self._custom_list.currentItem().data(Qt.ItemDataRole.UserRole)
            self.accept()
        else:
            QMessageBox.warning(self, "提示", "请选择一个字典文件")
    
    def get_selected_dict(self) -> Optional[str]:
        return self._selected_dict


class BaseModuleWidget(QWidget):
    log_message = pyqtSignal(str, str)
    scan_started = pyqtSignal()
    scan_finished = pyqtSignal()
    progress_updated = pyqtSignal(int)
    
    COMMON_STYLES = """
        QScrollArea { border: none; }
        QScrollBar:vertical {
            background-color: #F3F4F6;
            width: 8px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background-color: #D1D5DB;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #9CA3AF;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QTabWidget::pane {
            background-color: #FFFFFF;
            border: 1px solid #E5E7EB;
            border-radius: 6px;
        }
        QTabBar::tab {
            background-color: #F3F4F6;
            color: #6B7280;
            padding: 10px 20px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #FFFFFF;
            color: #1F2937;
            border: 1px solid #E5E7EB;
            border-bottom: none;
        }
        QTabBar::tab:hover {
            background-color: #E5E7EB;
            color: #1F2937;
        }
        QTableWidget {
            background-color: #FFFFFF;
            color: #1F2937;
            border: 1px solid #E5E7EB;
            border-radius: 6px;
            gridline-color: #E5E7EB;
        }
        QTableWidget::item {
            padding: 8px;
            border-bottom: 1px solid #E5E7EB;
        }
        QTableWidget::item:selected {
            background-color: #E5E7EB;
        }
        QHeaderView::section {
            background-color: #F9FAFB;
            color: #6B7280;
            padding: 8px;
            border: none;
            border-bottom: 1px solid #E5E7EB;
        }
        QHeaderView::section:horizontal {
            border-right: 1px solid #E5E7EB;
        }
        QHeaderView::section:last:horizontal {
            border-right: none;
        }
        QTextEdit {
            background-color: #FFFFFF;
            color: #1F2937;
            border: 1px solid #E5E7EB;
            border-radius: 6px;
            padding: 10px;
            font-family: Consolas, Monaco, monospace;
            font-size: 10pt;
        }
        QProgressBar {
            background-color: #F3F4F6;
            color: #1F2937;
            border: 1px solid #E5E7EB;
            border-radius: 6px;
            padding: 2px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #4285F4;
            border-radius: 4px;
        }
    """
    
    def __init__(self, module_name: str, parent=None):
        super().__init__(parent)
        self.module_name = module_name
        self._is_scanning = False
        self._results = []
        self._tool_manager = get_tool_manager()
        self._style_manager = get_style_manager()
        self._current_process = None
        self._setup_base_ui()
    
    def _get_available_tools(self) -> List[Dict[str, str]]:
        return self._tool_manager.get_module_tools_info(self.module_name)
    
    def _is_tool_available(self, tool_name: str) -> bool:
        return self._tool_manager.is_tool_available(self.module_name, tool_name)
    
    def _get_tool_path(self, tool_name: str) -> Optional[Path]:
        return self._tool_manager.get_tool_path(self.module_name, tool_name)
    
    def _execute_tool(self, tool_name: str, args: List[str], 
                     capture_output: bool = True) -> subprocess.Popen:
        self._current_process = self._tool_manager.execute_tool(
            self.module_name, tool_name, args
        )
        return self._current_process
    
    def _stop_current_tool(self):
        if self._current_process and self._current_process.poll() is None:
            self._current_process.terminate()
            try:
                self._current_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
            self._current_process = None
    
    def _setup_combo(self, combo: QComboBox, items: list = None):
        combo.setStyleSheet("""
            QComboBox {
                background-color: #FFFFFF;
                color: #1F2937;
                border: 1px solid #D1D5DB;
                border-radius: 6px;
                padding: 8px 12px;
                min-height: 20px;
            }
            QComboBox:hover {
                border-color: #9CA3AF;
            }
            QComboBox:focus {
                border-color: #4285F4;
            }
            QComboBox::drop-down {
                border: none;
                width: 0px;
            }
            QComboBox::down-arrow {
                image: none;
                width: 0px;
                height: 0px;
            }
            QComboBox QAbstractItemView {
                background-color: #FFFFFF;
                color: #1F2937;
                border: 1px solid #E5E7EB;
                selection-background-color: #E5E7EB;
                selection-color: #1F2937;
                outline: none;
            }
            QComboBox QAbstractItemView::item {
                padding: 8px 12px;
                min-height: 24px;
            }
            QComboBox QAbstractItemView::item:hover {
                background-color: #F3F4F6;
            }
        """)
        if items:
            combo.addItems(items)
    
    def _setup_spinbox(self, spinbox: QSpinBox, suffix: str = ""):
        if suffix:
            spinbox.setSuffix(suffix)
    
    def _setup_base_ui(self):
        self._main_layout = QVBoxLayout(self)
        self._main_layout.setContentsMargins(20, 20, 20, 20)
        self._main_layout.setSpacing(15)
        
        self._header = self._create_header()
        self._main_layout.addWidget(self._header)
        
        self._content_splitter = QSplitter(Qt.Orientation.Vertical)
        self._main_layout.addWidget(self._content_splitter, 1)
        
        self._input_panel = self._create_input_panel()
        self._content_splitter.addWidget(self._input_panel)
        
        self._output_panel = self._create_output_panel()
        self._content_splitter.addWidget(self._output_panel)
        
        self._content_splitter.setSizes([300, 400])
    
    def _create_header(self) -> QFrame:
        header = QFrame()
        header.setFixedHeight(60)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        
        title_label = QLabel(self.module_name)
        title_label.setObjectName("titleLabel")
        
        layout.addWidget(title_label)
        layout.addStretch()
        
        self._start_btn = QPushButton("开始")
        self._start_btn.clicked.connect(self._on_start_scan)
        layout.addWidget(self._start_btn)
        
        self._stop_btn = QPushButton("停止")
        self._stop_btn.setObjectName("dangerButton")
        self._stop_btn.setFixedWidth(80)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop_scan)
        layout.addWidget(self._stop_btn)
        
        return header
    
    def _create_input_panel(self) -> QFrame:
        panel = QFrame()
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(15, 15, 15, 15)
        
        target_label = QLabel("目标设置")
        target_label.setObjectName("categoryLabel")
        layout.addWidget(target_label)
        
        target_layout = QHBoxLayout()
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("输入目标地址，多个目标用逗号分隔")
        
        self._file_btn = QPushButton("从文件导入")
        self._file_btn.setObjectName("secondaryButton")
        self._file_btn.clicked.connect(self._import_targets)
        
        target_layout.addWidget(self._target_input, 1)
        target_layout.addWidget(self._file_btn)
        layout.addLayout(target_layout)
        
        self._options_widget = self._create_options_widget()
        if self._options_widget:
            scroll_area = QScrollArea()
            scroll_area.setWidgetResizable(True)
            scroll_area.setWidget(self._options_widget)
            scroll_area.setStyleSheet(self.COMMON_STYLES)
            layout.addWidget(scroll_area)
        
        return panel
    
    def _create_options_widget(self) -> Optional[QWidget]:
        return None
    
    def _create_output_panel(self) -> QFrame:
        panel = QFrame()
        
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(15, 15, 15, 15)
        
        output_tabs = QTabWidget()
        output_tabs.setStyleSheet(self.COMMON_STYLES)
        
        result_widget = QWidget()
        result_layout = QVBoxLayout(result_widget)
        result_layout.setContentsMargins(0, 0, 0, 0)
        result_layout.setSpacing(5)
        
        result_btn_layout = QHBoxLayout()
        self._clear_result_btn = QPushButton("清空结果")
        self._clear_result_btn.setObjectName("secondaryButton")
        self._clear_result_btn.clicked.connect(self._clear_results)
        
        self._delete_selected_btn = QPushButton("删除选中")
        self._delete_selected_btn.setObjectName("dangerButton")
        self._delete_selected_btn.clicked.connect(self._delete_selected_results)
        
        result_btn_layout.addStretch()
        result_btn_layout.addWidget(self._delete_selected_btn)
        result_btn_layout.addWidget(self._clear_result_btn)
        
        self._result_table = self._create_result_table()
        self._result_table.setStyleSheet(self.COMMON_STYLES)
        result_layout.addLayout(result_btn_layout)
        result_layout.addWidget(self._result_table)
        
        output_tabs.addTab(result_widget, "结果")
        
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.setSpacing(5)
        
        log_btn_layout = QHBoxLayout()
        self._clear_log_btn = QPushButton("清空日志")
        self._clear_log_btn.setObjectName("secondaryButton")
        self._clear_log_btn.clicked.connect(self._clear_log)
        
        self._export_log_btn = QPushButton("导出日志")
        self._export_log_btn.setObjectName("secondaryButton")
        self._export_log_btn.clicked.connect(self._export_log)
        
        log_btn_layout.addStretch()
        log_btn_layout.addWidget(self._export_log_btn)
        log_btn_layout.addWidget(self._clear_log_btn)
        
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setObjectName("logView")
        self._log_view.setStyleSheet(self.COMMON_STYLES)
        log_layout.addLayout(log_btn_layout)
        log_layout.addWidget(self._log_view)
        
        output_tabs.addTab(log_widget, "日志")
        
        layout.addWidget(output_tabs)
        
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setStyleSheet(self.COMMON_STYLES)
        layout.addWidget(self._progress_bar)
        
        return panel
    
    def _create_result_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["目标", "状态", "结果", "详情"])
        
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        return table
    
    def _clear_results(self):
        reply = QMessageBox.question(self, "确认清空", "确定要清空所有结果吗？",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._result_table.setRowCount(0)
            self._results.clear()
    
    def _delete_selected_results(self):
        selected_rows = set()
        for item in self._result_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "提示", "请先选择要删除的结果")
            return
        
        reply = QMessageBox.question(self, "确认删除", f"确定要删除选中的 {len(selected_rows)} 个结果吗？",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for row in sorted(selected_rows, reverse=True):
                self._result_table.removeRow(row)
                if row < len(self._results):
                    self._results.pop(row)
    
    def _clear_log(self):
        self._log_view.clear()
    
    def _export_log(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出日志", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self._log_view.toPlainText())
                self._add_log(LogLevel.SUCCESS, f"日志已导出到: {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导出失败: {str(e)}")
    
    def _import_targets(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    targets = [line.strip() for line in f if line.strip()]
                self._target_input.setText(','.join(targets))
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取文件失败: {str(e)}")
    
    def _select_dict(self, dict_type: str = "general") -> Optional[str]:
        dialog = DictSelectDialog(self, dict_type)
        if dialog.exec():
            return dialog.get_selected_dict()
        return None
    
    def _show_warning(self, title: str, message: str):
        QMessageBox.warning(self, title, message)
    
    def _on_start_scan(self):
        targets = self._target_input.text().strip()
        if not targets:
            self._show_warning("警告", "请输入目标地址")
            return
        
        self._is_scanning = True
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        
        self._log_view.clear()
        self._add_log(LogLevel.INFO, f"开始扫描: {targets}")
        
        self.scan_started.emit()
        self._start_scan_thread()
    
    def _on_stop_scan(self):
        reply = QMessageBox.question(self, "确认停止", "确定要停止当前扫描吗？",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._is_scanning = False
            self._stop_current_tool()
            self._add_log(LogLevel.WARNING, "正在停止扫描...")
    
    def _start_scan_thread(self):
        def scan():
            try:
                self._do_scan()
            except Exception as e:
                self._add_log(LogLevel.ERROR, f"扫描出错: {str(e)}")
            finally:
                self._scan_finished()
        
        thread = threading.Thread(target=scan, daemon=True)
        thread.start()
    
    def _do_scan(self):
        pass
    
    def _scan_finished(self):
        self._is_scanning = False
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress_bar.setVisible(False)
        self._add_log(LogLevel.INFO, "扫描完成")
        self.scan_finished.emit()
    
    def _add_log(self, level: LogLevel, message: str):
        color = self._style_manager.get_log_color(level)
        self._log_view.append(f'<span style="color: {color}">[{level.value}]</span> {message}')
    
    def _add_result(self, *args):
        row = self._result_table.rowCount()
        self._result_table.insertRow(row)
        
        for col, value in enumerate(args):
            if col < self._result_table.columnCount():
                self._result_table.setItem(row, col, QTableWidgetItem(str(value)))
        
        self._results.append(list(args))
    
    def _update_progress(self, value: int):
        QMetaObject.invokeMethod(self._progress_bar, "setValue", 
                                Qt.ConnectionType.QueuedConnection,
                                Q_ARG(int, min(100, max(0, value))))
    
    def get_results(self) -> List[Dict]:
        return self._results.copy()
    
    def clear_results(self):
        self._result_table.setRowCount(0)
        self._results.clear()
        self._log_view.clear()
