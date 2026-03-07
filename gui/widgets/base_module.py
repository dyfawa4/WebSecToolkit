from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QSpinBox, QFileDialog, QMessageBox, QListView, QDialog,
    QListWidget, QDialogButtonBox, QFormLayout, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot, QThread, QMetaObject, QTimer, QPropertyAnimation, QRect, Q_ARG
from PyQt6.QtGui import QFont, QColor
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
    module_running_changed = pyqtSignal(str, bool)
    module_completed = pyqtSignal(str, str, bool)
    
    COMMON_STYLES = """
        QScrollArea { border: none; background-color: transparent; }
        QScrollBar:vertical {
            background-color: #F3F4F6;
            width: 10px;
            margin: 0px;
        }
        QScrollBar::handle:vertical {
            background-color: #D1D5DB;
            border-radius: 5px;
            min-height: 30px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #9CA3AF;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background-color: #F3F4F6;
            height: 10px;
            margin: 0px;
        }
        QScrollBar::handle:horizontal {
            background-color: #D1D5DB;
            border-radius: 5px;
            min-width: 30px;
        }
        QTabWidget::pane {
            background-color: #FFFFFF;
            border: 1px solid #E5E7EB;
            border-radius: 8px;
        }
        QTabBar::tab {
            background-color: #F3F4F6;
            color: #6B7280;
            padding: 10px 20px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 2px;
            min-width: 80px;
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
            border-radius: 8px;
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
            padding: 10px;
            border: none;
            border-bottom: 1px solid #E5E7EB;
            font-weight: bold;
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
            border-radius: 8px;
            padding: 10px;
            font-family: Consolas, Monaco, monospace;
            font-size: 10pt;
        }
        QProgressBar {
            background-color: #F3F4F6;
            color: #1F2937;
            border: 1px solid #E5E7EB;
            border-radius: 8px;
            padding: 2px;
            text-align: center;
            min-height: 20px;
        }
        QProgressBar::chunk {
            background-color: #4285F4;
            border-radius: 6px;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #E5E7EB;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 8px;
            color: #374151;
        }
    """
    
    def __init__(self, module_id: str, display_name: str = None, parent=None):
        super().__init__(parent)
        self.module_id = module_id
        self.module_name = display_name or module_id
        self._is_scanning = False
        self._scan_finished_called = False
        self._results = []
        self._tool_manager = get_tool_manager()
        self._style_manager = get_style_manager()
        self._current_process = None
        self._setup_base_ui()
    
    def _get_available_tools(self) -> List[Dict[str, str]]:
        return self._tool_manager.get_module_tools_info(self.module_id)
    
    def _is_tool_available(self, tool_name: str) -> bool:
        return self._tool_manager.is_tool_available(self.module_id, tool_name)
    
    def _get_tool_path(self, tool_name: str) -> Optional[Path]:
        return self._tool_manager.get_tool_path(self.module_id, tool_name)
    
    def _execute_tool(self, tool_name: str, args: List[str], 
                     capture_output: bool = True) -> Optional[subprocess.Popen]:
        try:
            if not self._is_tool_available(tool_name):
                self._add_log(LogLevel.ERROR, f"工具 {tool_name} 不可用")
                return None
            
            self._current_process = self._tool_manager.execute_tool(
                self.module_id, tool_name, args
            )
            return self._current_process
        except FileNotFoundError:
            self._add_log(LogLevel.ERROR, f"工具 {tool_name} 未找到")
            return None
        except Exception as e:
            self._add_log(LogLevel.ERROR, f"执行工具失败: {str(e)}")
            return None
    
    def _stop_current_tool(self):
        try:
            if hasattr(self, '_executor') and self._executor:
                try:
                    self._add_log(LogLevel.INFO, "正在取消线程池任务...")
                    if hasattr(self, '_futures') and self._futures:
                        for future in list(self._futures.values()):
                            try:
                                future.cancel()
                            except Exception:
                                pass
                    self._executor.shutdown(wait=False, cancel_futures=True)
                    self._add_log(LogLevel.INFO, "线程池已关闭")
                except Exception:
                    pass
                self._executor = None
                self._futures = None
        except Exception:
            pass
        
        try:
            if hasattr(self, '_current_process') and self._current_process:
                if self._current_process.poll() is None:
                    try:
                        self._current_process.terminate()
                        try:
                            self._current_process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            self._current_process.kill()
                    except Exception:
                        pass
                self._current_process = None
        except Exception:
            pass
    
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
        self._main_layout.setContentsMargins(15, 15, 15, 15)
        self._main_layout.setSpacing(10)
        
        self._header = self._create_header()
        self._main_layout.addWidget(self._header)
        
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setStyleSheet(self.COMMON_STYLES)
        self._main_layout.addWidget(self._progress_bar)
        
        main_scroll = QScrollArea()
        main_scroll.setWidgetResizable(True)
        main_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        main_scroll.setStyleSheet(self.COMMON_STYLES)
        
        scroll_content = QWidget()
        scroll_content.setMinimumWidth(600)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(5, 5, 5, 5)
        scroll_layout.setSpacing(15)
        
        target_group = QGroupBox("目标设置")
        target_layout = QVBoxLayout(target_group)
        target_layout.setSpacing(10)
        
        target_input_layout = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("输入目标地址，多个目标用逗号分隔")
        self._target_input.setMinimumHeight(36)
        
        self._file_btn = QPushButton("从文件导入")
        self._file_btn.setObjectName("secondaryButton")
        self._file_btn.setFixedWidth(100)
        self._file_btn.clicked.connect(self._import_targets)
        
        target_input_layout.addWidget(self._target_input, 1)
        target_input_layout.addWidget(self._file_btn)
        target_layout.addLayout(target_input_layout)
        
        scroll_layout.addWidget(target_group)
        
        self._options_widget = self._create_options_widget()
        if self._options_widget:
            scroll_layout.addWidget(self._options_widget)
        
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout(result_group)
        result_layout.setSpacing(10)
        
        self._result_table = self._create_result_table()
        self._result_table.setMinimumHeight(250)
        self._result_table.setStyleSheet(self.COMMON_STYLES)
        result_layout.addWidget(self._result_table)
        
        result_btn_layout = QHBoxLayout()
        
        self._clear_result_btn = QPushButton("清空结果")
        self._clear_result_btn.setObjectName("secondaryButton")
        self._clear_result_btn.clicked.connect(self._clear_results)
        result_btn_layout.addWidget(self._clear_result_btn)
        
        self._delete_result_btn = QPushButton("删除选中")
        self._delete_result_btn.setObjectName("secondaryButton")
        self._delete_result_btn.clicked.connect(self._delete_selected_results)
        result_btn_layout.addWidget(self._delete_result_btn)
        
        self._export_result_btn = QPushButton("导出结果")
        self._export_result_btn.setObjectName("secondaryButton")
        self._export_result_btn.clicked.connect(self._export_results)
        result_btn_layout.addWidget(self._export_result_btn)
        
        result_btn_layout.addStretch()
        result_layout.addLayout(result_btn_layout)
        
        scroll_layout.addWidget(result_group)
        
        log_group = QGroupBox("操作日志")
        log_layout = QVBoxLayout(log_group)
        log_layout.setSpacing(10)
        
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setMinimumHeight(150)
        self._log_view.setMaximumHeight(300)
        
        font = self._log_view.font()
        font.setPointSize(12)
        self._log_view.setFont(font)
        
        self._log_view.setStyleSheet(self.COMMON_STYLES)
        log_layout.addWidget(self._log_view)
        
        log_btn_layout = QHBoxLayout()
        
        self._clear_log_btn = QPushButton("清空日志")
        self._clear_log_btn.setObjectName("secondaryButton")
        self._clear_log_btn.clicked.connect(self._clear_log)
        log_btn_layout.addWidget(self._clear_log_btn)
        
        self._export_log_btn = QPushButton("导出日志")
        self._export_log_btn.setObjectName("secondaryButton")
        self._export_log_btn.clicked.connect(self._export_log)
        log_btn_layout.addWidget(self._export_log_btn)
        
        log_btn_layout.addStretch()
        log_layout.addLayout(log_btn_layout)
        
        scroll_layout.addWidget(log_group)
        
        scroll_layout.addStretch()
        
        main_scroll.setWidget(scroll_content)
        self._main_layout.addWidget(main_scroll, 1)
        
        self._config_widgets = []
        self._collect_config_widgets()
    
    def _collect_config_widgets(self):
        self._config_widgets = []
        self._config_widgets.append(self._target_input)
        self._config_widgets.append(self._file_btn)
        
        if self._options_widget:
            self._find_editable_widgets(self._options_widget)
    
    def _find_editable_widgets(self, widget):
        for child in widget.findChildren(QWidget):
            if isinstance(child, (QLineEdit, QComboBox, QCheckBox, QSpinBox, QTextEdit)):
                if child not in self._config_widgets:
                    self._config_widgets.append(child)
            elif isinstance(child, QPushButton):
                if child not in self._config_widgets and child not in [self._clear_result_btn, self._delete_result_btn, self._export_result_btn, self._clear_log_btn, self._export_log_btn]:
                    self._config_widgets.append(child)
    
    def _lock_config(self, locked: bool):
        for widget in self._config_widgets:
            if widget is None:
                continue
            try:
                widget.setEnabled(not locked)
                if locked:
                    widget.setStyleSheet(widget.styleSheet() + "; background-color: #F3F4F6;")
                else:
                    widget.setStyleSheet(widget.styleSheet().replace("; background-color: #F3F4F6;", ""))
            except:
                pass
    
    def _create_header(self) -> QFrame:
        header = QFrame()
        header.setFixedHeight(50)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(10, 5, 10, 5)
        
        title_label = QLabel(self.module_name)
        title_label.setObjectName("titleLabel")
        
        layout.addWidget(title_label)
        layout.addStretch()
        
        self._start_btn = QPushButton("开始")
        self._start_btn.setFixedWidth(100)
        self._start_btn.clicked.connect(self._on_start_scan)
        layout.addWidget(self._start_btn)
        
        self._stop_btn = QPushButton("停止")
        self._stop_btn.setObjectName("dangerButton")
        self._stop_btn.setFixedWidth(80)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop_scan)
        layout.addWidget(self._stop_btn)
        
        return header
    
    def _create_options_widget(self) -> Optional[QWidget]:
        return None
    
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
        table.setMinimumHeight(200)
        
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
    
    def _export_results(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出结果", "", "CSV文件 (*.csv);;文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    headers = []
                    for col in range(self._result_table.columnCount()):
                        headers.append(self._result_table.horizontalHeaderItem(col).text())
                    f.write(','.join(headers) + '\n')
                    
                    for row in range(self._result_table.rowCount()):
                        row_data = []
                        for col in range(self._result_table.columnCount()):
                            item = self._result_table.item(row, col)
                            row_data.append(item.text() if item else '')
                        f.write(','.join(row_data) + '\n')
                
                self._add_log(LogLevel.SUCCESS, f"结果已导出到: {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导出失败: {str(e)}")
    
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
        self._scan_finished_called = False
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        
        self._lock_config(True)
        
        self._log_view.clear()
        self._add_log(LogLevel.INFO, f"开始扫描: {targets}")
        
        self.module_running_changed.emit(self.module_name, True)
        self.scan_started.emit()
        self._start_scan_thread()
    
    def _on_stop_scan(self):
        if not self._is_scanning:
            return
        
        self._is_scanning = False
        
        try:
            if hasattr(self, '_stop_btn') and self._stop_btn:
                self._stop_btn.setEnabled(False)
        except Exception:
            pass
        
        try:
            self._add_log(LogLevel.WARNING, "正在停止扫描...")
        except Exception:
            pass
        
        try:
            self._stop_current_tool()
        except Exception:
            pass
        
        try:
            self._add_log(LogLevel.INFO, "扫描已停止")
        except Exception:
            pass
    
    def stop_scan(self):
        self._on_stop_scan()
    
    def _start_scan_thread(self):
        def scan():
            try:
                self._do_scan()
            except Exception as e:
                import traceback
                traceback.print_exc()
            finally:
                QMetaObject.invokeMethod(self, "_scan_finished", Qt.ConnectionType.QueuedConnection)
        
        thread = threading.Thread(target=scan, daemon=True)
        thread.start()
    
    def _do_scan(self):
        pass
    
    @pyqtSlot()
    def _scan_finished(self):
        if self._scan_finished_called:
            return
        self._scan_finished_called = True
        
        try:
            self._is_scanning = False
            
            if hasattr(self, '_progress_bar') and self._progress_bar:
                self._progress_bar.setValue(100)
            
            if hasattr(self, '_start_btn') and self._start_btn:
                self._start_btn.setEnabled(True)
            if hasattr(self, '_stop_btn') and self._stop_btn:
                self._stop_btn.setEnabled(False)
            
            if hasattr(self, '_lock_config'):
                self._lock_config(False)
            
            if hasattr(self, '_add_log'):
                self._add_log(LogLevel.INFO, "扫描完成")
            
            if hasattr(self, 'scan_finished'):
                self.scan_finished.emit()
            
            if hasattr(self, 'module_running_changed') and hasattr(self, 'module_name'):
                self.module_running_changed.emit(self.module_name, False)
            
            if hasattr(self, 'module_completed') and hasattr(self, 'module_name'):
                success = len(self._results) > 0 if hasattr(self, '_results') else False
                self.module_completed.emit(self.module_name, self.module_name, success)
        except Exception as e:
            import traceback
            traceback.print_exc()
        finally:
            if hasattr(self, '_progress_bar') and self._progress_bar:
                self._progress_bar.setVisible(False)
    
    def _add_log(self, level: LogLevel, message: str):
        try:
            color = self._style_manager.get_log_color(level)
            log_text = f'<span style="color: {color}">[{level.value}]</span> {message}'
            if threading.current_thread() is not threading.main_thread():
                QMetaObject.invokeMethod(
                    self._log_view, "append", 
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(str, log_text)
                )
            else:
                self._log_view.append(log_text)
        except Exception:
            pass
    
    def _add_result(self, *args):
        try:
            self._results.append(list(args))
            
            if threading.current_thread() is not threading.main_thread():
                QMetaObject.invokeMethod(
                    self, "_add_result_to_table",
                    Qt.ConnectionType.QueuedConnection,
                    Q_ARG(int, len(self._results) - 1)
                )
            else:
                self._add_result_to_table(len(self._results) - 1)
        except Exception as e:
            import traceback
            traceback.print_exc()
    
    @pyqtSlot(int)
    def _add_result_to_table(self, result_index: int):
        try:
            if 0 <= result_index < len(self._results):
                args = self._results[result_index]
                row = self._result_table.rowCount()
                self._result_table.insertRow(row)
                
                for col, value in enumerate(args):
                    if col < self._result_table.columnCount():
                        self._result_table.setItem(row, col, QTableWidgetItem(str(value)))
        except Exception as e:
            import traceback
            traceback.print_exc()
    
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
