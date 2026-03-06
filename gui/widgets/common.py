from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont


class CollapsibleSection(QWidget):
    toggled = pyqtSignal(bool)
    
    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self._is_expanded = True
        self._title = title
        self._content_widget = None
        self._setup_ui()
    
    def _setup_ui(self):
        self._main_layout = QVBoxLayout(self)
        self._main_layout.setContentsMargins(0, 0, 0, 0)
        self._main_layout.setSpacing(0)
        
        self._header = QFrame()
        self._header.setObjectName("card")
        self._header.setFixedHeight(40)
        self._header.setCursor(Qt.CursorShape.PointingHandCursor)
        
        header_layout = QHBoxLayout(self._header)
        header_layout.setContentsMargins(15, 0, 15, 0)
        
        self._arrow_label = QLabel("▼")
        self._arrow_label.setFixedWidth(15)
        self._arrow_label.setStyleSheet("font-size: 10px; background: transparent;")
        
        self._title_label = QLabel(self._title)
        self._title_label.setStyleSheet("font-weight: bold; font-size: 13px; background: transparent;")
        
        header_layout.addWidget(self._arrow_label)
        header_layout.addWidget(self._title_label)
        header_layout.addStretch()
        
        self._main_layout.addWidget(self._header)
        
        self._content_area = QScrollArea()
        self._content_area.setWidgetResizable(True)
        self._content_area.setFrameShape(QFrame.Shape.NoFrame)
        self._content_area.setStyleSheet("background: transparent; border: none;")
        self._content_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self._content_container = QWidget()
        self._content_container.setStyleSheet("background: transparent;")
        self._content_layout = QVBoxLayout(self._content_container)
        self._content_layout.setContentsMargins(0, 5, 0, 0)
        self._content_layout.setSpacing(5)
        
        self._content_area.setWidget(self._content_container)
        self._main_layout.addWidget(self._content_area)
        
        self._header.mousePressEvent = self._toggle
    
    def _toggle(self, event):
        self._is_expanded = not self._is_expanded
        self._content_area.setVisible(self._is_expanded)
        self._arrow_label.setText("▼" if self._is_expanded else "▶")
        self.toggled.emit(self._is_expanded)
    
    def set_content_widget(self, widget: QWidget):
        if self._content_widget:
            self._content_layout.removeWidget(self._content_widget)
            self._content_widget.deleteLater()
        
        self._content_widget = widget
        self._content_layout.addWidget(widget)
    
    def add_widget(self, widget: QWidget):
        self._content_layout.addWidget(widget)
    
    def set_expanded(self, expanded: bool):
        if self._is_expanded != expanded:
            self._toggle(None)
    
    def is_expanded(self) -> bool:
        return self._is_expanded


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", 
                 color: str = "#89B4FA", parent=None):
        super().__init__(parent)
        self._color = color
        self._setup_ui(title, value)
    
    def _setup_ui(self, title: str, value: str):
        self.setObjectName("statCard")
        self.setMinimumHeight(110)
        self.setMaximumHeight(130)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(8)
        
        self._value_label = QLabel(str(value))
        self._value_label.setObjectName("statNumber")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._value_label.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {self._color}; background: transparent; border: none; margin: 0; padding: 0;")
        
        self._title_label = QLabel(title)
        self._title_label.setObjectName("statLabel")
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self._title_label.setStyleSheet("font-size: 13px; background: transparent; border: none;")
        
        layout.addWidget(self._value_label)
        layout.addWidget(self._title_label)
        layout.addStretch()
    
    def set_value(self, value):
        self._value_label.setText(str(value))
    
    def set_title(self, title: str):
        self._title_label.setText(title)
    
    def set_color(self, color: str):
        self._color = color
        self._value_label.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {self._color}; background: transparent; border: none;")


class InfoCard(QFrame):
    def __init__(self, title: str, content: str = "", 
                 icon: str = "", parent=None):
        super().__init__(parent)
        self._setup_ui(title, content, icon)
    
    def _setup_ui(self, title: str, content: str, icon: str):
        self.setObjectName("card")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(10)
        
        header_layout = QHBoxLayout()
        
        if icon:
            icon_label = QLabel(icon)
            icon_label.setStyleSheet("font-size: 20px; background: transparent;")
            header_layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 14px; font-weight: bold; background: transparent;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        if content:
            content_label = QLabel(content)
            content_label.setWordWrap(True)
            content_label.setStyleSheet("font-size: 12px; line-height: 1.5; background: transparent;")
            layout.addWidget(content_label)


class TagWidget(QLabel):
    def __init__(self, text: str, tag_type: str = "default", parent=None):
        super().__init__(text, parent)
        self._tag_type = tag_type
        self._setup_style()
    
    def _setup_style(self):
        styles = {
            "default": ("#45475A", "#CDD6F4"),
            "critical": ("#F38BA8", "#1E1E2E"),
            "high": ("#FAB387", "#1E1E2E"),
            "medium": ("#F9E2AF", "#1E1E2E"),
            "low": ("#A6E3A1", "#1E1E2E"),
            "info": ("#89B4FA", "#1E1E2E"),
            "success": ("#A6E3A1", "#1E1E2E"),
            "warning": ("#F9E2AF", "#1E1E2E"),
            "danger": ("#F38BA8", "#1E1E2E"),
        }
        
        bg_color, text_color = styles.get(self._tag_type, styles["default"])
        
        self.setStyleSheet(f"""
            background-color: {bg_color};
            color: {text_color};
            border-radius: 4px;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: bold;
        """)


class LoadingOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self.hide()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self._loading_label = QLabel("加载中...")
        self._loading_label.setStyleSheet("font-size: 16px; font-weight: bold; background: transparent;")
        self._loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self._loading_label)
    
    def show_loading(self, text: str = "加载中..."):
        self._loading_label.setText(text)
        self.show()
    
    def hide_loading(self):
        self.hide()
