from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame, QGraphicsOpacityEffect
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal
from PyQt6.QtGui import QFont


class ToastNotification(QFrame):
    closed = pyqtSignal()
    
    def __init__(self, title: str, message: str, success: bool = True, parent=None):
        super().__init__(parent)
        self._title = title
        self._message = message
        self._success = success
        self._setup_ui()
        self._setup_animation()
    
    def _setup_ui(self):
        self.setObjectName("toastNotification")
        self.setFixedWidth(380)
        self.setMinimumHeight(100)
        
        if self._success:
            bg_color = "#DCFCE7"
            border_color = "#22C55E"
            text_color = "#166534"
            icon = "✓"
        else:
            bg_color = "#FEF2F2"
            border_color = "#EF4444"
            text_color = "#991B1B"
            icon = "✗"
        
        self.setStyleSheet(f"""
            QFrame#toastNotification {{
                background-color: {bg_color};
                border: 1px solid {border_color};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(12)
        
        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"font-size: 28px; color: {text_color};")
        icon_label.setFixedWidth(35)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(icon_label)
        
        content_layout = QVBoxLayout()
        content_layout.setSpacing(6)
        
        title_label = QLabel(self._title)
        title_label.setStyleSheet(f"font-size: 15px; font-weight: bold; color: {text_color};")
        content_layout.addWidget(title_label)
        
        message_label = QLabel(self._message)
        message_label.setStyleSheet(f"font-size: 13px; color: {text_color};")
        message_label.setWordWrap(True)
        content_layout.addWidget(message_label)
        
        layout.addLayout(content_layout, 1)
        
        close_btn = QPushButton("×")
        close_btn.setFixedSize(28, 28)
        close_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                font-size: 20px;
                color: {text_color};
            }}
            QPushButton:hover {{
                background-color: rgba(0,0,0,0.1);
                border-radius: 14px;
            }}
        """)
        close_btn.clicked.connect(self._on_close)
        layout.addWidget(close_btn)
    
    def _setup_animation(self):
        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._opacity_effect.setOpacity(0.0)
        
        self._show_animation = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._show_animation.setDuration(200)
        self._show_animation.setStartValue(0.0)
        self._show_animation.setEndValue(1.0)
        self._show_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
        self._hide_animation = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._hide_animation.setDuration(200)
        self._hide_animation.setStartValue(1.0)
        self._hide_animation.setEndValue(0.0)
        self._hide_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self._hide_animation.finished.connect(self._on_hide_finished)
    
    def show_toast(self):
        self.show()
        self._show_animation.start()
        
        self._auto_close_timer = QTimer(self)
        self._auto_close_timer.setSingleShot(True)
        self._auto_close_timer.timeout.connect(self._on_close)
        self._auto_close_timer.start(5000)
    
    def _on_close(self):
        if hasattr(self, '_auto_close_timer'):
            self._auto_close_timer.stop()
        self._hide_animation.start()
    
    def _on_hide_finished(self):
        self.hide()
        self.closed.emit()


class NotificationManager(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._notifications = []
        self._setup_ui()
    
    def _setup_ui(self):
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setStyleSheet("background: transparent;")
        
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 60, 20, 20)
        self._layout.setSpacing(10)
        self._layout.addStretch()
    
    def show_notification(self, title: str, message: str, success: bool = True):
        notification = ToastNotification(title, message, success, self)
        notification.closed.connect(lambda: self._remove_notification(notification))
        notification.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        
        self._layout.insertWidget(self._layout.count() - 1, notification, 0, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight)
        self._notifications.append(notification)
        
        notification.show_toast()
        
        return notification
    
    def _remove_notification(self, notification):
        if notification in self._notifications:
            self._notifications.remove(notification)
            self._layout.removeWidget(notification)
            notification.deleteLater()
