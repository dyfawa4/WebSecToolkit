from PyQt6.QtWidgets import QComboBox, QListView, QStyledItemDelegate
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette


COMBO_STYLE = """
    QComboBox {
        background-color: #11111b;
        color: #cdd6f4;
        border: 1px solid #313244;
        border-radius: 6px;
        padding: 8px 12px;
        min-height: 20px;
    }
    QComboBox:hover {
        border-color: #585b70;
    }
    QComboBox:focus {
        border-color: #89b4fa;
    }
    QComboBox::drop-down {
        border: none;
        width: 30px;
    }
    QComboBox::down-arrow {
        image: none;
        border-left: 5px solid transparent;
        border-right: 5px solid transparent;
        border-top: 6px solid #6c7086;
    }
    QComboBox QAbstractItemView {
        background-color: #181825;
        color: #cdd6f4;
        selection-background-color: #45475a;
        selection-color: #cdd6f4;
        outline: none;
        border: none;
        margin: 0px;
        padding: 4px;
    }
    QComboBox QAbstractItemView::item {
        background-color: #181825;
        color: #cdd6f4;
        padding: 8px 12px;
        min-height: 24px;
    }
    QComboBox QAbstractItemView::item:hover {
        background-color: #313244;
        color: #cdd6f4;
    }
    QComboBox QAbstractItemView::item:selected {
        background-color: #45475a;
        color: #89b4fa;
    }
"""

VIEW_STYLE = """
    QListView {
        background-color: #181825;
        color: #cdd6f4;
        border: none;
        outline: none;
    }
    QListView::item {
        background-color: #181825;
        color: #cdd6f4;
        padding: 8px 12px;
        min-height: 24px;
    }
    QListView::item:hover {
        background-color: #313244;
    }
    QListView::item:selected {
        background-color: #45475a;
        color: #89b4fa;
    }
"""


def setup_combo_style(combo: QComboBox):
    combo.setStyleSheet(COMBO_STYLE)
    
    try:
        view = combo.view()
        if view:
            view.setStyleSheet(VIEW_STYLE)
            
            parent = view.parentWidget()
            if parent:
                parent.setAutoFillBackground(True)
                palette = parent.palette()
                palette.setColor(QPalette.ColorRole.Window, QColor("#181825"))
                palette.setColor(QPalette.ColorRole.WindowText, QColor("#cdd6f4"))
                palette.setColor(QPalette.ColorRole.Base, QColor("#181825"))
                parent.setPalette(palette)
                parent.setStyleSheet("background-color: #181825;")
    except Exception:
        pass


class StyledComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()

    def _setup_style(self):
        view = QListView()
        self.setView(view)
        setup_combo_style(self)
