from PyQt6.QtWidgets import QComboBox, QListView, QStyledItemDelegate
from PyQt6.QtCore import Qt


class StyledComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_style()
    
    def _setup_style(self):
        view = QListView()
        self.setView(view)
