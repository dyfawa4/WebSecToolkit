from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFormLayout, QLineEdit, QTextEdit, QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt


class NewProjectDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._project_data = {}
        self.setWindowTitle("新建项目")
        self.setMinimumSize(500, 350)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        title = QLabel("创建新项目")
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        form_layout = QFormLayout()
        form_layout.setSpacing(15)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("输入项目名称")
        form_layout.addRow("项目名称:", self._name_input)

        self._desc_input = QTextEdit()
        self._desc_input.setPlaceholderText("输入项目描述（可选）")
        self._desc_input.setMaximumHeight(80)
        form_layout.addRow("描述:", self._desc_input)

        target_layout = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("输入目标地址")

        file_btn = QPushButton("导入")
        file_btn.setObjectName("secondaryButton")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self._import_targets)

        target_layout.addWidget(self._target_input)
        target_layout.addWidget(file_btn)
        form_layout.addRow("目标:", target_layout)

        layout.addLayout(form_layout)
        layout.addStretch()

        button_layout = QHBoxLayout()
        button_layout.addStretch()

        create_btn = QPushButton("创建项目")
        create_btn.setFixedWidth(100)
        create_btn.clicked.connect(self._create_project)

        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("secondaryButton")
        cancel_btn.setFixedWidth(80)
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(create_btn)
        button_layout.addSpacing(10)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

    def _import_targets(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择目标文件", "", "文本文件;;所有文件"
        )

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                self._target_input.setText(content)
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取文件失败: {str(e)}")

    def _create_project(self):
        name = self._name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "警告", "请输入项目名称")
            return

        self._project_data = {
            "name": name,
            "description": self._desc_input.toPlainText().strip(),
            "target": self._target_input.text().strip()
        }
        self.accept()

    def get_project_data(self) -> dict:
        return self._project_data
