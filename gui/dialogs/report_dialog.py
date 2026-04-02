from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QComboBox, QFileDialog, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from gui.widgets.styled_widgets import setup_combo_style
import json
from datetime import datetime


class ReportPreviewDialog(QDialog):
    def __init__(self, stats_data, vulnerabilities=None, parent=None):
        super().__init__(parent)
        self._stats_data = stats_data
        self._vulnerabilities = vulnerabilities or []
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("报告预览")
        self.setMinimumSize(600, 500)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        title_label = QLabel("报告预览")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title_label)

        self._preview_text = QTextEdit()
        self._preview_text.setReadOnly(True)
        self._preview_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self._preview_text)

        format_frame = QFrame()
        format_layout = QHBoxLayout(format_frame)
        format_layout.setContentsMargins(0, 0, 0, 0)

        format_label = QLabel("导出格式:")
        format_layout.addWidget(format_label)

        self._format_combo = QComboBox()
        self._format_combo.addItems(["JSON", "HTML", "TXT"])
        setup_combo_style(self._format_combo)
        self._format_combo.currentTextChanged.connect(self._update_preview)
        format_layout.addWidget(self._format_combo)

        format_layout.addStretch()
        layout.addWidget(format_frame)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        export_btn = QPushButton("导出")
        export_btn.clicked.connect(self._export_report)
        btn_layout.addWidget(export_btn)

        layout.addLayout(btn_layout)

        self._update_preview()

    def _generate_report_data(self):
        return {
            "title": "WebSec Toolkit 安全测试报告",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": self._stats_data,
            "vulnerabilities": self._vulnerabilities
        }

    def _update_preview(self):
        format_type = self._format_combo.currentText()
        report_data = self._generate_report_data()

        vuln_list = ""
        if self._vulnerabilities:
            for i, vuln in enumerate(self._vulnerabilities, 1):
                vuln_list += f"        <div class=\"vuln-item\">\n"
                vuln_list += f"            <div class=\"vuln-title\">{i}. {vuln.get('name', '未知漏洞')}</div>\n"
                vuln_list += f"            <div class=\"vuln-severity\">严重程度: {vuln.get('severity', '未知')}</div>\n"
                vuln_list += f"            <div class=\"vuln-target\">目标: {vuln.get('target', '未知')}</div>\n"
                vuln_list += f"            <div class=\"vuln-desc\">描述: {vuln.get('description', '无描述')}</div>\n"
                vuln_list += f"        </div>\n"
        else:
            vuln_list = "        <p>暂无漏洞数据</p>\n"

        if format_type == "JSON":
            preview = json.dumps(report_data, ensure_ascii=False, indent=2)
        elif format_type == "HTML":
            preview = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report_data['title']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .stats {{ display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0; }}
        .stat-item {{ flex: 1; min-width: 150px; padding: 15px; background: #f8f9fa; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .vulnerabilities {{ margin-top: 20px; }}
        .vuln-item {{ padding: 15px; margin: 10px 0; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #dc3545; }}
        .vuln-title {{ font-weight: bold; color: #333; }}
        .vuln-severity {{ color: #dc3545; margin: 5px 0; }}
        .vuln-target {{ color: #666; }}
        .vuln-desc {{ color: #666; margin-top: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report_data['title']}</h1>
        <div class="meta">生成时间: {report_data['generated_at']}</div>
        <div class="stats">
            <div class="stat-item">
                <div class="stat-value">{report_data['statistics']['projects']}</div>
                <div class="stat-label">项目总数</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{report_data['statistics']['targets']}</div>
                <div class="stat-label">目标数量</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{report_data['statistics']['vulnerabilities']}</div>
                <div class="stat-label">发现漏洞</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{report_data['statistics']['scans']}</div>
                <div class="stat-label">扫描次数</div>
            </div>
        </div>
        <div class="vulnerabilities">
            <h3>漏洞详细内容</h3>
{vuln_list}
        </div>
    </div>
</body>
</html>"""
        else:
            vuln_text = ""
            if self._vulnerabilities:
                for i, vuln in enumerate(self._vulnerabilities, 1):
                    vuln_text += f"{i}. {vuln.get('name', '未知漏洞')}\n"
                    vuln_text += f"   严重程度: {vuln.get('severity', '未知')}\n"
                    vuln_text += f"   目标: {vuln.get('target', '未知')}\n"
                    vuln_text += f"   描述: {vuln.get('description', '无描述')}\n\n"
            else:
                vuln_text = "暂无漏洞数据\n"

            preview = f"""
{'='*50}
{report_data['title']}
{'='*50}

生成时间: {report_data['generated_at']}

{'─'*50}
统计数据
{'─'*50}
项目总数: {report_data['statistics']['projects']}
目标数量: {report_data['statistics']['targets']}
发现漏洞: {report_data['statistics']['vulnerabilities']}
扫描次数: {report_data['statistics']['scans']}

{'─'*50}
漏洞详细内容
{'─'*50}
{vuln_text}
{'='*50}
"""

        self._preview_text.setPlainText(preview)

    def _export_report(self):
        format_type = self._format_combo.currentText()
        ext_map = {"JSON": "json", "HTML": "html", "TXT": "txt"}
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存报告", f"report.{ext_map[format_type]}",
            f"{format_type} Files (*.{ext_map[format_type]})"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self._preview_text.toPlainText())
                QMessageBox.information(self, "成功", f"报告已保存到: {file_path}")
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")
