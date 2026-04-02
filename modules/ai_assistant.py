from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel
from core.ai_service import (
    ai_service_manager, operation_analyzer, result_reporter,
    AIMessage, AIProvider
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QCheckBox, QSpinBox, QGroupBox,
    QFormLayout, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QFileDialog, QMessageBox, QTabWidget,
    QListWidget, QListWidgetItem, QSplitter, QFrame, QDialog,
    QDialogButtonBox, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QTextCursor
import json
import time
import threading


class AIChatWorker(QThread):
    response_received = pyqtSignal(str, bool)
    stream_received = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, messages, provider=None, stream=True, **kwargs):
        super().__init__()
        self.messages = messages
        self.provider = provider
        self.stream = stream
        self.kwargs = kwargs
        self._is_running = True
    
    def run(self):
        if self.stream:
            def stream_callback(text):
                if self._is_running:
                    self.stream_received.emit(text)
            
            response = ai_service_manager.stream_chat(
                self.messages, stream_callback, self.provider, **self.kwargs
            )
            if response.success:
                self.response_received.emit(response.content, True)
            else:
                self.response_received.emit(response.error, False)
        else:
            response = ai_service_manager.chat(self.messages, self.provider, **self.kwargs)
            if response.success:
                self.response_received.emit(response.content, True)
            else:
                self.response_received.emit(response.error, False)
        
        self.finished_signal.emit()
    
    def stop(self):
        self._is_running = False


class AnalysisWorker(QThread):
    analysis_complete = pyqtSignal(str)
    
    def __init__(self, result_data, context=None):
        super().__init__()
        self.result_data = result_data
        self.context = context
    
    def run(self):
        analysis = ai_service_manager.analyze_result(self.result_data, self.context)
        self.analysis_complete.emit(analysis)


@register_module("ai_assistant")
class AIAssistantWidget(BaseModuleWidget):
    def __init__(self):
        self._chat_history: list = []
        self._chat_worker = None
        self._analysis_worker = None
        super().__init__("ai_assistant", "AI助手")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        tabs = QTabWidget()
        
        config_tab = QWidget()
        config_layout = QVBoxLayout(config_tab)
        
        status_group = QGroupBox("AI服务状态")
        status_form = QFormLayout(status_group)
        
        self._status_label = QLabel("未配置")
        self._status_label.setStyleSheet("font-weight: bold;")
        status_form.addRow("状态:", self._status_label)
        
        self._provider_combo = QComboBox()
        self._setup_combo(self._provider_combo)
        status_form.addRow("当前提供商:", self._provider_combo)
        
        self._refresh_status_btn = QPushButton("刷新状态")
        self._refresh_status_btn.setObjectName("secondaryButton")
        self._refresh_status_btn.clicked.connect(self._refresh_status)
        status_form.addRow(self._refresh_status_btn)
        
        config_layout.addWidget(status_group)
        
        provider_group = QGroupBox("添加AI服务提供商")
        provider_form = QFormLayout(provider_group)
        
        self._new_provider_type = QComboBox()
        self._setup_combo(self._new_provider_type, [
            "OpenAI", "Anthropic (Claude)", "DeepSeek", "通义千问", "自定义"
        ])
        provider_form.addRow("提供商类型:", self._new_provider_type)
        
        self._new_provider_name = QLineEdit()
        self._new_provider_name.setPlaceholderText("自定义名称，如: my-gpt")
        provider_form.addRow("名称:", self._new_provider_name)
        
        self._new_provider_key = QLineEdit()
        self._new_provider_key.setPlaceholderText("API Key")
        self._new_provider_key.setEchoMode(QLineEdit.EchoMode.Password)
        provider_form.addRow("API Key:", self._new_provider_key)
        
        self._new_provider_url = QLineEdit()
        self._new_provider_url.setPlaceholderText("API Base URL (可选)")
        provider_form.addRow("Base URL:", self._new_provider_url)
        
        self._new_provider_model = QLineEdit()
        self._new_provider_model.setPlaceholderText("模型名称，如: gpt-4, claude-3-opus")
        provider_form.addRow("模型:", self._new_provider_model)
        
        add_provider_btn = QPushButton("添加提供商")
        add_provider_btn.setObjectName("primaryButton")
        add_provider_btn.clicked.connect(self._add_provider)
        provider_form.addRow(add_provider_btn)
        
        config_layout.addWidget(provider_group)
        
        settings_group = QGroupBox("AI设置")
        settings_form = QFormLayout(settings_group)
        
        self._temperature_spin = QSpinBox()
        self._temperature_spin.setRange(0, 100)
        self._temperature_spin.setValue(70)
        settings_form.addRow("温度 (0-100):", self._temperature_spin)
        
        self._max_tokens_spin = QSpinBox()
        self._max_tokens_spin.setRange(100, 32000)
        self._max_tokens_spin.setValue(4096)
        settings_form.addRow("最大Token:", self._max_tokens_spin)
        
        self._stream_check = QCheckBox("启用流式输出")
        self._stream_check.setChecked(True)
        settings_form.addRow(self._stream_check)
        
        self._auto_analyze_check = QCheckBox("自动分析操作结果")
        self._auto_analyze_check.setChecked(True)
        settings_form.addRow(self._auto_analyze_check)
        
        config_layout.addWidget(settings_group)
        config_layout.addStretch()
        tabs.addTab(config_tab, "配置")
        
        chat_tab = QWidget()
        chat_layout = QVBoxLayout(chat_tab)
        
        chat_group = QGroupBox("AI对话")
        chat_inner_layout = QVBoxLayout(chat_group)
        
        self._chat_display = QTextEdit()
        self._chat_display.setReadOnly(True)
        self._chat_display.setFont(QFont("Consolas", 10))
        self._chat_display.setMinimumHeight(300)
        chat_inner_layout.addWidget(self._chat_display)
        
        input_layout = QHBoxLayout()
        
        self._chat_input = QLineEdit()
        self._chat_input.setPlaceholderText("输入消息...")
        self._chat_input.returnPressed.connect(self._send_message)
        input_layout.addWidget(self._chat_input)
        
        self._send_btn = QPushButton("发送")
        self._send_btn.setObjectName("primaryButton")
        self._send_btn.clicked.connect(self._send_message)
        input_layout.addWidget(self._send_btn)
        
        self._clear_btn = QPushButton("清空")
        self._clear_btn.setObjectName("secondaryButton")
        self._clear_btn.clicked.connect(self._clear_chat)
        input_layout.addWidget(self._clear_btn)
        
        chat_inner_layout.addLayout(input_layout)
        chat_layout.addWidget(chat_group)
        
        quick_group = QGroupBox("快捷指令")
        quick_layout = QHBoxLayout(quick_group)
        
        analyze_btn = QPushButton("分析当前结果")
        analyze_btn.setObjectName("secondaryButton")
        analyze_btn.clicked.connect(self._analyze_current_result)
        quick_layout.addWidget(analyze_btn)
        
        suggest_btn = QPushButton("获取建议")
        suggest_btn.setObjectName("secondaryButton")
        suggest_btn.clicked.connect(self._get_suggestions)
        quick_layout.addWidget(suggest_btn)
        
        explain_btn = QPushButton("解释概念")
        explain_btn.setObjectName("secondaryButton")
        explain_btn.clicked.connect(self._explain_concept)
        quick_layout.addWidget(explain_btn)
        
        quick_layout.addStretch()
        chat_layout.addWidget(quick_group)
        
        tabs.addTab(chat_tab, "对话")
        
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        
        input_group = QGroupBox("输入数据")
        input_inner_layout = QVBoxLayout(input_group)
        
        self._analysis_input = QTextEdit()
        self._analysis_input.setPlaceholderText("粘贴需要分析的数据（JSON、文本等）...")
        self._analysis_input.setMaximumHeight(150)
        input_inner_layout.addWidget(self._analysis_input)
        
        context_layout = QHBoxLayout()
        context_layout.addWidget(QLabel("上下文:"))
        self._context_input = QLineEdit()
        self._context_input.setPlaceholderText("可选的上下文信息")
        context_layout.addWidget(self._context_input)
        input_inner_layout.addLayout(context_layout)
        
        analysis_layout.addWidget(input_group)
        
        analyze_btn_layout = QHBoxLayout()
        
        self._analyze_btn = QPushButton("开始分析")
        self._analyze_btn.setObjectName("primaryButton")
        self._analyze_btn.clicked.connect(self._start_analysis)
        analyze_btn_layout.addWidget(self._analyze_btn)
        
        self._generate_report_btn = QPushButton("生成报告")
        self._generate_report_btn.setObjectName("secondaryButton")
        self._generate_report_btn.clicked.connect(self._generate_report)
        analyze_btn_layout.addWidget(self._generate_report_btn)
        
        analyze_btn_layout.addStretch()
        analysis_layout.addLayout(analyze_btn_layout)
        
        result_group = QGroupBox("分析结果")
        result_inner_layout = QVBoxLayout(result_group)
        
        self._analysis_result = QTextEdit()
        self._analysis_result.setReadOnly(True)
        self._analysis_result.setFont(QFont("Consolas", 10))
        result_inner_layout.addWidget(self._analysis_result)
        
        analysis_layout.addWidget(result_group)
        tabs.addTab(analysis_tab, "分析")
        
        history_tab = QWidget()
        history_layout = QVBoxLayout(history_tab)
        
        history_group = QGroupBox("操作历史")
        history_inner_layout = QVBoxLayout(history_group)
        
        self._history_list = QListWidget()
        self._history_list.itemDoubleClicked.connect(self._on_history_item_clicked)
        history_inner_layout.addWidget(self._history_list)
        
        history_btn_layout = QHBoxLayout()
        
        refresh_history_btn = QPushButton("刷新")
        refresh_history_btn.setObjectName("secondaryButton")
        refresh_history_btn.clicked.connect(self._refresh_history)
        history_btn_layout.addWidget(refresh_history_btn)
        
        clear_history_btn = QPushButton("清空历史")
        clear_history_btn.setObjectName("secondaryButton")
        clear_history_btn.clicked.connect(self._clear_history)
        history_btn_layout.addWidget(clear_history_btn)
        
        analyze_selected_btn = QPushButton("分析选中项")
        analyze_selected_btn.setObjectName("secondaryButton")
        analyze_selected_btn.clicked.connect(self._analyze_selected_history)
        history_btn_layout.addWidget(analyze_selected_btn)
        
        history_btn_layout.addStretch()
        history_inner_layout.addLayout(history_btn_layout)
        
        history_layout.addWidget(history_group)
        tabs.addTab(history_tab, "历史")
        
        templates_tab = QWidget()
        templates_layout = QVBoxLayout(templates_tab)
        
        templates_group = QGroupBox("预设提示模板")
        templates_inner_layout = QVBoxLayout(templates_group)
        
        self._templates_list = QListWidget()
        templates = [
            ("安全分析", "请对以下安全测试结果进行专业分析，指出潜在风险和修复建议："),
            ("漏洞评估", "评估以下漏洞的严重程度、可利用性和影响范围："),
            ("渗透测试建议", "针对以下目标，提供渗透测试的方法和步骤建议："),
            ("代码审计", "审计以下代码的安全问题，重点关注注入、XSS、认证等："),
            ("报告生成", "根据以下测试结果，生成一份专业的安全测试报告："),
            ("工具使用指导", "解释如何使用以下安全工具，包括参数说明和使用场景："),
        ]
        for name, template in templates:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, template)
            self._templates_list.addItem(item)
        
        self._templates_list.itemDoubleClicked.connect(self._use_template)
        templates_inner_layout.addWidget(self._templates_list)
        
        templates_layout.addWidget(templates_group)
        templates_layout.addStretch()
        tabs.addTab(templates_tab, "模板")
        
        layout.addWidget(tabs)
        
        self._refresh_status()
        return widget
    
    def _refresh_status(self):
        status = ai_service_manager.get_status()
        
        if status["configured"]:
            self._status_label.setText("已配置")
            self._status_label.setStyleSheet("font-weight: bold; color: #a6e3a1;")
        else:
            self._status_label.setText("未配置")
            self._status_label.setStyleSheet("font-weight: bold; color: #f38ba8;")
        
        providers = ["选择提供商..."] + status["providers"]
        self._setup_combo(self._provider_combo, providers)
        
        if status["default_provider"]:
            index = self._provider_combo.findText(status["default_provider"])
            if index > 0:
                self._provider_combo.setCurrentIndex(index)
    
    def _add_provider(self):
        provider_type_map = {
            "OpenAI": "openai",
            "Anthropic (Claude)": "anthropic",
            "DeepSeek": "deepseek",
            "通义千问": "qwen",
            "自定义": "openai"
        }
        
        provider_type = provider_type_map.get(self._new_provider_type.currentText(), "openai")
        name = self._new_provider_name.text().strip()
        api_key = self._new_provider_key.text().strip()
        base_url = self._new_provider_url.text().strip()
        model = self._new_provider_model.text().strip()
        
        if not api_key:
            self._add_log(LogLevel.ERROR, "请输入API Key")
            return
        
        if not name:
            name = self._new_provider_type.currentText()
        
        config = {
            "type": provider_type,
            "api_key": api_key,
            "model": model
        }
        
        if base_url:
            config["base_url"] = base_url
        
        if ai_service_manager.add_provider(name, config):
            self._add_log(LogLevel.SUCCESS, f"成功添加提供商: {name}")
            self._refresh_status()
            
            self._new_provider_name.clear()
            self._new_provider_key.clear()
            self._new_provider_url.clear()
            self._new_provider_model.clear()
        else:
            self._add_log(LogLevel.ERROR, "添加提供商失败")
    
    def _send_message(self):
        text = self._chat_input.text().strip()
        if not text:
            return
        
        if not ai_service_manager.is_configured():
            self._add_log(LogLevel.ERROR, "请先配置AI服务")
            return
        
        self._chat_display.append(f"\n<span style='color: #2196F3;'><b>你:</b></span>")
        self._chat_display.append(text)
        self._chat_display.append(f"\n<span style='color: #4CAF50;'><b>AI:</b></span>")
        
        self._chat_input.clear()
        self._send_btn.setEnabled(False)
        
        messages = [AIMessage(role="user", content=text)]
        
        if self._chat_history:
            messages = self._chat_history[-10:] + messages
        
        provider = None
        if self._provider_combo.currentIndex() > 0:
            provider = self._provider_combo.currentText()
        
        self._chat_worker = AIChatWorker(
            messages,
            provider=provider,
            stream=self._stream_check.isChecked(),
            temperature=self._temperature_spin.value() / 100,
            max_tokens=self._max_tokens_spin.value()
        )
        self._chat_worker.stream_received.connect(self._on_stream_received)
        self._chat_worker.response_received.connect(self._on_response_received)
        self._chat_worker.finished_signal.connect(self._on_chat_finished)
        self._chat_worker.start()
    
    def _on_stream_received(self, text):
        cursor = self._chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text)
        self._chat_display.setTextCursor(cursor)
        self._chat_display.ensureCursorVisible()
    
    def _on_response_received(self, content, success):
        if not success:
            self._chat_display.append(f"\n<span style='color: red;'>错误: {content}</span>")
        else:
            self._chat_history.append(AIMessage(role="assistant", content=content))
    
    def _on_chat_finished(self):
        self._send_btn.setEnabled(True)
        self._chat_display.append("\n")
    
    def _clear_chat(self):
        self._chat_display.clear()
        self._chat_history.clear()
    
    def _analyze_current_result(self):
        self._chat_input.setText("请分析当前工具箱的操作结果，提供安全建议。")
        self._send_message()
    
    def _get_suggestions(self):
        history = ai_service_manager.get_operation_history(5)
        if history:
            context = f"最近的操作: {history[-1].get('module', '未知')}"
            self._chat_input.setText(f"基于{context}，请提供下一步测试建议。")
        else:
            self._chat_input.setText("请提供网络安全测试的一般建议和最佳实践。")
        self._send_message()
    
    def _explain_concept(self):
        self._chat_input.setText("请解释以下安全概念：SQL注入、XSS、CSRF、SSRF的区别和检测方法。")
        self._send_message()
    
    def _start_analysis(self):
        data_text = self._analysis_input.toPlainText().strip()
        if not data_text:
            self._add_log(LogLevel.ERROR, "请输入需要分析的数据")
            return
        
        if not ai_service_manager.is_configured():
            self._add_log(LogLevel.ERROR, "请先配置AI服务")
            return
        
        self._analysis_result.clear()
        self._analysis_result.append("正在分析中...\n")
        
        try:
            data = json.loads(data_text)
        except json.JSONDecodeError:
            data = {"raw_data": data_text}
        
        context = self._context_input.text().strip()
        
        self._analysis_worker = AnalysisWorker(data, context if context else None)
        self._analysis_worker.analysis_complete.connect(self._on_analysis_complete)
        self._analysis_worker.start()
    
    def _on_analysis_complete(self, analysis):
        self._analysis_result.clear()
        self._analysis_result.append(analysis)
    
    def _generate_report(self):
        analysis = self._analysis_result.toPlainText()
        if not analysis:
            self._add_log(LogLevel.ERROR, "请先进行分析")
            return
        
        report = result_reporter.generate_report({
            "module": "AI分析",
            "timestamp": time.time(),
            "ai_analysis": analysis,
            "recommendations": []
        })
        
        self._analysis_result.clear()
        self._analysis_result.append(report)
    
    def _refresh_history(self):
        self._history_list.clear()
        history = ai_service_manager.get_operation_history(50)
        
        for item in history:
            module = item.get("module", "未知")
            action = item.get("action", "未知")
            timestamp = time.strftime("%H:%M:%S", time.localtime(item.get("timestamp", 0)))
            
            list_item = QListWidgetItem(f"[{timestamp}] {module} - {action}")
            list_item.setData(Qt.ItemDataRole.UserRole, item)
            self._history_list.addItem(list_item)
    
    def _clear_history(self):
        ai_service_manager._operation_history.clear()
        self._history_list.clear()
    
    def _on_history_item_clicked(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        self._analysis_input.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
    
    def _analyze_selected_history(self):
        selected = self._history_list.currentItem()
        if not selected:
            self._add_log(LogLevel.ERROR, "请选择一个历史记录")
            return
        
        data = selected.data(Qt.ItemDataRole.UserRole)
        analysis = ai_service_manager.analyze_operation(data)
        
        self._analysis_result.clear()
        self._analysis_result.append(analysis)
    
    def _use_template(self, item):
        template = item.data(Qt.ItemDataRole.UserRole)
        self._chat_input.setText(template)
        self._chat_input.setFocus()
    
    def _do_scan(self):
        if not ai_service_manager.is_configured():
            self._add_log(LogLevel.WARNING, "AI服务未配置，请先在配置选项卡中添加API密钥")
        else:
            self._add_log(LogLevel.SUCCESS, "AI服务已就绪，可以在对话选项卡中开始对话")
    
    def stop_scan(self):
        if self._chat_worker:
            self._chat_worker.cancel()
        if self._analysis_worker:
            self._analysis_worker.cancel()
        super().stop_scan()
    
    def record_module_operation(self, module: str, action: str, params: dict, result: any = None):
        operation = {
            "module": module,
            "action": action,
            "params": params,
            "result": str(result)[:1000] if result else None
        }
        ai_service_manager.record_operation(operation)
        
        if self._auto_analyze_check.isChecked() and result:
            analysis = ai_service_manager.analyze_operation(operation)
            self._add_log(LogLevel.INFO, f"AI建议: {analysis[:200]}...")


def get_ai_assistant():
    return ai_service_manager
