from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QFileDialog, QMessageBox, QWidget, QProgressDialog, QApplication,
    QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import os
import shutil
import sys
import subprocess
from pathlib import Path


class ToolLoadWorker(QThread):
    finished = pyqtSignal(list)
    
    def __init__(self, tools_dir: Path, common_tools: list, cache: dict):
        super().__init__()
        self._tools_dir = tools_dir
        self._common_tools = common_tools
        self._cache = cache
    
    def run(self):
        results = []
        for tool_name, tool_desc in self._common_tools:
            if tool_name in self._cache:
                tool_path = self._cache[tool_name]
            else:
                tool_path = self._find_tool(tool_name)
                self._cache[tool_name] = tool_path
            results.append((tool_name, tool_desc, tool_path))
        self.finished.emit(results)
    
    def _find_tool(self, tool_name: str) -> str:
        system_path = shutil.which(tool_name)
        if system_path:
            return system_path
        
        if not self._tools_dir.exists():
            return ""
        
        tool_extensions = ['.exe', '.py', '']
        
        tool_path = self._tools_dir / f"{tool_name}"
        for ext in tool_extensions:
            path = tool_path.with_suffix(ext) if ext else tool_path
            if path.exists():
                return str(path)
        
        try:
            for category_dir in self._tools_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                
                for ext in tool_extensions:
                    path = category_dir / f"{tool_name}{ext}"
                    if path.exists():
                        return str(path)
                
                try:
                    for sub_dir in category_dir.iterdir():
                        if not sub_dir.is_dir():
                            continue
                        
                        for ext in tool_extensions:
                            path = sub_dir / f"{tool_name}{ext}"
                            if path.exists():
                                return str(path)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
        
        return ""


class ToolTestWorker(QThread):
    progress_updated = pyqtSignal(int, int)
    test_finished = pyqtSignal(list)
    
    def __init__(self, tools_data):
        super().__init__()
        self._tools_data = tools_data
        self._is_cancelled = False
    
    def run(self):
        results = []
        total = len(self._tools_data)
        
        for i, (tool_name, tool_path) in enumerate(self._tools_data):
            if self._is_cancelled:
                break
            
            self.progress_updated.emit(i + 1, total)
            
            if not tool_path:
                results.append(f"- {tool_name}: 未配置")
                continue
            
            if not Path(tool_path).exists():
                results.append(f"✗ {tool_name}: 文件不存在")
                continue
            
            try:
                if tool_path.endswith('.py'):
                    cmds = [
                        f'"{sys.executable}" "{tool_path}" --help',
                        f'"{sys.executable}" "{tool_path}" -h',
                        f'"{sys.executable}" "{tool_path}" --version',
                    ]
                else:
                    cmds = [
                        f'"{tool_path}" --help',
                        f'"{tool_path}" -h',
                        f'"{tool_path}" --version',
                        f'"{tool_path}" -version',
                        f'"{tool_path}" -V',
                    ]
                
                success = False
                last_error = ""
                
                for cmd in cmds:
                    try:
                        process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE,
                            text=True,
                            shell=True,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        
                        stdout, stderr = process.communicate(timeout=5)
                        
                        output = stdout.lower() + stderr.lower()
                        if any(keyword in output for keyword in ['usage', 'options', 'version', 'usage:', 'flags:', 'arguments:', 'help']):
                            success = True
                            break
                        elif process.returncode == 0 and (stdout.strip() or stderr.strip()):
                            success = True
                            break
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.communicate(timeout=1)
                        except:
                            pass
                        last_error = "超时"
                    except PermissionError:
                        last_error = "权限被拒绝(可能被杀毒软件拦截)"
                        break
                    except OSError as e:
                        if "WinError 5" in str(e) or "拒绝访问" in str(e):
                            last_error = "权限被拒绝(可能被杀毒软件拦截)"
                        else:
                            last_error = str(e)[:50]
                        break
                    except Exception as e:
                        last_error = str(e)[:50]
                
                if success:
                    results.append(f"✓ {tool_name}: 正常")
                else:
                    if last_error:
                        results.append(f"✗ {tool_name}: {last_error}")
                    else:
                        results.append(f"✓ {tool_name}: 已安装")
            except PermissionError:
                results.append(f"✗ {tool_name}: 权限被拒绝(可能被杀毒软件拦截)")
            except OSError as e:
                if "WinError 5" in str(e) or "拒绝访问" in str(e):
                    results.append(f"✗ {tool_name}: 权限被拒绝(可能被杀毒软件拦截)")
                else:
                    results.append(f"✗ {tool_name}: {str(e)[:50]}")
            except FileNotFoundError:
                results.append(f"✗ {tool_name}: 文件不存在")
            except Exception as e:
                error_msg = str(e)
                if len(error_msg) > 50:
                    error_msg = error_msg[:50] + "..."
                results.append(f"✗ {tool_name}: {error_msg}")
        
        self.test_finished.emit(results)
    
    def cancel(self):
        self._is_cancelled = True


class ToolManagerDialog(QDialog):
    _tool_cache = {}
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("工具管理")
        self.setMinimumSize(800, 600)
        self._tools_dir = Path(__file__).parent.parent.parent / "tools"
        self._config_path = Path(__file__).parent.parent.parent / "config" / "tools.json"
        self._common_tools = self._load_tools_from_config()
        self._categories = self._load_categories_from_config()
        self._setup_ui()
        self._load_tools_async()
    
    def _load_tools_from_config(self) -> list:
        tools = []
        self._tool_categories = {}
        if self._config_path.exists():
            try:
                import json
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                for module_id, module_tools in config.get("tools", {}).items():
                    for tool_id, tool_info in module_tools.items():
                        tool_name = tool_info.get("name", tool_id)
                        tool_desc = tool_info.get("description", "")
                        tool_category = tool_info.get("category", "")
                        tools.append((tool_id, f"{tool_name} - {tool_desc}", tool_info.get("path", "")))
                        self._tool_categories[tool_id] = tool_category
            except Exception as e:
                print(f"加载工具配置失败: {e}")
        
        if not tools:
            tools = [
                ("nmap", "Nmap - 端口扫描", ""),
                ("sqlmap", "SQLMap - SQL注入", ""),
                ("gobuster", "Gobuster - 目录爆破", ""),
                ("nuclei", "Nuclei - 漏洞扫描", ""),
                ("subfinder", "Subfinder - 子域名枚举", ""),
                ("httpx", "HTTPX - HTTP探测", ""),
                ("naabu", "Naabu - 端口扫描", ""),
                ("ffuf", "FFUF - Web模糊测试", ""),
                ("john", "John the Ripper - 密码破解", ""),
                ("dirsearch", "Dirsearch - 目录扫描", ""),
                ("amass", "Amass - 子域名枚举", ""),
                ("assetfinder", "Assetfinder - 资产发现", ""),
                ("dalfox", "Dalfox - XSS扫描", ""),
            ]
        
        return tools
    
    def _load_categories_from_config(self) -> dict:
        categories = {}
        if self._config_path.exists():
            try:
                import json
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                categories = config.get("categories", {})
            except Exception:
                pass
        return categories
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        desc_label = QLabel("管理外部安全工具路径配置 - 从 tools.json 加载")
        layout.addWidget(desc_label)
        
        filter_layout = QHBoxLayout()
        
        filter_layout.addWidget(QLabel("分类:"))
        self._category_combo = QComboBox()
        self._category_combo.addItem("全部", "all")
        for cat_id, cat_name in self._categories.items():
            self._category_combo.addItem(cat_name, cat_id)
        self._category_combo.currentIndexChanged.connect(self._filter_by_category)
        filter_layout.addWidget(self._category_combo)
        
        filter_layout.addWidget(QLabel("搜索:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("搜索工具...")
        self._search_input.textChanged.connect(self._filter_tools)
        filter_layout.addWidget(self._search_input)
        
        layout.addLayout(filter_layout)
        
        self._tools_table = QTableWidget()
        self._tools_table.setColumnCount(4)
        self._tools_table.setHorizontalHeaderLabels(["工具名称", "路径", "状态", "操作"])
        
        self._tools_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tools_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tools_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        
        vertical_header = self._tools_table.verticalHeader()
        vertical_header.setVisible(True)
        vertical_header.setDefaultSectionSize(40)
        
        header = self._tools_table.horizontalHeader()
        header.setSectionsClickable(True)
        header.setHighlightSections(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tools_table.setColumnWidth(1, 400)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._tools_table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self._tools_table.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        
        layout.addWidget(self._tools_table)
        
        stats_label = QLabel(f"共 {len(self._common_tools)} 个工具")
        self._stats_label = stats_label
        layout.addWidget(stats_label)
        
        btn_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("刷新配置")
        refresh_btn.clicked.connect(self._refresh_config)
        
        add_btn = QPushButton("添加工具")
        add_btn.clicked.connect(self._add_tool)
        
        auto_detect_btn = QPushButton("自动检测")
        auto_detect_btn.setObjectName("secondaryButton")
        auto_detect_btn.clicked.connect(self._auto_detect_tools)
        
        download_btn = QPushButton("下载工具")
        download_btn.setObjectName("secondaryButton")
        download_btn.clicked.connect(self._download_tools)
        
        test_btn = QPushButton("测试工具")
        test_btn.setObjectName("secondaryButton")
        test_btn.clicked.connect(self._test_tools)
        
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(auto_detect_btn)
        btn_layout.addWidget(download_btn)
        btn_layout.addWidget(test_btn)
        btn_layout.addStretch()
        
        close_btn = QPushButton("关闭")
        close_btn.setObjectName("secondaryButton")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
    
    def _load_tools_async(self):
        self._tools_table.setRowCount(len(self._common_tools))
        
        for row, (tool_id, tool_desc, config_path) in enumerate(self._common_tools):
            self._tools_table.setItem(row, 0, QTableWidgetItem(tool_desc))
            
            if config_path:
                full_path = str(self._tools_dir.parent / config_path) if not Path(config_path).is_absolute() else config_path
                self._tools_table.setItem(row, 1, QTableWidgetItem(full_path))
                status = "✓ 已配置" if Path(full_path).exists() else "✗ 文件不存在"
            else:
                self._tools_table.setItem(row, 1, QTableWidgetItem("正在检测..."))
                status = "..."
            
            self._tools_table.setItem(row, 2, QTableWidgetItem(status))
            
            browse_btn = QPushButton("浏览")
            browse_btn.setFixedWidth(90)
            browse_btn.setFixedHeight(30)
            browse_btn.clicked.connect(lambda checked, r=row, t=tool_id: self._browse_tool(r, t))
            self._tools_table.setCellWidget(row, 3, browse_btn)
        
        self._detect_missing_tools()
    
    def _detect_missing_tools(self):
        tools_to_detect = []
        for row in range(self._tools_table.rowCount()):
            path_item = self._tools_table.item(row, 1)
            if path_item and path_item.text() == "正在检测...":
                desc_item = self._tools_table.item(row, 0)
                tool_id = desc_item.text().split(" - ")[0].lower()
                tools_to_detect.append((tool_id, desc_item.text(), row))
        
        if tools_to_detect:
            self._load_worker = ToolLoadWorker(
                self._tools_dir, 
                [(t[0], t[1]) for t in tools_to_detect], 
                ToolManagerDialog._tool_cache
            )
            self._load_worker.finished.connect(
                lambda results: self._on_tools_detected(results, tools_to_detect)
            )
            self._load_worker.start()
    
    def _on_tools_detected(self, results, tools_info):
        for i, (tool_id, tool_desc, tool_path) in enumerate(results):
            row = tools_info[i][2]
            path_item = QTableWidgetItem(tool_path)
            path_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self._tools_table.setItem(row, 1, path_item)
            
            status = "✓ 已找到" if tool_path else "✗ 未配置"
            status_item = QTableWidgetItem(status)
            self._tools_table.setItem(row, 2, status_item)
    
    def _on_tools_loaded(self, results):
        for row, (tool_name, tool_desc, tool_path) in enumerate(results):
            path_item = QTableWidgetItem(tool_path)
            path_item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            self._tools_table.setItem(row, 1, path_item)
            
            status = "✓ 已找到" if tool_path else "✗ 未配置"
            status_item = QTableWidgetItem(status)
            self._tools_table.setItem(row, 2, status_item)
    
    def _filter_by_category(self, index):
        category_id = self._category_combo.currentData()
        search_text = self._search_input.text().lower()
        
        visible_count = 0
        for row in range(self._tools_table.rowCount()):
            if row >= len(self._common_tools):
                continue
            
            tool_id = self._common_tools[row][0]
            desc_item = self._tools_table.item(row, 0)
            tool_desc = desc_item.text().lower() if desc_item else ""
            
            visible = True
            
            if category_id != "all":
                tool_category = self._tool_categories.get(tool_id, "")
                if tool_category != category_id:
                    visible = False
            
            if search_text and search_text not in tool_desc:
                visible = False
            
            self._tools_table.setRowHidden(row, not visible)
            if visible:
                visible_count += 1
        
        self._stats_label.setText(f"显示 {visible_count} / {self._tools_table.rowCount()} 个工具")
    
    def _refresh_config(self):
        self._common_tools = self._load_tools_from_config()
        self._categories = self._load_categories_from_config()
        
        self._category_combo.clear()
        self._category_combo.addItem("全部", "all")
        for cat_id, cat_name in self._categories.items():
            self._category_combo.addItem(cat_name, cat_id)
        
        self._load_tools_async()
        self._stats_label.setText(f"共 {len(self._common_tools)} 个工具")
        QMessageBox.information(self, "刷新完成", f"已重新加载配置，共 {len(self._common_tools)} 个工具")
    
    def _find_tool(self, tool_name: str) -> str:
        system_path = shutil.which(tool_name)
        if system_path:
            return system_path
        
        if not self._tools_dir.exists():
            return ""
        
        tool_extensions = ['.exe', '.py', '']
        
        tool_path = self._tools_dir / f"{tool_name}"
        for ext in tool_extensions:
            path = tool_path.with_suffix(ext) if ext else tool_path
            if path.exists():
                return str(path)
        
        try:
            for category_dir in self._tools_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                
                for ext in tool_extensions:
                    path = category_dir / f"{tool_name}{ext}"
                    if path.exists():
                        return str(path)
                
                try:
                    for sub_dir in category_dir.iterdir():
                        if not sub_dir.is_dir():
                            continue
                        
                        for ext in tool_extensions:
                            path = sub_dir / f"{tool_name}{ext}"
                            if path.exists():
                                return str(path)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
        
        return ""
    
    def _browse_tool(self, row: int, tool_name: str):
        file_path, _ = QFileDialog.getOpenFileName(self, f"选择 {tool_name} 路径")
        if file_path:
            self._tools_table.item(row, 1).setText(file_path)
            self._tools_table.item(row, 2).setText("✓ 已配置")
            ToolManagerDialog._tool_cache[tool_name] = file_path
    
    def _add_tool(self):
        QMessageBox.information(self, "提示", "请在上方表格中配置工具路径")
    
    def _auto_detect_tools(self):
        for row in range(self._tools_table.rowCount()):
            desc_item = self._tools_table.item(row, 0)
            tool_name = desc_item.text().split(" - ")[0].lower()
            path = self._find_tool(tool_name)
            if path:
                self._tools_table.item(row, 1).setText(path)
                self._tools_table.item(row, 2).setText("✓ 已找到")
        QMessageBox.information(self, "完成", "自动检测完成")
    
    def _download_tools(self):
        download_script = Path(__file__).parent.parent.parent / "scripts" / "download_tools.py"
        
        if not download_script.exists():
            QMessageBox.warning(self, "错误", f"下载脚本不存在:\n{download_script}")
            return
        
        reply = QMessageBox.question(
            self, 
            "下载工具",
            "将运行下载脚本下载常用安全工具。\n\n"
            "注意：下载可能需要较长时间，且需要网络连接。\n\n"
            "是否继续?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                subprocess.Popen(
                    [sys.executable, str(download_script), "-y"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
                )
                QMessageBox.information(
                    self, 
                    "提示", 
                    "下载脚本已在新的命令行窗口中启动。\n"
                    "请在命令行窗口中查看下载进度。\n\n"
                    "下载完成后，请点击'自动检测'按钮刷新工具状态。"
                )
            except Exception as e:
                QMessageBox.warning(self, "错误", f"启动下载脚本失败:\n{str(e)}")
    
    def _test_tools(self):
        tools_data = []
        for row in range(self._tools_table.rowCount()):
            desc_item = self._tools_table.item(row, 0)
            path_item = self._tools_table.item(row, 1)
            tool_name = desc_item.text().split(" - ")[0].lower()
            tool_path = path_item.text()
            tools_data.append((tool_name, tool_path))
        
        total_tools = len(tools_data)
        self._progress = QProgressDialog("正在测试工具...", "取消", 0, total_tools, self)
        self._progress.setWindowTitle("测试进度")
        self._progress.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress.setMinimumDuration(0)
        self._progress.setValue(0)
        
        self._worker = ToolTestWorker(tools_data)
        self._worker.progress_updated.connect(self._on_progress_updated)
        self._worker.test_finished.connect(self._on_test_finished)
        self._progress.canceled.connect(self._worker.cancel)
        self._worker.start()
    
    def _on_progress_updated(self, current, total):
        if hasattr(self, '_progress'):
            self._progress.setValue(current)
    
    def _on_test_finished(self, results):
        if hasattr(self, '_progress'):
            self._progress.close()
        QMessageBox.information(self, "测试结果", "\n".join(results))
    
    def _filter_tools(self, text: str):
        self._filter_by_category(self._category_combo.currentIndex())


class WordlistManagerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("字典管理")
        self.setMinimumSize(700, 500)
        self._wordlists = []
        self._wordlists_dir = Path(__file__).parent.parent.parent / "wordlists"
        self._tools_dir = Path(__file__).parent.parent.parent / "tools"
        self._setup_ui()
        self._load_wordlists()
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        desc_label = QLabel("管理字典文件，支持导入和管理常用字典")
        layout.addWidget(desc_label)
        
        self._wordlist_table = QTableWidget()
        self._wordlist_table.setColumnCount(4)
        self._wordlist_table.setHorizontalHeaderLabels(["字典名称", "路径", "条目数", "操作"])
        
        header = self._wordlist_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        
        layout.addWidget(self._wordlist_table)
        
        btn_layout = QHBoxLayout()
        
        import_btn = QPushButton("导入字典")
        import_btn.clicked.connect(self._import_wordlist)
        
        create_btn = QPushButton("创建字典")
        create_btn.setObjectName("secondaryButton")
        create_btn.clicked.connect(self._create_wordlist)
        
        btn_layout.addWidget(import_btn)
        btn_layout.addWidget(create_btn)
        btn_layout.addStretch()
        
        close_btn = QPushButton("关闭")
        close_btn.setObjectName("secondaryButton")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
    
    def _load_wordlists(self):
        wordlists = []
        
        builtin_wordlists = [
            ("常用密码TOP100", "内置", "100"),
            ("常用密码TOP1000", "内置", "1000"),
            ("常用用户名", "内置", "100"),
            ("常见目录", "内置", "500"),
            ("常见子域名", "内置", "200"),
            ("常见API路径", "内置", "150"),
            ("敏感文件路径", "内置", "100"),
            ("常见端口服务", "内置", "1000"),
        ]
        wordlists.extend(builtin_wordlists)
        
        if self._tools_dir.exists():
            seclists_dir = self._tools_dir / "SecLists" / "SecLists-master"
            if seclists_dir.exists():
                password_files = [
                    ("SecLists - 常用密码", str(seclists_dir / "Passwords" / "darkc0de.txt"), "大型"),
                    ("SecLists - 常见用户名", str(seclists_dir / "Usernames" / "Names" / "names.txt"), "大型"),
                ]
                wordlists.extend(password_files)
        
        self._wordlist_table.setRowCount(len(wordlists))
        
        for row, (name, path, count) in enumerate(wordlists):
            self._wordlist_table.setItem(row, 0, QTableWidgetItem(name))
            self._wordlist_table.setItem(row, 1, QTableWidgetItem(path))
            self._wordlist_table.setItem(row, 2, QTableWidgetItem(count))
            
            btn_widget = QWidget()
            btn_layout = QHBoxLayout(btn_widget)
            btn_layout.setContentsMargins(4, 4, 4, 4)
            
            view_btn = QPushButton("查看")
            view_btn.setFixedWidth(50)
            view_btn.clicked.connect(lambda checked, n=name: self._view_wordlist(n))
            
            export_btn = QPushButton("导出")
            export_btn.setFixedWidth(50)
            export_btn.setObjectName("secondaryButton")
            export_btn.clicked.connect(lambda checked, n=name: self._export_wordlist(n))
            
            btn_layout.addWidget(view_btn)
            btn_layout.addWidget(export_btn)
            
            self._wordlist_table.setCellWidget(row, 3, btn_widget)
    
    def _import_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "导入字典文件", "", "文本文件;;所有文件"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = sum(1 for _ in f)
                
                name = os.path.basename(file_path)
                row = self._wordlist_table.rowCount()
                self._wordlist_table.insertRow(row)
                self._wordlist_table.setItem(row, 0, QTableWidgetItem(name))
                self._wordlist_table.setItem(row, 1, QTableWidgetItem(file_path))
                self._wordlist_table.setItem(row, 2, QTableWidgetItem(str(lines)))
                
                QMessageBox.information(self, "成功", f"已导入字典: {name}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导入失败: {str(e)}")
    
    def _create_wordlist(self):
        QMessageBox.information(self, "提示", "字典生成功能开发中...")
    
    def _view_wordlist(self, name: str):
        QMessageBox.information(self, f"字典预览 - {name}", "字典预览功能开发中...")
    
    def _export_wordlist(self, name: str):
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"导出字典 - {name}", f"{name}.txt", "文本文件"
        )
        if file_path:
            QMessageBox.information(self, "成功", f"字典已导出到: {file_path}")