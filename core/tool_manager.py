import os
import subprocess
import json
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import threading
import queue


class ToolType(Enum):
    EXECUTABLE = "executable"
    PYTHON = "python"
    PERL = "perl"
    RUBY = "ruby"
    ARCHIVE = "archive"


@dataclass
class ToolInfo:
    name: str
    path: Path
    description: str
    tool_type: ToolType
    version: str = ""
    category: str = ""
    templates: Optional[Path] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def available(self) -> bool:
        return self.path.exists()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "description": self.description,
            "type": self.tool_type.value,
            "version": self.version,
            "category": self.category,
            "available": self.available
        }


class ToolExecutor:
    def __init__(self, tool_info: ToolInfo, base_path: Path):
        self._tool = tool_info
        self._base_path = base_path
        self._process: Optional[subprocess.Popen] = None
        self._output_queue: queue.Queue = queue.Queue()
        self._error_queue: queue.Queue = queue.Queue()
    
    def build_command(self, args: List[str]) -> List[str]:
        cmd = []
        tool_type = self._tool.tool_type
        
        if tool_type == ToolType.PYTHON:
            cmd = ["python", str(self._tool.path)] + args
        elif tool_type == ToolType.PERL:
            cmd = ["perl", str(self._tool.path)] + args
        elif tool_type == ToolType.RUBY:
            cmd = ["ruby", str(self._tool.path)] + args
        else:
            cmd = [str(self._tool.path)] + args
        
        return cmd
    
    def execute(self, args: List[str], timeout: Optional[int] = None,
                on_output: Optional[Callable[[str], None]] = None,
                on_error: Optional[Callable[[str], None]] = None) -> subprocess.Popen:
        cmd = self.build_command(args)
        
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creation_flags,
            cwd=str(self._base_path)
        )
        
        if on_output or on_error:
            self._start_output_handlers(on_output, on_error)
        
        return self._process
    
    def _start_output_handlers(self, on_output: Optional[Callable], on_error: Optional[Callable]):
        def read_stdout():
            if self._process and self._process.stdout:
                for line in self._process.stdout:
                    if on_output:
                        on_output(line.rstrip())
        
        def read_stderr():
            if self._process and self._process.stderr:
                for line in self._process.stderr:
                    if on_error:
                        on_error(line.rstrip())
        
        if on_output:
            threading.Thread(target=read_stdout, daemon=True).start()
        if on_error:
            threading.Thread(target=read_stderr, daemon=True).start()
    
    def terminate(self):
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
    
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None


class ToolManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        
        self._base_path = Path(__file__).parent.parent
        self._tools_dir = self._base_path / "tools"
        self._tools: Dict[str, Dict[str, ToolInfo]] = {}
        self._categories: Dict[str, str] = {}
        self._executors: Dict[str, ToolExecutor] = {}
        
        self._load_tools()
    
    def _get_config_path(self) -> Path:
        return self._base_path / "config" / "tools.json"
    
    def _load_tools(self):
        config_path = self._get_config_path()
        
        if config_path.exists():
            self._load_from_config(config_path)
        else:
            self._load_default_tools()
    
    def _load_from_config(self, config_path: Path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self._categories = config.get("categories", {})
            
            for module_id, tools in config.get("tools", {}).items():
                self._tools[module_id] = {}
                for tool_name, tool_data in tools.items():
                    tool_path = self._base_path / tool_data["path"]
                    tool_type = ToolType(tool_data.get("type", "executable"))
                    
                    templates = None
                    if "templates" in tool_data:
                        templates = self._base_path / tool_data["templates"]
                    
                    self._tools[module_id][tool_name] = ToolInfo(
                        name=tool_data.get("name", tool_name),
                        path=tool_path,
                        description=tool_data.get("description", ""),
                        tool_type=tool_type,
                        version=tool_data.get("version", ""),
                        category=tool_data.get("category", ""),
                        templates=templates,
                        extra={k: v for k, v in tool_data.items() 
                               if k not in ["name", "path", "description", "type", "version", "category", "templates"]}
                    )
        except Exception as e:
            self._load_default_tools()
    
    def _load_default_tools(self):
        self._tools = {}
        self._categories = {
            "network": "网络扫描",
            "recon": "信息收集",
            "web": "Web安全",
            "scanner": "漏洞扫描",
            "exploit": "漏洞利用",
            "password": "密码破解",
            "proxy": "代理隧道",
            "internal": "内网渗透",
            "crypto": "加密解密"
        }
    
    def register_tool(self, module_id: str, tool_name: str, tool_info: ToolInfo):
        if module_id not in self._tools:
            self._tools[module_id] = {}
        self._tools[module_id][tool_name] = tool_info
    
    def get_tool(self, module_id: str, tool_name: str) -> Optional[ToolInfo]:
        return self._tools.get(module_id, {}).get(tool_name)
    
    def get_tools_for_module(self, module_id: str) -> Dict[str, ToolInfo]:
        return self._tools.get(module_id, {})
    
    def get_executor(self, module_id: str, tool_name: str) -> Optional[ToolExecutor]:
        tool = self.get_tool(module_id, tool_name)
        if tool:
            key = f"{module_id}:{tool_name}"
            if key not in self._executors:
                self._executors[key] = ToolExecutor(tool, self._base_path)
            return self._executors[key]
        return None
    
    def execute_tool(self, module_id: str, tool_name: str, args: List[str],
                    on_output: Optional[Callable[[str], None]] = None,
                    on_error: Optional[Callable[[str], None]] = None,
                    timeout: Optional[int] = None) -> subprocess.Popen:
        tool = self.get_tool(module_id, tool_name)
        if not tool:
            raise ValueError(f"Tool {tool_name} not found for module {module_id}")
        
        if not tool.available:
            raise FileNotFoundError(f"Tool not found: {tool.path}")
        
        executor = self.get_executor(module_id, tool_name)
        return executor.execute(args, timeout, on_output, on_error)
    
    def get_tool_path(self, module_id: str, tool_name: str) -> Optional[Path]:
        tool = self.get_tool(module_id, tool_name)
        return tool.path if tool else None
    
    def is_tool_available(self, module_id: str, tool_name: str) -> bool:
        tool = self.get_tool(module_id, tool_name)
        return tool.available if tool else False
    
    def get_all_modules(self) -> List[str]:
        return list(self._tools.keys())
    
    def get_module_tools_info(self, module_id: str) -> List[Dict[str, Any]]:
        tools = self.get_tools_for_module(module_id)
        return [tool.to_dict() for tool in tools.values()]
    
    def get_categories(self) -> Dict[str, str]:
        return self._categories.copy()
    
    def get_tools_by_category(self, category: str) -> Dict[str, List[ToolInfo]]:
        result = {}
        for module_id, tools in self._tools.items():
            category_tools = [t for t in tools.values() if t.category == category]
            if category_tools:
                result[module_id] = category_tools
        return result
    
    def save_config(self):
        config_path = self._get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        tools_config = {}
        for module_id, tools in self._tools.items():
            tools_config[module_id] = {}
            for tool_name, tool in tools.items():
                tools_config[module_id][tool_name] = {
                    "path": str(tool.path.relative_to(self._base_path)),
                    "name": tool.name,
                    "description": tool.description,
                    "type": tool.tool_type.value,
                    "version": tool.version,
                    "category": tool.category,
                    **tool.extra
                }
        
        config = {
            "tools": tools_config,
            "categories": self._categories
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    
    def stop_all_executors(self):
        for executor in self._executors.values():
            executor.terminate()
        self._executors.clear()


tool_manager = ToolManager()
