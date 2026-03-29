import threading
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

from .stages import (
    WorkflowStage, STAGES, SCAN_MODES, StageCategory, StageStatus,
    get_execution_order, validate_dependencies
)
from .result_parser import ResultParser


@dataclass
class Finding:
    stage_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    url: str = ""
    raw_output: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        return {
            "stage_id": self.stage_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "url": self.url,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class StageResult:
    stage_id: str
    status: StageStatus
    start_time: datetime = None
    end_time: datetime = None
    output: str = ""
    findings: List[Finding] = field(default_factory=list)
    error: str = ""
    raw_output: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "stage_id": self.stage_id,
            "status": self.status.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error
        }


@dataclass
class WorkflowResult:
    target: str
    mode: str
    start_time: datetime = None
    end_time: datetime = None
    stages: Dict[str, StageResult] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_stage(self, stage_id: str) -> List[Finding]:
        return [f for f in self.findings if f.stage_id == stage_id]
    
    def get_statistics(self) -> Dict:
        stats = {
            "total_findings": len(self.findings),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "by_category": {}
        }
        
        for f in self.findings:
            sev = f.severity.lower()
            if sev in stats:
                stats[sev] += 1
            else:
                stats["info"] += 1
            stage = STAGES.get(f.stage_id)
            if stage:
                cat = stage.category.value
                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        
        return stats
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "stages": {k: v.to_dict() for k, v in self.stages.items()},
            "findings": [f.to_dict() for f in self.findings],
            "info": self.info,
            "statistics": self.get_statistics()
        }


PYTHON_TOOLS = {"sqlmap", "sstimap", "fenjing", "searchsploit", "dirsearch"}


class WorkflowEngine:
    def __init__(self, tool_manager=None):
        self.tool_manager = tool_manager
        self.stages: Dict[str, WorkflowStage] = {}
        self.results: Dict[str, StageResult] = {}
        self.findings: List[Finding] = []
        self.info: Dict[str, Any] = {}
        
        self.current_stage: Optional[str] = None
        self.target: str = ""
        self.mode: str = "quick"
        
        self._is_running = False
        self._is_paused = False
        self._should_stop = False
        self._process: Optional[subprocess.Popen] = None
        
        self.callbacks: Dict[str, List[Callable]] = {
            "stage_started": [], "stage_completed": [], "stage_failed": [],
            "finding_found": [], "progress_updated": [], "output_received": [],
            "workflow_completed": [], "workflow_stopped": []
        }
        
        self._wordlists = {
            "directory": "wordlists/directories/common.txt",
            "lfi": "wordlists/lfi.txt",
            "redirect": "wordlists/redirect.txt"
        }
        self._templates_path = "tools/nuclei-templates/nuclei-templates-main"
        self._parser = ResultParser()
        
        self._proxy = None
        self._timeout = 300
        self._threads = 5
        self._retry = 3
        self._delay = 0
        self._custom_headers = None
        self._cookies = None
        
        self._load_config()
    
    def _load_config(self):
        try:
            from gui.dialogs.settings_dialog import load_config
            config = load_config()
            self._threads = config.get("threads", 5)
            self._timeout = config.get("timeout", 30) * 60
            self._retry = config.get("retry", 3)
            self._delay = config.get("delay", 0)
            
            if config.get("proxy_enabled", False):
                self._proxy = config.get("http_proxy", "") or config.get("https_proxy", "")
        except:
            pass
    
    def set_tool_manager(self, tool_manager):
        self.tool_manager = tool_manager
    
    def set_wordlists(self, wordlists: Dict[str, str]):
        self._wordlists.update(wordlists)
    
    def set_templates_path(self, path: str):
        self._templates_path = path
    
    def on(self, event: str, callback: Callable):
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def _emit(self, event: str, *args, **kwargs):
        for callback in self.callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def configure(self, mode: str = "quick", custom_stages: List[str] = None):
        self.mode = mode
        
        if custom_stages:
            if not validate_dependencies(custom_stages):
                raise ValueError("阶段依赖关系无效")
            stage_ids = get_execution_order(custom_stages)
        else:
            mode_config = SCAN_MODES.get(mode, SCAN_MODES["quick"])
            stage_ids = get_execution_order(mode_config["stages"])
        
        self.stages = {sid: STAGES[sid] for sid in stage_ids if sid in STAGES}
        return list(self.stages.keys())
    
    def execute(self, target: str) -> WorkflowResult:
        self.target = self._normalize_target(target)
        self._is_running = True
        self._should_stop = False
        self.results.clear()
        self.findings.clear()
        self.info.clear()
        
        result = WorkflowResult(
            target=self.target,
            mode=self.mode,
            start_time=datetime.now()
        )
        
        self._emit("workflow_started", self.target)
        
        for stage_id, stage in self.stages.items():
            if self._should_stop:
                break
            
            while self._is_paused:
                time.sleep(0.5)
                if self._should_stop:
                    break
            
            if self._should_stop or not stage.enabled:
                continue
            
            deps_met = all(
                self.results.get(dep, StageResult("", StageStatus.PENDING)).status == StageStatus.COMPLETED
                for dep in stage.dependencies
            )
            
            if not deps_met:
                self.results[stage_id] = StageResult(
                    stage_id=stage_id,
                    status=StageStatus.SKIPPED,
                    error="依赖阶段未完成"
                )
                continue
            
            self.current_stage = stage_id
            stage_result = self._execute_stage(stage)
            self.results[stage_id] = stage_result
            result.stages[stage_id] = stage_result
            
            self.findings.extend(stage_result.findings)
            result.findings = self.findings
            
            progress = self.get_progress()
            self._emit("progress_updated", progress)
        
        result.end_time = datetime.now()
        result.info = self.info
        
        self._is_running = False
        self._emit("workflow_completed", result)
        
        return result
    
    def _normalize_target(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target
    
    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0]
    
    def _execute_stage(self, stage: WorkflowStage) -> StageResult:
        result = StageResult(
            stage_id=stage.id,
            status=StageStatus.RUNNING,
            start_time=datetime.now()
        )
        
        self._emit("stage_started", stage.id, stage.name)
        
        try:
            tool_path = self._get_tool_path(stage.tool_name, stage.tool_category)
            if not tool_path:
                result.status = StageStatus.SKIPPED
                result.error = f"工具未安装: {stage.tool_name}"
                result.end_time = datetime.now()
                self._emit("stage_failed", stage.id, result.error)
                return result
            
            args = self._build_args(stage)
            cmd = self._build_command(tool_path, args, stage)
            
            self._emit("output_received", stage.id, f"执行: {cmd}")
            
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                shell=True,
                creationflags=creation_flags
            )
            
            output_lines = []
            
            while True:
                if self._should_stop:
                    self._process.terminate()
                    break
                
                line = self._process.stdout.readline()
                if not line:
                    if self._process.poll() is not None:
                        break
                    continue
                
                line = line.rstrip()
                output_lines.append(line)
                self._emit("output_received", stage.id, line)
                
                findings = self._parse_output(stage, line)
                for finding in findings:
                    result.findings.append(finding)
                    self._emit("finding_found", finding)
            
            result.output = '\n'.join(output_lines)
            result.raw_output = result.output
            
            if self._process.returncode == 0 or result.findings or output_lines:
                result.status = StageStatus.COMPLETED
                self._emit("stage_completed", stage.id, result)
            else:
                result.status = StageStatus.FAILED
                result.error = f"工具返回非零状态: {self._process.returncode}"
                self._emit("stage_failed", stage.id, result.error)
            
        except Exception as e:
            result.status = StageStatus.FAILED
            result.error = str(e)
            self._emit("stage_failed", stage.id, str(e))
        
        result.end_time = datetime.now()
        return result
    
    def _get_tool_path(self, tool_name: str, tool_category: str) -> Optional[str]:
        if self.tool_manager:
            tool_info = self.tool_manager.get_tool(tool_category, tool_name)
            if tool_info and tool_info.available:
                return str(tool_info.path)
        return None
    
    def _build_args(self, stage: WorkflowStage) -> Dict[str, str]:
        domain = self._extract_domain(self.target)
        
        return {
            "target": domain,
            "url": self.target,
            "domain": domain,
            "ports": "1-1000",
            "wordlist": self._wordlists.get("directory", "wordlists/directories/common.txt"),
            "lfi_wordlist": self._wordlists.get("lfi", "wordlists/lfi.txt"),
            "redirect_wordlist": self._wordlists.get("redirect", "wordlists/redirect.txt"),
            "templates": self._templates_path,
            "query": f'host:"{domain}"',
            "search_term": domain
        }
    
    def _build_command(self, tool_path: str, args: Dict[str, str], stage: WorkflowStage) -> str:
        template = stage.args_template
        
        for key, value in args.items():
            template = template.replace(f"{{{key}}}", value)
        
        tool_name = stage.tool_name.lower()
        
        extra_args = []
        
        if self._proxy:
            if tool_name in ["nmap"]:
                extra_args.append(f"--proxy {self._proxy}")
            elif tool_name in ["httpx", "nuclei", "katana", "naabu", "tlsx", "dnsx", "uncover", "cloudlist", "cdncheck"]:
                extra_args.append(f"-proxy {self._proxy}")
            elif tool_name in ["ffuf", "feroxbuster", "gobuster"]:
                extra_args.append(f"-x {self._proxy}")
            elif tool_name in ["dalfox"]:
                extra_args.append(f"--proxy {self._proxy}")
            elif tool_name in ["sqlmap"]:
                extra_args.append(f"--proxy={self._proxy}")
        
        if self._custom_headers:
            if tool_name in ["httpx", "nuclei", "katana"]:
                for header in self._custom_headers.split(","):
                    if ":" in header:
                        extra_args.append(f"-H \"{header.strip()}\"")
            elif tool_name in ["ffuf", "feroxbuster"]:
                for header in self._custom_headers.split(","):
                    if ":" in header:
                        extra_args.append(f"-H \"{header.strip()}\"")
        
        if self._cookies:
            if tool_name in ["httpx", "nuclei", "katana", "dalfox"]:
                extra_args.append(f"-cookie \"{self._cookies}\"")
            elif tool_name in ["sqlmap"]:
                extra_args.append(f"--cookie=\"{self._cookies}\"")
        
        if extra_args:
            template = f"{template} {' '.join(extra_args)}"
        
        if tool_name in PYTHON_TOOLS:
            return f'python "{tool_path}" {template}'
        return f'"{tool_path}" {template}'
    
    def _parse_output(self, stage: WorkflowStage, line: str) -> List[Finding]:
        if not line.strip():
            return []
        
        try:
            parsed = self._parser.parse(stage.output_parser, line)
            findings = []
            
            for p in parsed:
                finding = Finding(
                    stage_id=stage.id,
                    finding_type=p.finding_type,
                    severity=p.severity,
                    title=p.title,
                    description=p.description,
                    evidence=p.evidence,
                    url=p.url
                )
                findings.append(finding)
                
                if p.raw_data:
                    self._update_info(stage, p.raw_data)
            
            return findings
        except Exception:
            return []
    
    def _update_info(self, stage: WorkflowStage, data: Dict):
        if stage.output_parser == "naabu":
            self.info.setdefault("ports", []).append(data)
        elif stage.output_parser == "subfinder":
            self.info.setdefault("subdomains", []).append(data.get("host", ""))
        elif stage.output_parser == "httpx":
            if "tech" in data:
                self.info["tech"] = data["tech"]
            if "webserver" in data:
                self.info["webserver"] = data["webserver"]
    
    def start_async(self, target: str, callback: Callable = None):
        def run():
            result = self.execute(target)
            if callback:
                callback(result)
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
    
    def pause(self):
        self._is_paused = True
    
    def resume(self):
        self._is_paused = False
    
    def stop(self):
        self._should_stop = True
        self._is_paused = False
        
        if self._process:
            try:
                self._process.terminate()
            except:
                pass
        
        self._emit("workflow_stopped")
    
    def is_running(self) -> bool:
        return self._is_running
    
    def get_progress(self) -> Dict:
        total = len(self.stages)
        completed = sum(1 for r in self.results.values() if r.status == StageStatus.COMPLETED)
        failed = sum(1 for r in self.results.values() if r.status == StageStatus.FAILED)
        
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "current": self.current_stage,
            "percentage": int((completed + failed) / total * 100) if total > 0 else 0
        }
