import threading
import subprocess
import queue
import re
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from pathlib import Path
from enum import Enum

from .stages import (
    WorkflowStage, STAGES, SCAN_MODES, StageCategory, StageStatus,
    get_stage, get_execution_order, validate_dependencies
)


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
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "by_category": {}
        }
        
        for f in self.findings:
            sev = f.severity.lower()
            if sev in stats:
                stats[sev] += 1
            
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
        self._thread: Optional[threading.Thread] = None
        
        self.callbacks: Dict[str, List[Callable]] = {
            "stage_started": [],
            "stage_completed": [],
            "stage_failed": [],
            "finding_found": [],
            "progress_updated": [],
            "output_received": [],
            "workflow_completed": [],
            "workflow_stopped": []
        }
        
        self._output_queue = queue.Queue()
        
        self._wordlists = {
            "directory": "wordlists/directories/common.txt",
            "lfi": "wordlists/lfi.txt",
            "redirect": "wordlists/redirect.txt"
        }
        
        self._templates_path = "tools/nuclei-templates"
        
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
            
            if self._should_stop:
                break
            
            if not stage.enabled:
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
        from urllib.parse import urlparse
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
                result.status = StageStatus.FAILED
                result.error = f"工具不可用: {stage.tool_name}"
                result.end_time = datetime.now()
                self._emit("stage_failed", stage.id, result.error)
                return result
            
            args = self._build_args(stage)
            cmd = self._build_command(tool_path, args, stage)
            
            self._emit("output_received", stage.id, f"执行: {' '.join(cmd)}")
            
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
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
            
            if self._process.returncode == 0 or result.findings:
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
        
        args = {
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
        
        return args
    
    def _build_command(self, tool_path: str, args: Dict[str, str], stage: WorkflowStage) -> List[str]:
        template = stage.args_template
        
        for key, value in args.items():
            template = template.replace(f"{{{key}}}", value)
        
        tool_name = stage.tool_name.lower()
        
        if tool_name == "nmap":
            return f'"{tool_path}" {template}'
        elif tool_name == "naabu":
            return f'"{tool_path}" {template}'
        elif tool_name == "subfinder":
            return f'"{tool_path}" {template}'
        elif tool_name == "ffuf":
            return f'"{tool_path}" {template}'
        elif tool_name == "httpx":
            return f'"{tool_path}" {template}'
        elif tool_name == "nuclei":
            return f'"{tool_path}" {template}'
        elif tool_name == "katana":
            return f'"{tool_path}" {template}'
        elif tool_name == "tlsx":
            return f'"{tool_path}" {template}'
        elif tool_name == "dnsx":
            return f'"{tool_path}" {template}'
        elif tool_name == "dalfox":
            return f'"{tool_path}" {template}'
        elif tool_name == "sqlmap":
            return f'python "{tool_path}" {template}'
        elif tool_name == "sstimap":
            return f'python "{tool_path}" {template}'
        elif tool_name == "gitleaks":
            return f'"{tool_path}" {template}'
        elif tool_name == "searchsploit":
            return f'python "{tool_path}" {template}'
        elif tool_name == "uncover":
            return f'"{tool_path}" {template}'
        elif tool_name == "cloudlist":
            return f'"{tool_path}" {template}'
        elif tool_name == "cdncheck":
            return f'"{tool_path}" {template}'
        else:
            return f'"{tool_path}" {template}'
    
    def _parse_output(self, stage: WorkflowStage, line: str) -> List[Finding]:
        findings = []
        
        if not line.strip():
            return findings
        
        parser = stage.output_parser
        
        try:
            if parser == "nmap":
                findings = self._parse_nmap(stage.id, line)
            elif parser == "naabu":
                findings = self._parse_naabu(stage.id, line)
            elif parser == "subfinder":
                findings = self._parse_subfinder(stage.id, line)
            elif parser == "ffuf":
                findings = self._parse_ffuf(stage.id, line)
            elif parser == "httpx":
                findings = self._parse_httpx(stage.id, line)
            elif parser == "nuclei":
                findings = self._parse_nuclei(stage.id, line)
            elif parser == "katana":
                findings = self._parse_katana(stage.id, line)
            elif parser == "tlsx":
                findings = self._parse_tlsx(stage.id, line)
            elif parser == "dnsx":
                findings = self._parse_dnsx(stage.id, line)
            elif parser == "dalfox":
                findings = self._parse_dalfox(stage.id, line)
            elif parser == "sqlmap":
                findings = self._parse_sqlmap(stage.id, line)
            elif parser == "sstimap":
                findings = self._parse_sstimap(stage.id, line)
            elif parser == "gitleaks":
                findings = self._parse_gitleaks(stage.id, line)
            elif parser == "searchsploit":
                findings = self._parse_searchsploit(stage.id, line)
            elif parser == "cdncheck":
                findings = self._parse_cdncheck(stage.id, line)
            elif parser == "uncover":
                findings = self._parse_uncover(stage.id, line)
            elif parser == "cloudlist":
                findings = self._parse_cloudlist(stage.id, line)
        except Exception as e:
            pass
        
        return findings
    
    def _parse_nmap(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
        if port_match:
            port = port_match.group(1)
            service = port_match.group(2)
            version = port_match.group(3) or ""
            
            self.info.setdefault("ports", []).append({
                "port": int(port),
                "service": service,
                "version": version.strip()
            })
            
            findings.append(Finding(
                stage_id=stage_id,
                finding_type="open_port",
                severity="info",
                title=f"开放端口: {port}/{service}",
                description=f"发现开放端口 {port}，服务: {service} {version}".strip(),
                evidence=line
            ))
        
        return findings
    
    def _parse_naabu(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            if "port" in data and "host" in data:
                self.info.setdefault("ports", []).append({
                    "port": data["port"],
                    "host": data["host"]
                })
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="open_port",
                    severity="info",
                    title=f"开放端口: {data['port']}",
                    description=f"主机 {data['host']} 开放端口 {data['port']}",
                    evidence=line
                ))
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_subfinder(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            if "host" in data:
                subdomain = data["host"]
                
                self.info.setdefault("subdomains", []).append(subdomain)
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="subdomain",
                    severity="info",
                    title=f"子域名: {subdomain}",
                    description=f"发现子域名: {subdomain}",
                    evidence=line
                ))
        except json.JSONDecodeError:
            if line and "." in line:
                self.info.setdefault("subdomains", []).append(line.strip())
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="subdomain",
                    severity="info",
                    title=f"子域名: {line.strip()}",
                    description=f"发现子域名: {line.strip()}",
                    evidence=line
                ))
        
        return findings
    
    def _parse_ffuf(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            if "url" in data and "status" in data:
                url = data["url"]
                status = data["status"]
                
                self.info.setdefault("directories", []).append({
                    "url": url,
                    "status": status,
                    "size": data.get("length", 0)
                })
                
                severity = "info"
                if status == 200:
                    severity = "low"
                elif status in [401, 403]:
                    severity = "info"
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="directory",
                    severity=severity,
                    title=f"目录发现: {url} [{status}]",
                    description=f"发现路径: {url}，状态码: {status}",
                    url=url,
                    evidence=line
                ))
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_httpx(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            url = data.get("url", "")
            title = data.get("title", "")
            webserver = data.get("webserver", "")
            tech = data.get("tech", [])
            
            self.info["url"] = url
            self.info["title"] = title
            self.info["webserver"] = webserver
            self.info["tech"] = tech
            
            if tech:
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="fingerprint",
                    severity="info",
                    title=f"技术栈: {', '.join(tech)}",
                    description=f"检测到技术栈: {', '.join(tech)}",
                    url=url,
                    evidence=line
                ))
            
            if webserver:
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="fingerprint",
                    severity="info",
                    title=f"Web服务器: {webserver}",
                    description=f"检测到Web服务器: {webserver}",
                    url=url,
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_nuclei(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            template_id = data.get("template-id", "")
            info = data.get("info", {})
            matched_at = data.get("matched-at", "")
            
            severity = info.get("severity", "info").lower()
            name = info.get("name", template_id)
            description = info.get("description", "")
            
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "info"
            }
            
            findings.append(Finding(
                stage_id=stage_id,
                finding_type="vulnerability",
                severity=severity_map.get(severity, "info"),
                title=f"[{severity.upper()}] {name}",
                description=description or f"检测到漏洞: {name}",
                url=matched_at,
                evidence=line
            ))
            
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_katana(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            url = data.get("request", {}).get("endpoint", "")
            method = data.get("request", {}).get("method", "GET")
            
            if url:
                self.info.setdefault("endpoints", []).append({
                    "url": url,
                    "method": method
                })
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_tlsx(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            version = data.get("version", "")
            cipher = data.get("cipher", "")
            
            self.info["ssl"] = {
                "version": version,
                "cipher": cipher
            }
            
            if "tls1.0" in version.lower() or "tls1.1" in version.lower():
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="ssl_issue",
                    severity="medium",
                    title=f"弱TLS版本: {version}",
                    description=f"检测到弱TLS版本: {version}，建议升级到TLS 1.2或更高版本",
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_dnsx(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            host = data.get("host", "")
            self.info.setdefault("dns_records", []).append(data)
            
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_dalfox(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            if data.get("type") == "found":
                url = data.get("data", {}).get("url", "")
                param = data.get("data", {}).get("param", "")
                poc = data.get("data", {}).get("poc", "")
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="xss",
                    severity="high",
                    title=f"XSS漏洞: {param}",
                    description=f"检测到反射型XSS漏洞，参数: {param}",
                    url=url,
                    evidence=f"PoC: {poc}"
                ))
                
        except json.JSONDecodeError:
            if "found" in line.lower() and "xss" in line.lower():
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="xss",
                    severity="high",
                    title="XSS漏洞",
                    description="检测到XSS漏洞",
                    evidence=line
                ))
        
        return findings
    
    def _parse_sqlmap(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        if "sql injection" in line.lower() or "injectable" in line.lower():
            findings.append(Finding(
                stage_id=stage_id,
                finding_type="sqli",
                severity="critical",
                title="SQL注入漏洞",
                description="检测到SQL注入漏洞",
                evidence=line
            ))
        
        if "Parameter:" in line:
            match = re.search(r'Parameter:\s*(\S+)', line)
            if match:
                self.info["sqli_param"] = match.group(1)
        
        return findings
    
    def _parse_sstimap(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        if "[+]" in line:
            if "injection" in line.lower():
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="ssti",
                    severity="high",
                    title="SSTI漏洞",
                    description="检测到服务端模板注入漏洞",
                    evidence=line
                ))
        
        if "Engine:" in line:
            match = re.search(r'Engine:\s*(\w+)', line)
            if match:
                self.info["ssti_engine"] = match.group(1)
        
        return findings
    
    def _parse_gitleaks(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            if data.get("RuleID"):
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="secret_leak",
                    severity="high",
                    title=f"密钥泄露: {data.get('RuleID', 'Unknown')}",
                    description=f"检测到敏感信息泄露: {data.get('Description', '')}",
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_searchsploit(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            for item in data.get("RESULTS_EXPLOIT", []):
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="exploit",
                    severity="medium",
                    title=f"CVE/Exploit: {item.get('Title', '')}",
                    description=f"发现相关漏洞利用: {item.get('Title', '')}",
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_cdncheck(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            if data.get("cdn"):
                self.info["cdn"] = data.get("cdn_name", "Unknown")
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="cdn",
                    severity="info",
                    title=f"CDN检测: {data.get('cdn_name', 'Unknown')}",
                    description=f"目标使用CDN: {data.get('cdn_name', 'Unknown')}",
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_uncover(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            if "host" in data:
                self.info.setdefault("search_results", []).append(data)
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _parse_cloudlist(self, stage_id: str, line: str) -> List[Finding]:
        findings = []
        
        try:
            data = json.loads(line)
            
            if data.get("service"):
                self.info.setdefault("cloud_assets", []).append(data)
                
                findings.append(Finding(
                    stage_id=stage_id,
                    finding_type="cloud_asset",
                    severity="info",
                    title=f"云资产: {data.get('service', 'Unknown')}",
                    description=f"发现云平台资产: {data.get('service', 'Unknown')}",
                    evidence=line
                ))
                
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def start_async(self, target: str, callback: Callable = None):
        def run():
            result = self.execute(target)
            if callback:
                callback(result)
        
        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
    
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
