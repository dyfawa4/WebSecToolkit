import subprocess
import threading
import os
import queue
from typing import Optional, Callable, List, Dict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolResult:
    success: bool
    output: str
    error: str
    return_code: int
    findings: List[Dict] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []


class ToolRunner:
    def __init__(self, tool_manager=None):
        self.tool_manager = tool_manager
        self._process: Optional[subprocess.Popen] = None
        self._is_running = False
        self._should_stop = False
        self._output_queue = queue.Queue()
        
    def get_tool_path(self, tool_category: str, tool_name: str) -> Optional[str]:
        if self.tool_manager:
            tool_info = self.tool_manager.get_tool(tool_category, tool_name)
            if tool_info and tool_info.available:
                return str(tool_info.path)
        return None
    
    def is_tool_available(self, tool_category: str, tool_name: str) -> bool:
        if self.tool_manager:
            return self.tool_manager.is_tool_available(tool_category, tool_name)
        return False
    
    def run(self, 
            tool_category: str,
            tool_name: str,
            args: str,
            timeout: int = 300,
            output_callback: Callable[[str], None] = None,
            cwd: str = None) -> ToolResult:
        
        tool_path = self.get_tool_path(tool_category, tool_name)
        
        if not tool_path:
            return ToolResult(
                success=False,
                output="",
                error=f"工具不可用: {tool_name}",
                return_code=-1
            )
        
        cmd = self._build_command(tool_name, tool_path, args)
        
        return self._execute(cmd, timeout, output_callback, cwd)
    
    def run_command(self,
                    command: str,
                    timeout: int = 300,
                    output_callback: Callable[[str], None] = None,
                    cwd: str = None) -> ToolResult:
        return self._execute(command, timeout, output_callback, cwd)
    
    def _build_command(self, tool_name: str, tool_path: str, args: str) -> str:
        tool_name = tool_name.lower()
        
        if tool_name == "nmap":
            return f'"{tool_path}" {args}'
        elif tool_name == "naabu":
            return f'"{tool_path}" {args}'
        elif tool_name == "subfinder":
            return f'"{tool_path}" {args}'
        elif tool_name == "ffuf":
            return f'"{tool_path}" {args}'
        elif tool_name == "httpx":
            return f'"{tool_path}" {args}'
        elif tool_name == "nuclei":
            return f'"{tool_path}" {args}'
        elif tool_name == "katana":
            return f'"{tool_path}" {args}'
        elif tool_name == "tlsx":
            return f'"{tool_path}" {args}'
        elif tool_name == "dnsx":
            return f'"{tool_path}" {args}'
        elif tool_name == "dalfox":
            return f'"{tool_path}" {args}'
        elif tool_name == "sqlmap":
            return f'python "{tool_path}" {args}'
        elif tool_name == "sstimap":
            return f'python "{tool_path}" {args}'
        elif tool_name == "fenjing":
            return f'python -m fenjing {args}'
        elif tool_name == "gitleaks":
            return f'"{tool_path}" {args}'
        elif tool_name == "searchsploit":
            return f'python "{tool_path}" {args}'
        elif tool_name == "uncover":
            return f'"{tool_path}" {args}'
        elif tool_name == "cloudlist":
            return f'"{tool_path}" {args}'
        elif tool_name == "cdncheck":
            return f'"{tool_path}" {args}'
        elif tool_name == "rustscan":
            return f'"{tool_path}" {args}'
        elif tool_name == "dirsearch":
            return f'python "{tool_path}" {args}'
        elif tool_name == "gobuster":
            return f'"{tool_path}" {args}'
        elif tool_name == "feroxbuster":
            return f'"{tool_path}" {args}'
        elif tool_name == "assetfinder":
            return f'"{tool_path}" {args}'
        elif tool_name == "subdominator":
            return f'"{tool_path}" {args}'
        else:
            return f'"{tool_path}" {args}'
    
    def _execute(self,
                 command: str,
                 timeout: int,
                 output_callback: Callable[[str], None],
                 cwd: str = None) -> ToolResult:
        
        self._is_running = True
        self._should_stop = False
        output_lines = []
        error_lines = []
        
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                cwd=cwd,
                creationflags=creation_flags
            )
            
            def read_stdout():
                for line in self._process.stdout:
                    if self._should_stop:
                        break
                    line = line.rstrip()
                    output_lines.append(line)
                    if output_callback:
                        output_callback(line)
                    self._output_queue.put(('stdout', line))
            
            def read_stderr():
                for line in self._process.stderr:
                    if self._should_stop:
                        break
                    line = line.rstrip()
                    error_lines.append(line)
                    self._output_queue.put(('stderr', line))
            
            stdout_thread = threading.Thread(target=read_stdout, daemon=True)
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            
            stdout_thread.start()
            stderr_thread.start()
            
            try:
                self._process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                return ToolResult(
                    success=False,
                    output='\n'.join(output_lines),
                    error="命令执行超时",
                    return_code=-1
                )
            
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)
            
            return_code = self._process.returncode
            
            return ToolResult(
                success=return_code == 0,
                output='\n'.join(output_lines),
                error='\n'.join(error_lines),
                return_code=return_code
            )
            
        except Exception as e:
            return ToolResult(
                success=False,
                output='\n'.join(output_lines),
                error=str(e),
                return_code=-1
            )
        finally:
            self._is_running = False
            self._process = None
    
    def stop(self):
        self._should_stop = True
        if self._process:
            try:
                self._process.kill()
            except:
                pass
    
    def is_running(self) -> bool:
        return self._is_running


TOOL_COMMANDS = {
    "nmap": {
        "quick_scan": "-sV -sC -F --open -Pn {target}",
        "full_scan": "-sV -sC -p- --open -Pn {target}",
        "vuln_scan": "-sV --script=vuln --open -Pn {target}",
        "udp_scan": "-sU --top-ports 100 --open -Pn {target}"
    },
    "naabu": {
        "quick_scan": "-host {target} -top-ports 100 -silent -json",
        "full_scan": "-host {target} -p - -silent -json",
        "top_ports": "-host {target} -top-ports {ports} -silent -json"
    },
    "subfinder": {
        "enum": "-d {domain} -silent -json",
        "recursive": "-d {domain} -recursive -silent -json",
        "bruteforce": "-d {domain} -silent -json -b"
    },
    "ffuf": {
        "directory": "-u {url}/FUZZ -w {wordlist} -mc 200,301,302,403,500 -t 50 -silent -json",
        "subdomain": "-u http://FUZZ.{domain} -w {wordlist} -mc 200,301,302 -t 50 -silent -json",
        "parameter": "-u {url}?FUZZ=test -w {wordlist} -mc 200,301,302 -t 50 -silent -json"
    },
    "httpx": {
        "probe": "-u {url} -silent -json -tech-detect -status-code -title -web-server",
        "screenshot": "-u {url} -silent -json -screenshot",
        "fingerprint": "-u {url} -silent -json -tech-detect -cdn -waf"
    },
    "nuclei": {
        "quick": "-u {url} -silent -json -severity critical,high",
        "full": "-u {url} -silent -json",
        "custom": "-u {url} -silent -json -t {templates} -severity {severity}"
    },
    "katana": {
        "crawl": "-u {url} -silent -json -aff -depth 3",
        "passive": "-u {url} -silent -json -passive",
        "forms": "-u {url} -silent -json -aff -form-scope"
    },
    "tlsx": {
        "analyze": "-u {target} -silent -json",
        "cert_info": "-u {target} -silent -json -cert",
        "cipher": "-u {target} -silent -json -cipher"
    },
    "dnsx": {
        "enum": "-d {domain} -silent -json -a -aaaa -cname -mx -ns -txt",
        "bruteforce": "-d {domain} -w {wordlist} -silent -json",
        "resolve": "-l {list} -silent -json -a -resp"
    },
    "dalfox": {
        "scan": "url {url} --silence --format json",
        "pipe": "pipe --silence --format json",
        "custom": "url {url} --silence --format json --only-poc r"
    },
    "sqlmap": {
        "quick": "-u {url} --batch --level=1 --risk=1 --threads=5",
        "deep": "-u {url} --batch --level=3 --risk=2 --threads=5",
        "dbs": "-u {url} --batch --dbs",
        "tables": "-u {url} --batch -D {db} --tables",
        "dump": "-u {url} --batch -D {db} -T {table} --dump"
    },
    "sstimap": {
        "scan": "-u {url} --level 1",
        "deep": "-u {url} --level 3",
        "shell": "-u {url} --os-shell"
    },
    "fenjing": {
        "scan": "scan --url {url}",
        "crack": "crack --url {url} --inputs {params}",
        "crack_path": "crack-path --url {url}",
        "crack_json": "crack-json --url {url}"
    },
    "gitleaks": {
        "detect": "detect --source {url} --no-git -f json",
        "repo": "detect --source {repo} -f json"
    },
    "searchsploit": {
        "search": "--json {query}",
        "cve": "--cve {cve_id} --json"
    },
    "uncover": {
        "shodan": "-q 'host:{domain}' -e shodan -silent -json",
        "fofa": "-q 'domain={domain}' -e fofa -silent -json",
        "hunter": "-q 'domain=\"{domain}\"' -e hunter -silent -json"
    },
    "cloudlist": {
        "enum": "-d {domain} -silent -json"
    },
    "cdncheck": {
        "check": "-i {target} -silent -json"
    },
    "rustscan": {
        "quick": "-a {target} --ulimit 5000",
        "full": "-a {target} -p- --ulimit 5000"
    },
    "dirsearch": {
        "quick": "-u {url} -e php,asp,aspx,jsp,html,js -t 50 --json",
        "full": "-u {url} -e * -t 50 --json"
    },
    "gobuster": {
        "dir": "dir -u {url} -w {wordlist} -t 50 --quiet -j",
        "dns": "dns -d {domain} -w {wordlist} -t 50 --quiet -j"
    },
    "feroxbuster": {
        "scan": "-u {url} -w {wordlist} -t 50 -q --json",
        "deep": "-u {url} -w {wordlist} -t 50 -d 5 -q --json"
    },
    "assetfinder": {
        "enum": "--subs-only {domain}"
    },
    "subdominator": {
        "enum": "-d {domain} -silent -json"
    }
}


def get_tool_command(tool_name: str, command_type: str) -> Optional[str]:
    tool_commands = TOOL_COMMANDS.get(tool_name.lower())
    if tool_commands:
        return tool_commands.get(command_type)
    return None


def list_tool_commands(tool_name: str) -> List[str]:
    tool_commands = TOOL_COMMANDS.get(tool_name.lower())
    if tool_commands:
        return list(tool_commands.keys())
    return []
