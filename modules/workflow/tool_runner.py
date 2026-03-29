import subprocess
import threading
import os
from typing import Optional, Callable, List, Dict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolResult:
    success: bool
    output: str
    error: str
    return_code: int
    findings: List[Dict] = field(default_factory=list)


PYTHON_TOOLS = {
    "sqlmap", "sstimap", "fenjing", "searchsploit", "dirsearch"
}

TOOL_COMMANDS = {
    "nmap": {
        "quick": "-sV -sC -F --open -Pn {target}",
        "full": "-sV -sC -p- --open -Pn {target}",
        "vuln": "-sV --script=vuln --open -Pn {target}",
    },
    "naabu": {
        "quick": "-host {target} -top-ports 100 -silent -json",
        "full": "-host {target} -p - -silent -json",
    },
    "subfinder": {
        "enum": "-d {domain} -silent -json",
        "recursive": "-d {domain} -recursive -silent -json",
    },
    "ffuf": {
        "directory": "-u {url}/FUZZ -w {wordlist} -mc 200,301,302,403,500 -t 50 -silent -json",
        "subdomain": "-u http://FUZZ.{domain} -w {wordlist} -mc 200,301,302 -t 50 -silent -json",
    },
    "httpx": {
        "probe": "-u {url} -silent -json -tech-detect -status-code -title -web-server",
        "fingerprint": "-u {url} -silent -json -tech-detect -cdn -waf",
    },
    "nuclei": {
        "quick": "-u {url} -silent -json -severity critical,high",
        "full": "-u {url} -silent -json",
    },
    "katana": {
        "crawl": "-u {url} -silent -json -aff -depth 3",
        "passive": "-u {url} -silent -json -passive",
    },
    "tlsx": {
        "analyze": "-u {target} -silent -json",
    },
    "dnsx": {
        "enum": "-d {domain} -silent -json -a -aaaa -cname -mx -ns -txt",
    },
    "dalfox": {
        "scan": "url {url} --silence --format json",
    },
    "sqlmap": {
        "quick": "-u {url} --batch --level=1 --risk=1 --threads=5",
        "deep": "-u {url} --batch --level=3 --risk=2 --threads=5",
    },
    "sstimap": {
        "scan": "-u {url} --level 1",
        "shell": "-u {url} --os-shell",
    },
    "fenjing": {
        "scan": "scan --url {url}",
        "crack": "crack --url {url} --inputs {params}",
    },
    "gitleaks": {
        "detect": "detect --source {url} --no-git -f json",
    },
    "searchsploit": {
        "search": "--json {query}",
    },
    "uncover": {
        "shodan": "-q 'host:{domain}' -e shodan -silent -json",
        "fofa": "-q 'domain={domain}' -e fofa -silent -json",
    },
    "cloudlist": {
        "enum": "-d {domain} -silent -json",
    },
    "cdncheck": {
        "check": "-i {target} -silent -json",
    },
}


class ToolRunner:
    def __init__(self, tool_manager=None):
        self.tool_manager = tool_manager
        self._process: Optional[subprocess.Popen] = None
        self._is_running = False
        self._should_stop = False
    
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
        
        if tool_name in PYTHON_TOOLS:
            return f'python "{tool_path}" {args}'
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
            
            def read_output():
                for line in self._process.stdout:
                    if self._should_stop:
                        break
                    line = line.rstrip()
                    output_lines.append(line)
                    if output_callback:
                        output_callback(line)
            
            output_thread = threading.Thread(target=read_output, daemon=True)
            output_thread.start()
            
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
            
            output_thread.join(timeout=1)
            
            stderr_output = self._process.stderr.read()
            if stderr_output:
                error_lines.append(stderr_output)
            
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
