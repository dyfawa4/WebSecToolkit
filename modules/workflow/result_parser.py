import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedFinding:
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    url: str = ""
    raw_data: Dict = None
    
    def __post_init__(self):
        if self.raw_data is None:
            self.raw_data = {}
    
    def to_dict(self) -> Dict:
        return {
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "url": self.url,
            "raw_data": self.raw_data
        }


class ResultParser:
    
    @staticmethod
    def parse(tool_name: str, output: str) -> List[ParsedFinding]:
        parser_map = {
            "nmap": ResultParser.parse_nmap,
            "naabu": ResultParser.parse_naabu,
            "subfinder": ResultParser.parse_subfinder,
            "ffuf": ResultParser.parse_ffuf,
            "httpx": ResultParser.parse_httpx,
            "nuclei": ResultParser.parse_nuclei,
            "katana": ResultParser.parse_katana,
            "tlsx": ResultParser.parse_tlsx,
            "dnsx": ResultParser.parse_dnsx,
            "dalfox": ResultParser.parse_dalfox,
            "sqlmap": ResultParser.parse_sqlmap,
            "sstimap": ResultParser.parse_sstimap,
            "fenjing": ResultParser.parse_fenjing,
            "gitleaks": ResultParser.parse_gitleaks,
            "searchsploit": ResultParser.parse_searchsploit,
            "cdncheck": ResultParser.parse_cdncheck,
            "uncover": ResultParser.parse_uncover,
            "cloudlist": ResultParser.parse_cloudlist,
            "dirsearch": ResultParser.parse_dirsearch,
            "gobuster": ResultParser.parse_gobuster,
            "feroxbuster": ResultParser.parse_feroxbuster,
            "rustscan": ResultParser.parse_rustscan,
            "assetfinder": ResultParser.parse_assetfinder,
            "subdominator": ResultParser.parse_subdominator
        }
        
        parser = parser_map.get(tool_name.lower(), ResultParser.parse_generic)
        return parser(output)
    
    @staticmethod
    def parse_generic(output: str) -> List[ParsedFinding]:
        findings = []
        if output.strip():
            findings.append(ParsedFinding(
                finding_type="info",
                severity="info",
                title="工具输出",
                description="工具执行完成",
                evidence=output[:500]
            ))
        return findings
    
    @staticmethod
    def parse_nmap(output: str) -> List[ParsedFinding]:
        findings = []
        
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?'
        
        for line in output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port = match.group(1)
                protocol = match.group(2)
                service = match.group(3)
                version = match.group(4) or ""
                
                findings.append(ParsedFinding(
                    finding_type="open_port",
                    severity="info",
                    title=f"开放端口: {port}/{protocol}",
                    description=f"服务: {service} {version}".strip(),
                    evidence=line.strip(),
                    raw_data={
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "version": version.strip()
                    }
                ))
        
        vuln_pattern = r'\|(.+)'
        for line in output.split('\n'):
            if '|' in line and ('vuln' in line.lower() or 'CVE' in line):
                findings.append(ParsedFinding(
                    finding_type="vulnerability",
                    severity="medium",
                    title="潜在漏洞",
                    description=line.strip(),
                    evidence=line.strip()
                ))
        
        return findings
    
    @staticmethod
    def parse_naabu(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                host = data.get("host", "")
                port = data.get("port", "")
                ip = data.get("ip", "")
                
                findings.append(ParsedFinding(
                    finding_type="open_port",
                    severity="info",
                    title=f"开放端口: {port}",
                    description=f"主机: {host or ip}, 端口: {port}",
                    evidence=line,
                    raw_data=data
                ))
            except json.JSONDecodeError:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        findings.append(ParsedFinding(
                            finding_type="open_port",
                            severity="info",
                            title=f"开放端口: {parts[-1]}",
                            description=f"主机: {parts[0]}, 端口: {parts[-1]}",
                            evidence=line
                        ))
        
        return findings
    
    @staticmethod
    def parse_subfinder(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                subdomain = data.get("host", "")
                
                if subdomain:
                    findings.append(ParsedFinding(
                        finding_type="subdomain",
                        severity="info",
                        title=f"子域名: {subdomain}",
                        description=f"发现子域名: {subdomain}",
                        evidence=line,
                        raw_data=data
                    ))
            except json.JSONDecodeError:
                subdomain = line.strip()
                if '.' in subdomain and not subdomain.startswith('#'):
                    findings.append(ParsedFinding(
                        finding_type="subdomain",
                        severity="info",
                        title=f"子域名: {subdomain}",
                        description=f"发现子域名: {subdomain}",
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_ffuf(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                if data.get("type") == "result":
                    url = data.get("url", "")
                    status = data.get("status", 0)
                    length = data.get("length", 0)
                    
                    severity = "info"
                    if status == 200:
                        severity = "low"
                    
                    findings.append(ParsedFinding(
                        finding_type="directory",
                        severity=severity,
                        title=f"路径发现: {url} [{status}]",
                        description=f"状态码: {status}, 大小: {length}",
                        url=url,
                        evidence=line,
                        raw_data=data
                    ))
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_httpx(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                url = data.get("url", "")
                title = data.get("title", "")
                webserver = data.get("webserver", "")
                tech = data.get("tech", [])
                status_code = data.get("status_code", 0)
                
                if tech:
                    findings.append(ParsedFinding(
                        finding_type="fingerprint",
                        severity="info",
                        title=f"技术栈: {', '.join(tech)}",
                        description=f"检测到技术栈: {', '.join(tech)}",
                        url=url,
                        evidence=line,
                        raw_data=data
                    ))
                
                if webserver:
                    findings.append(ParsedFinding(
                        finding_type="fingerprint",
                        severity="info",
                        title=f"Web服务器: {webserver}",
                        description=f"检测到Web服务器: {webserver}",
                        url=url,
                        evidence=line
                    ))
                
                if title:
                    findings.append(ParsedFinding(
                        finding_type="info",
                        severity="info",
                        title=f"页面标题: {title}",
                        description=f"URL: {url}, 状态码: {status_code}",
                        url=url,
                        evidence=line
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_nuclei(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
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
                    "info": "info",
                    "unknown": "info"
                }
                
                findings.append(ParsedFinding(
                    finding_type="vulnerability",
                    severity=severity_map.get(severity, "info"),
                    title=f"[{severity.upper()}] {name}",
                    description=description or f"检测到漏洞: {name}",
                    url=matched_at,
                    evidence=line,
                    raw_data=data
                ))
                
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_katana(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                request = data.get("request", {})
                url = request.get("endpoint", "")
                method = request.get("method", "GET")
                
                if url:
                    findings.append(ParsedFinding(
                        finding_type="endpoint",
                        severity="info",
                        title=f"端点: {method} {url}",
                        description=f"发现端点: {method} {url}",
                        url=url,
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_tlsx(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                version = data.get("version", "")
                cipher = data.get("cipher", "")
                issuer = data.get("issuer", "")
                
                if "tls1.0" in version.lower() or "tls1.1" in version.lower():
                    findings.append(ParsedFinding(
                        finding_type="ssl_issue",
                        severity="medium",
                        title=f"弱TLS版本: {version}",
                        description=f"检测到弱TLS版本: {version}，建议升级到TLS 1.2或更高版本",
                        evidence=line,
                        raw_data=data
                    ))
                
                findings.append(ParsedFinding(
                    finding_type="ssl_info",
                    severity="info",
                    title=f"SSL/TLS信息",
                    description=f"版本: {version}, 加密套件: {cipher}",
                    evidence=line,
                    raw_data=data
                ))
                
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_dnsx(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                host = data.get("host", "")
                
                records = []
                for key in ["a", "aaaa", "cname", "mx", "ns", "txt"]:
                    if key in data:
                        records.append(f"{key.upper()}: {data[key]}")
                
                if records:
                    findings.append(ParsedFinding(
                        finding_type="dns_record",
                        severity="info",
                        title=f"DNS记录: {host}",
                        description=", ".join(records),
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_dalfox(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                if data.get("type") == "found":
                    finding_data = data.get("data", {})
                    url = finding_data.get("url", "")
                    param = finding_data.get("param", "")
                    poc = finding_data.get("poc", "")
                    
                    findings.append(ParsedFinding(
                        finding_type="xss",
                        severity="high",
                        title=f"XSS漏洞: {param}",
                        description=f"检测到反射型XSS漏洞，参数: {param}",
                        url=url,
                        evidence=f"PoC: {poc}",
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                if "found" in line.lower() and "xss" in line.lower():
                    findings.append(ParsedFinding(
                        finding_type="xss",
                        severity="high",
                        title="XSS漏洞",
                        description="检测到XSS漏洞",
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_sqlmap(output: str) -> List[ParsedFinding]:
        findings = []
        
        if "sql injection" in output.lower() or "injectable" in output.lower():
            param = ""
            for line in output.split('\n'):
                if "Parameter:" in line:
                    match = re.search(r'Parameter:\s*(\S+)', line)
                    if match:
                        param = match.group(1)
                
                if "Type:" in line:
                    match = re.search(r'Type:\s*(\S+)', line)
                    if match:
                        inj_type = match.group(1)
                        
                        findings.append(ParsedFinding(
                            finding_type="sqli",
                            severity="critical",
                            title=f"SQL注入漏洞: {param}",
                            description=f"检测到SQL注入漏洞，参数: {param}, 类型: {inj_type}",
                            evidence=line
                        ))
        
        if "available databases" in output.lower():
            match = re.search(r'available databases[^:]*:\s*\[(.+)\]', output, re.IGNORECASE)
            if match:
                dbs = match.group(1)
                findings.append(ParsedFinding(
                    finding_type="sqli_data",
                    severity="high",
                    title="数据库枚举",
                    description=f"发现数据库: {dbs}",
                    evidence=line
                ))
        
        return findings
    
    @staticmethod
    def parse_sstimap(output: str) -> List[ParsedFinding]:
        findings = []
        
        engine = ""
        for line in output.split('\n'):
            if "Engine:" in line:
                match = re.search(r'Engine:\s*(\w+)', line)
                if match:
                    engine = match.group(1)
            
            if "[+]" in line:
                if "injection" in line.lower():
                    findings.append(ParsedFinding(
                        finding_type="ssti",
                        severity="high",
                        title=f"SSTI漏洞: {engine}",
                        description=f"检测到服务端模板注入漏洞，引擎: {engine}",
                        evidence=line
                    ))
                
                if "Shell command execution" in line:
                    findings.append(ParsedFinding(
                        finding_type="ssti_rce",
                        severity="critical",
                        title="SSTI RCE",
                        description="SSTI漏洞可导致远程代码执行",
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_fenjing(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.split('\n'):
            if "found" in line.lower() or "success" in line.lower():
                findings.append(ParsedFinding(
                    finding_type="ssti",
                    severity="high",
                    title="SSTI漏洞",
                    description="检测到服务端模板注入漏洞",
                    evidence=line
                ))
            
            if "payload" in line.lower():
                findings.append(ParsedFinding(
                    finding_type="ssti_payload",
                    severity="medium",
                    title="SSTI Payload",
                    description="生成SSTI Payload",
                    evidence=line
                ))
        
        return findings
    
    @staticmethod
    def parse_gitleaks(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                rule_id = data.get("RuleID", "")
                description = data.get("Description", "")
                match = data.get("Match", "")
                
                if rule_id:
                    findings.append(ParsedFinding(
                        finding_type="secret_leak",
                        severity="high",
                        title=f"密钥泄露: {rule_id}",
                        description=f"{description}, 匹配: {match[:50]}...",
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_searchsploit(output: str) -> List[ParsedFinding]:
        findings = []
        
        try:
            data = json.loads(output)
            
            for item in data.get("RESULTS_EXPLOIT", []):
                title = item.get("Title", "")
                cve = item.get("CVE", "")
                path = item.get("Path", "")
                
                findings.append(ParsedFinding(
                    finding_type="exploit",
                    severity="medium",
                    title=f"Exploit: {title}",
                    description=f"CVE: {cve}, 路径: {path}",
                    evidence=output,
                    raw_data=item
                ))
                
        except json.JSONDecodeError:
            for line in output.split('\n'):
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        findings.append(ParsedFinding(
                            finding_type="exploit",
                            severity="medium",
                            title=f"Exploit: {parts[0].strip()}",
                            description=parts[1].strip() if len(parts) > 1 else "",
                            evidence=line
                        ))
        
        return findings
    
    @staticmethod
    def parse_cdncheck(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                if data.get("cdn"):
                    cdn_name = data.get("cdn_name", "Unknown")
                    
                    findings.append(ParsedFinding(
                        finding_type="cdn",
                        severity="info",
                        title=f"CDN检测: {cdn_name}",
                        description=f"目标使用CDN: {cdn_name}",
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_uncover(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                host = data.get("host", "")
                ip = data.get("ip", "")
                port = data.get("port", "")
                
                findings.append(ParsedFinding(
                    finding_type="asset",
                    severity="info",
                    title=f"资产发现: {host or ip}",
                    description=f"IP: {ip}, 端口: {port}",
                    evidence=line,
                    raw_data=data
                ))
                
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_cloudlist(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                service = data.get("service", "")
                host = data.get("host", "")
                
                if service:
                    findings.append(ParsedFinding(
                        finding_type="cloud_asset",
                        severity="info",
                        title=f"云资产: {service}",
                        description=f"发现云平台资产: {service}, 主机: {host}",
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                pass
        
        return findings
    
    @staticmethod
    def parse_dirsearch(output: str) -> List[ParsedFinding]:
        findings = []
        
        try:
            data = json.loads(output)
            
            for result in data.get("results", []):
                url = result.get("url", "")
                status = result.get("status", 0)
                
                severity = "info"
                if status == 200:
                    severity = "low"
                
                findings.append(ParsedFinding(
                    finding_type="directory",
                    severity=severity,
                    title=f"路径发现: {url} [{status}]",
                    description=f"状态码: {status}",
                    url=url,
                    evidence=output,
                    raw_data=result
                ))
                
        except json.JSONDecodeError:
            for line in output.split('\n'):
                match = re.search(r'\[(\d+)\]\s+(\S+)', line)
                if match:
                    status = int(match.group(1))
                    url = match.group(2)
                    
                    severity = "info"
                    if status == 200:
                        severity = "low"
                    
                    findings.append(ParsedFinding(
                        finding_type="directory",
                        severity=severity,
                        title=f"路径发现: {url} [{status}]",
                        description=f"状态码: {status}",
                        url=url,
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_gobuster(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                url = data.get("url", "")
                status = data.get("status", 0)
                
                severity = "info"
                if status == 200:
                    severity = "low"
                
                findings.append(ParsedFinding(
                    finding_type="directory",
                    severity=severity,
                    title=f"路径发现: {url} [{status}]",
                    description=f"状态码: {status}",
                    url=url,
                    evidence=line,
                    raw_data=data
                ))
                
            except json.JSONDecodeError:
                match = re.search(r'(\S+)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    url = match.group(1)
                    status = int(match.group(2))
                    
                    severity = "info"
                    if status == 200:
                        severity = "low"
                    
                    findings.append(ParsedFinding(
                        finding_type="directory",
                        severity=severity,
                        title=f"路径发现: {url} [{status}]",
                        description=f"状态码: {status}",
                        url=url,
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_feroxbuster(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                if data.get("type") == "response":
                    url = data.get("url", "")
                    status = data.get("status", 0)
                    
                    severity = "info"
                    if status == 200:
                        severity = "low"
                    
                    findings.append(ParsedFinding(
                        finding_type="directory",
                        severity=severity,
                        title=f"路径发现: {url} [{status}]",
                        description=f"状态码: {status}",
                        url=url,
                        evidence=line,
                        raw_data=data
                    ))
                    
            except json.JSONDecodeError:
                match = re.search(r'(\d+)\s+(\S+)', line)
                if match:
                    status = int(match.group(1))
                    url = match.group(2)
                    
                    severity = "info"
                    if status == 200:
                        severity = "low"
                    
                    findings.append(ParsedFinding(
                        finding_type="directory",
                        severity=severity,
                        title=f"路径发现: {url} [{status}]",
                        description=f"状态码: {status}",
                        url=url,
                        evidence=line
                    ))
        
        return findings
    
    @staticmethod
    def parse_rustscan(output: str) -> List[ParsedFinding]:
        findings = []
        
        port_pattern = r'(\d+)\s+open'
        
        for line in output.split('\n'):
            match = re.search(port_pattern, line)
            if match:
                port = match.group(1)
                
                findings.append(ParsedFinding(
                    finding_type="open_port",
                    severity="info",
                    title=f"开放端口: {port}",
                    description=f"发现开放端口: {port}",
                    evidence=line
                ))
        
        return findings
    
    @staticmethod
    def parse_assetfinder(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and '.' in subdomain:
                findings.append(ParsedFinding(
                    finding_type="subdomain",
                    severity="info",
                    title=f"子域名: {subdomain}",
                    description=f"发现子域名: {subdomain}",
                    evidence=line
                ))
        
        return findings
    
    @staticmethod
    def parse_subdominator(output: str) -> List[ParsedFinding]:
        findings = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                subdomain = data.get("host", "")
                
                if subdomain:
                    findings.append(ParsedFinding(
                        finding_type="subdomain",
                        severity="info",
                        title=f"子域名: {subdomain}",
                        description=f"发现子域名: {subdomain}",
                        evidence=line,
                        raw_data=data
                    ))
            except json.JSONDecodeError:
                subdomain = line.strip()
                if '.' in subdomain:
                    findings.append(ParsedFinding(
                        finding_type="subdomain",
                        severity="info",
                        title=f"子域名: {subdomain}",
                        description=f"发现子域名: {subdomain}",
                        evidence=line
                    ))
        
        return findings
