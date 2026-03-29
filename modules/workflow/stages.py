from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class StageCategory(Enum):
    RECON = "信息收集"
    VULN_SCAN = "漏洞扫描"
    ADV_SCAN = "高级检测"
    VERIFY = "漏洞验证"
    REPORT = "报告生成"


class StageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStage:
    id: str
    name: str
    category: StageCategory
    tool_name: str
    tool_category: str
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    required: bool = True
    timeout: int = 300
    args_template: str = ""
    output_parser: str = "default"
    enabled: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "tool_name": self.tool_name,
            "tool_category": self.tool_category,
            "description": self.description,
            "dependencies": self.dependencies,
            "required": self.required,
            "timeout": self.timeout,
            "enabled": self.enabled
        }


STAGES: Dict[str, WorkflowStage] = {
    "port_scan": WorkflowStage(
        id="port_scan",
        name="端口扫描",
        category=StageCategory.RECON,
        tool_name="nmap",
        tool_category="port_scanner",
        description="扫描目标开放端口和服务",
        timeout=600,
        args_template="-sV -sC -p {ports} --open -Pn {target}",
        output_parser="nmap"
    ),
    
    "port_scan_naabu": WorkflowStage(
        id="port_scan_naabu",
        name="快速端口扫描",
        category=StageCategory.RECON,
        tool_name="naabu",
        tool_category="port_scanner",
        description="使用Naabu快速扫描端口",
        timeout=300,
        args_template="-host {target} -top-ports 1000 -silent -json",
        output_parser="naabu"
    ),
    
    "subdomain": WorkflowStage(
        id="subdomain",
        name="子域名枚举",
        category=StageCategory.RECON,
        tool_name="subfinder",
        tool_category="subdomain",
        description="枚举目标子域名",
        timeout=600,
        args_template="-d {domain} -silent -json",
        output_parser="subfinder"
    ),
    
    "directory": WorkflowStage(
        id="directory",
        name="目录扫描",
        category=StageCategory.RECON,
        tool_name="ffuf",
        tool_category="directory",
        description="扫描Web目录和文件",
        timeout=900,
        args_template="-u {url}/FUZZ -w {wordlist} -mc 200,301,302,403,500 -t 50 -silent -json",
        output_parser="ffuf"
    ),
    
    "fingerprint": WorkflowStage(
        id="fingerprint",
        name="指纹识别",
        category=StageCategory.RECON,
        tool_name="httpx",
        tool_category="fingerprint",
        description="识别Web技术栈和指纹",
        timeout=300,
        args_template="-u {url} -silent -json -tech-detect -status-code -title -web-server",
        output_parser="httpx"
    ),
    
    "crawler": WorkflowStage(
        id="crawler",
        name="爬虫抓取",
        category=StageCategory.RECON,
        tool_name="katana",
        tool_category="crawler",
        description="爬取网站链接和参数",
        timeout=600,
        args_template="-u {url} -silent -json -aff -depth 3",
        output_parser="katana"
    ),
    
    "ssl_analyze": WorkflowStage(
        id="ssl_analyze",
        name="SSL/TLS分析",
        category=StageCategory.RECON,
        tool_name="tlsx",
        tool_category="ssl_analyzer",
        description="分析SSL/TLS配置",
        timeout=300,
        args_template="-u {target} -silent -json",
        output_parser="tlsx"
    ),
    
    "dns_enum": WorkflowStage(
        id="dns_enum",
        name="DNS枚举",
        category=StageCategory.RECON,
        tool_name="dnsx",
        tool_category="dns",
        description="DNS记录枚举",
        timeout=300,
        args_template="-d {domain} -silent -json -a -aaaa -cname -mx -ns -txt",
        output_parser="dnsx"
    ),
    
    "cdn_check": WorkflowStage(
        id="cdn_check",
        name="CDN检测",
        category=StageCategory.RECON,
        tool_name="cdncheck",
        tool_category="cloud",
        description="检测CDN和云服务",
        timeout=120,
        args_template="-i {target} -silent -json",
        output_parser="cdncheck"
    ),
    
    "search_engine": WorkflowStage(
        id="search_engine",
        name="搜索引擎查询",
        category=StageCategory.RECON,
        tool_name="uncover",
        tool_category="search_engine",
        description="从搜索引擎发现资产",
        timeout=300,
        args_template="-q {query} -silent -json",
        output_parser="uncover"
    ),
    
    "cloud_asset": WorkflowStage(
        id="cloud_asset",
        name="云资产发现",
        category=StageCategory.RECON,
        tool_name="cloudlist",
        tool_category="cloud",
        description="发现云平台资产",
        timeout=300,
        args_template="-d {domain} -silent -json",
        output_parser="cloudlist"
    ),
    
    "nuclei_scan": WorkflowStage(
        id="nuclei_scan",
        name="模板漏洞扫描",
        category=StageCategory.VULN_SCAN,
        tool_name="nuclei",
        tool_category="fingerprint",
        description="使用Nuclei模板扫描漏洞",
        dependencies=["fingerprint"],
        timeout=1800,
        args_template="-u {url} -silent -json -severity critical,high,medium -t {templates}",
        output_parser="nuclei"
    ),
    
    "sqli_scan": WorkflowStage(
        id="sqli_scan",
        name="SQL注入检测",
        category=StageCategory.VULN_SCAN,
        tool_name="sqlmap",
        tool_category="sqli",
        description="检测SQL注入漏洞",
        dependencies=["crawler"],
        timeout=900,
        args_template="-u {url} --batch --level=1 --risk=1 --threads=5 --technique=BEUST",
        output_parser="sqlmap"
    ),
    
    "xss_scan": WorkflowStage(
        id="xss_scan",
        name="XSS扫描",
        category=StageCategory.VULN_SCAN,
        tool_name="dalfox",
        tool_category="xss",
        description="检测XSS漏洞",
        dependencies=["crawler"],
        timeout=900,
        args_template="url {url} --silence --format json --only-poc r",
        output_parser="dalfox"
    ),
    
    "ssti_scan": WorkflowStage(
        id="ssti_scan",
        name="SSTI检测",
        category=StageCategory.VULN_SCAN,
        tool_name="sstimap",
        tool_category="ssti",
        description="检测服务端模板注入",
        dependencies=["crawler"],
        timeout=600,
        args_template="-u {url} --level 1",
        output_parser="sstimap"
    ),
    
    "lfi_scan": WorkflowStage(
        id="lfi_scan",
        name="LFI/RFI检测",
        category=StageCategory.VULN_SCAN,
        tool_name="ffuf",
        tool_category="directory",
        description="检测本地/远程文件包含",
        dependencies=["crawler"],
        timeout=600,
        args_template="-u {url} -w {lfi_wordlist} -mr \"root:|boot.ini|etc/passwd\" -silent -json",
        output_parser="ffuf"
    ),
    
    "secret_scan": WorkflowStage(
        id="secret_scan",
        name="密钥泄露检测",
        category=StageCategory.VULN_SCAN,
        tool_name="gitleaks",
        tool_category="leak",
        description="检测敏感信息泄露",
        timeout=300,
        args_template="detect --source {url} --no-git -f json",
        output_parser="gitleaks"
    ),
    
    "cve_search": WorkflowStage(
        id="cve_search",
        name="CVE搜索",
        category=StageCategory.VULN_SCAN,
        tool_name="searchsploit",
        tool_category="cve_search",
        description="搜索已知漏洞利用",
        dependencies=["fingerprint"],
        timeout=120,
        args_template="--json {search_term}",
        output_parser="searchsploit"
    ),
    
    "jwt_check": WorkflowStage(
        id="jwt_check",
        name="JWT安全检测",
        category=StageCategory.ADV_SCAN,
        tool_name="httpx",
        tool_category="fingerprint",
        description="检测JWT安全问题",
        timeout=300,
        args_template="-u {url} -silent -json -jwt",
        output_parser="httpx_jwt"
    ),
    
    "api_scan": WorkflowStage(
        id="api_scan",
        name="API安全检测",
        category=StageCategory.ADV_SCAN,
        tool_name="httpx",
        tool_category="fingerprint",
        description="检测API安全问题",
        dependencies=["crawler"],
        timeout=300,
        args_template="-u {url} -silent -json -api",
        output_parser="httpx_api"
    ),
    
    "open_redirect": WorkflowStage(
        id="open_redirect",
        name="开放重定向检测",
        category=StageCategory.ADV_SCAN,
        tool_name="ffuf",
        tool_category="directory",
        description="检测开放重定向漏洞",
        dependencies=["crawler"],
        timeout=300,
        args_template="-u {url} -w {redirect_wordlist} -mr \"Location:\" -silent -json",
        output_parser="ffuf"
    ),
}


SCAN_MODES = {
    "quick": {
        "name": "快速扫描",
        "description": "5-10分钟，基础端口和目录扫描+Nuclei模板扫描",
        "stages": [
            "port_scan_naabu",
            "fingerprint",
            "directory",
            "nuclei_scan"
        ],
        "estimated_time": "5-10分钟"
    },
    "standard": {
        "name": "标准扫描",
        "description": "20-40分钟，完整信息收集+漏洞扫描+高危验证",
        "stages": [
            "port_scan_naabu",
            "subdomain",
            "fingerprint",
            "directory",
            "crawler",
            "ssl_analyze",
            "nuclei_scan",
            "sqli_scan",
            "xss_scan",
            "ssti_scan",
            "secret_scan",
            "jwt_check",
            "api_scan",
            "open_redirect"
        ],
        "estimated_time": "20-40分钟"
    },
    "deep": {
        "name": "深度扫描",
        "description": "40-90分钟，全部信息收集+全部漏洞扫描+全部高级检测",
        "stages": list(STAGES.keys()),
        "estimated_time": "40-90分钟"
    }
}


def get_stage(stage_id: str) -> Optional[WorkflowStage]:
    return STAGES.get(stage_id)


def get_stages_by_category(category: StageCategory) -> List[WorkflowStage]:
    return [s for s in STAGES.values() if s.category == category]


def get_mode_stages(mode: str) -> List[str]:
    return SCAN_MODES.get(mode, SCAN_MODES["quick"])["stages"]


def validate_dependencies(stage_ids: List[str]) -> bool:
    for stage_id in stage_ids:
        stage = STAGES.get(stage_id)
        if stage:
            for dep in stage.dependencies:
                if dep not in stage_ids:
                    return False
    return True


def get_execution_order(stage_ids: List[str]) -> List[str]:
    ordered = []
    remaining = set(stage_ids)
    
    while remaining:
        for stage_id in list(remaining):
            stage = STAGES.get(stage_id)
            if stage:
                deps_met = all(d in ordered for d in stage.dependencies)
                if deps_met:
                    ordered.append(stage_id)
                    remaining.remove(stage_id)
            else:
                remaining.remove(stage_id)
    
    return ordered
