import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ReportSection:
    title: str
    content: str
    subsections: List['ReportSection'] = None
    
    def __post_init__(self):
        if self.subsections is None:
            self.subsections = []


class ReportGenerator:
    
    def __init__(self):
        self.template_dir = Path("templates/reports")
        self.output_dir = Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate(self, workflow_result: Dict, format: str = "html") -> str:
        if format == "html":
            return self._generate_html(workflow_result)
        elif format == "markdown" or format == "md":
            return self._generate_markdown(workflow_result)
        elif format == "json":
            return self._generate_json(workflow_result)
        else:
            return self._generate_html(workflow_result)
    
    def _generate_html(self, result: Dict) -> str:
        stats = result.get("statistics", {})
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告 - {result.get('target', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .meta {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-card.critical {{ border-top: 4px solid #dc3545; }}
        .stat-card.high {{ border-top: 4px solid #fd7e14; }}
        .stat-card.medium {{ border-top: 4px solid #ffc107; }}
        .stat-card.low {{ border-top: 4px solid #28a745; }}
        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-card.critical .number {{ color: #dc3545; }}
        .stat-card.high .number {{ color: #fd7e14; }}
        .stat-card.medium .number {{ color: #ffc107; }}
        .stat-card.low .number {{ color: #28a745; }}
        .stat-card .label {{
            color: #666;
            font-size: 1.1em;
        }}
        .section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        .finding {{
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
            border-left: 4px solid #ccc;
        }}
        .finding.critical {{
            background: #fff5f5;
            border-left-color: #dc3545;
        }}
        .finding.high {{
            background: #fff8f0;
            border-left-color: #fd7e14;
        }}
        .finding.medium {{
            background: #fffdf0;
            border-left-color: #ffc107;
        }}
        .finding.low {{
            background: #f0fff4;
            border-left-color: #28a745;
        }}
        .finding.info {{
            background: #f8f9fa;
            border-left-color: #6c757d;
        }}
        .finding h4 {{
            margin-bottom: 10px;
        }}
        .finding .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }}
        .severity.critical {{ background: #dc3545; color: white; }}
        .severity.high {{ background: #fd7e14; color: white; }}
        .severity.medium {{ background: #ffc107; color: #333; }}
        .severity.low {{ background: #28a745; color: white; }}
        .severity.info {{ background: #6c757d; color: white; }}
        .finding .description {{
            color: #666;
            margin-bottom: 10px;
        }}
        .finding .evidence {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .info-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .info-table th, .info-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        .info-table th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        .info-table tr:hover {{
            background: #f8f9fa;
        }}
        .progress-bar {{
            background: #eee;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-bar .fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s ease;
        }}
        .stage-status {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
        }}
        .stage-status.completed {{ background: #28a745; color: white; }}
        .stage-status.failed {{ background: #dc3545; color: white; }}
        .stage-status.skipped {{ background: #6c757d; color: white; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 渗透测试报告</h1>
            <div class="meta">
                <p><strong>目标:</strong> {result.get('target', 'Unknown')}</p>
                <p><strong>扫描模式:</strong> {result.get('mode', 'Unknown')}</p>
                <p><strong>扫描时间:</strong> {result.get('start_time', 'Unknown')}</p>
                <p><strong>总耗时:</strong> {self._calculate_duration(result)}</p>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="number">{stats.get('critical', 0)}</div>
                <div class="label">🔴 高危</div>
            </div>
            <div class="stat-card high">
                <div class="number">{stats.get('high', 0)}</div>
                <div class="label">🟠 高危</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{stats.get('medium', 0)}</div>
                <div class="label">🟡 中危</div>
            </div>
            <div class="stat-card low">
                <div class="number">{stats.get('low', 0)}</div>
                <div class="label">🟢 低危</div>
            </div>
        </div>
        
        {self._generate_findings_html(result)}
        
        {self._generate_info_html(result)}
        
        {self._generate_stages_html(result)}
        
        <div class="footer">
            <p>报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>WebSec Toolkit - 安全测试工具箱</p>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_findings_html(self, result: Dict) -> str:
        findings = result.get("findings", [])
        
        if not findings:
            return '<div class="section"><h2>📋 漏洞详情</h2><p>未发现漏洞</p></div>'
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
        
        findings_html = '<div class="section"><h2>📋 漏洞详情</h2>'
        
        for finding in sorted_findings:
            severity = finding.get("severity", "info").lower()
            title = finding.get("title", "Unknown")
            description = finding.get("description", "")
            evidence = finding.get("evidence", "")
            url = finding.get("url", "")
            
            findings_html += f"""
            <div class="finding {severity}">
                <h4>{title} <span class="severity {severity}">{severity.upper()}</span></h4>
                <p class="description">{description}</p>
                {f'<p><strong>URL:</strong> {url}</p>' if url else ''}
                {f'<div class="evidence">{evidence[:500]}</div>' if evidence else ''}
            </div>"""
        
        findings_html += '</div>'
        return findings_html
    
    def _generate_info_html(self, result: Dict) -> str:
        info = result.get("info", {})
        
        if not info:
            return ''
        
        info_html = '<div class="section"><h2>📊 信息收集结果</h2>'
        
        if "ports" in info:
            ports = info["ports"]
            info_html += '<h3>开放端口</h3><table class="info-table"><tr><th>端口</th><th>服务</th><th>版本</th></tr>'
            for port in ports[:20]:
                info_html += f'<tr><td>{port.get("port", "")}</td><td>{port.get("service", "")}</td><td>{port.get("version", "")}</td></tr>'
            info_html += '</table>'
        
        if "subdomains" in info:
            subdomains = info["subdomains"]
            info_html += f'<h3>子域名 ({len(subdomains)}个)</h3><table class="info-table"><tr><th>子域名</th></tr>'
            for subdomain in subdomains[:20]:
                info_html += f'<tr><td>{subdomain}</td></tr>'
            info_html += '</table>'
        
        if "tech" in info:
            tech = info["tech"]
            info_html += f'<h3>技术栈</h3><p>{", ".join(tech)}</p>'
        
        if "webserver" in info:
            info_html += f'<h3>Web服务器</h3><p>{info["webserver"]}</p>'
        
        info_html += '</div>'
        return info_html
    
    def _generate_stages_html(self, result: Dict) -> str:
        stages = result.get("stages", {})
        
        if not stages:
            return ''
        
        stages_html = '<div class="section"><h2>⚙️ 扫描阶段</h2><table class="info-table"><tr><th>阶段</th><th>状态</th><th>发现</th></tr>'
        
        for stage_id, stage in stages.items():
            status = stage.get("status", "pending")
            findings_count = len(stage.get("findings", []))
            
            stages_html += f'<tr><td>{stage_id}</td><td><span class="stage-status {status}">{status}</span></td><td>{findings_count}</td></tr>'
        
        stages_html += '</table></div>'
        return stages_html
    
    def _generate_markdown(self, result: Dict) -> str:
        stats = result.get("statistics", {})
        findings = result.get("findings", [])
        info = result.get("info", {})
        
        md = f"""# 渗透测试报告

## 概述

- **目标**: {result.get('target', 'Unknown')}
- **扫描模式**: {result.get('mode', 'Unknown')}
- **扫描时间**: {result.get('start_time', 'Unknown')}
- **总耗时**: {self._calculate_duration(result)}

## 风险统计

| 严重程度 | 数量 |
|----------|------|
| 🔴 高危 | {stats.get('critical', 0)} |
| 🟠 高危 | {stats.get('high', 0)} |
| 🟡 中危 | {stats.get('medium', 0)} |
| 🟢 低危 | {stats.get('low', 0)} |
| 🔵 信息 | {stats.get('info', 0)} |

## 漏洞详情

"""
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
        
        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get("severity", "info").upper()
            title = finding.get("title", "Unknown")
            description = finding.get("description", "")
            url = finding.get("url", "")
            evidence = finding.get("evidence", "")
            
            md += f"""### {i}. [{severity}] {title}

{description}

"""
            if url:
                md += f"**URL**: {url}\n\n"
            if evidence:
                md += f"**证据**:\n```\n{evidence[:500]}\n```\n\n"
        
        if "ports" in info:
            md += "## 开放端口\n\n| 端口 | 服务 | 版本 |\n|------|------|------|\n"
            for port in info["ports"][:20]:
                md += f"| {port.get('port', '')} | {port.get('service', '')} | {port.get('version', '')} |\n"
            md += "\n"
        
        if "subdomains" in info:
            md += f"## 子域名 ({len(info['subdomains'])}个)\n\n"
            for subdomain in info["subdomains"][:20]:
                md += f"- {subdomain}\n"
            md += "\n"
        
        if "tech" in info:
            md += f"## 技术栈\n\n{', '.join(info['tech'])}\n\n"
        
        md += f"""---

*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

*WebSec Toolkit - 安全测试工具箱*
"""
        
        return md
    
    def _generate_json(self, result: Dict) -> str:
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
    
    def _calculate_duration(self, result: Dict) -> str:
        start_time = result.get("start_time")
        end_time = result.get("end_time")
        
        if start_time and end_time:
            try:
                if isinstance(start_time, str):
                    start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                else:
                    start = start_time
                
                if isinstance(end_time, str):
                    end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                else:
                    end = end_time
                
                duration = end - start
                minutes = int(duration.total_seconds() // 60)
                seconds = int(duration.total_seconds() % 60)
                
                if minutes > 0:
                    return f"{minutes}分{seconds}秒"
                else:
                    return f"{seconds}秒"
            except:
                pass
        
        return "Unknown"
    
    def save(self, content: str, filename: str, format: str = "html") -> str:
        ext_map = {
            "html": ".html",
            "markdown": ".md",
            "md": ".md",
            "json": ".json"
        }
        
        ext = ext_map.get(format, ".html")
        filepath = self.output_dir / f"{filename}{ext}"
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        
        return str(filepath)
    
    def generate_and_save(self, workflow_result: Dict, format: str = "html") -> str:
        content = self.generate(workflow_result, format)
        
        target = workflow_result.get("target", "unknown").replace("://", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{target}_{timestamp}"
        
        return self.save(content, filename, format)
