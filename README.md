# WebSec Toolkit

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

### Overview

**WebSec Toolkit** is a comprehensive Web Security Integrated Tool designed for penetration testers, security researchers, and bug bounty hunters. It provides a user-friendly GUI interface that integrates multiple popular security tools, enabling efficient security assessments and vulnerability discovery.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-6.6+-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

### Features

#### 🔍 Information Gathering
- **Subdomain Enumeration**: Subfinder, Amass, Assetfinder
- **Port Scanning**: Nmap, Naabu
- **DNS Enumeration**: DNSX
- **HTTP Probing**: HTTPX, Httprobe

#### 🌐 Web Security
- **Directory Scanning**: Dirsearch, Gobuster, FFUF
- **Fingerprint Recognition**: WhatWeb, HTTPX
- **Technology Detection**: Wappalyzer-style analysis

#### 🔓 Vulnerability Scanning
- **Template-based Scanning**: Nuclei
- **SQL Injection**: SQLMap
- **XSS Scanning**: Dalfox
- **SSL/TLS Analysis**: TLSX
- **CVE Search**: SearchSploit

#### 🔑 Password Cracking
- **Hash Cracking**: Hashcat, John the Ripper
- **Online Brute Force**: THC-Hydra

#### 🔒 Internal Network Penetration
- **Information Gathering**: Seatbelt, BloodHound
- **Credential Extraction**: Mimikatz
- **Kerberos Attacks**: Rubeus

#### 🚇 Proxy & Tunneling
- **TCP Tunneling**: Chisel
- **Secure Tunneling**: Gost

#### 📊 Report Generation
- **Multiple Formats**: HTML, PDF, DOCX, Markdown
- **Customizable Templates**: Professional report templates
- **Data Export**: JSON, CSV, XML

### Installation

#### Method 1: Using Pre-built Executable (Recommended)

1. Download `WebSecToolkit.exe` from the [Releases](../../releases) page
2. Download the `config` and `tools` folders
3. Place all files in the same directory
4. Double-click `WebSecToolkit.exe` to run

#### Method 2: From Source Code

```bash
# Clone the repository
git clone https://github.com/dyfawa4/WebSecToolkit.git
cd WebSecToolkit

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Requirements

- Python 3.11+
- Windows 10/11

#### Python Dependencies
```
PyQt6>=6.6.0
requests>=2.31.0
cryptography>=41.0.0
Pillow>=10.0.0
reportlab>=4.0.0
python-docx>=0.8.11
markdown>=3.4.0
PyYAML>=6.0.0
```

### Integrated Tools

| Category | Tool | Description |
|----------|------|-------------|
| Network Scanning | Nmap | Network discovery and security auditing |
| Network Scanning | Naabu | Fast port scanner |
| Information Gathering | Subfinder | Subdomain discovery tool |
| Information Gathering | Amass | In-depth Attack Surface Mapping |
| Information Gathering | Assetfinder | Find domains and subdomains |
| Web Scanning | Dirsearch | Directory/file scanner |
| Web Scanning | Gobuster | Directory/DNS/VHost busting tool |
| Web Scanning | FFUF | Fast Web Fuzzer |
| Vulnerability Scanning | Nuclei | Template-based vulnerability scanner |
| Vulnerability Scanning | SQLMap | Automatic SQL injection tool |
| Vulnerability Scanning | Dalfox | XSS scanning and analysis tool |
| Password Cracking | Hashcat | Advanced password recovery |
| Password Cracking | John | Password security auditing tool |
| Password Cracking | Hydra | Network logon cracker |
| Internal Network | Mimikatz | Windows credential extraction |
| Internal Network | Seatbelt | Windows security audit tool |
| Internal Network | Rubeus | Kerberos abuse toolkit |
| Proxy/Tunnel | Chisel | Fast TCP tunnel |
| Proxy/Tunnel | Gost | GO Simple Tunnel |

### Usage Guide

#### 1. Tool Management
- Access via `Tools` → `Tool Management` menu
- View all integrated tools and their status
- Configure tool paths manually or use auto-detection
- Download missing tools directly from the interface

#### 2. Running Scans
1. Select a module from the left sidebar
2. Enter target URL/IP/domain
3. Configure scan options
4. Click "Start Scan" button
5. View results in real-time

#### 3. Report Generation
1. Complete your security assessment
2. Navigate to `File` → `Generate Report`
3. Select report format (HTML/PDF/DOCX/MD)
4. Customize report content
5. Export and save

### Configuration

#### Tool Paths
Edit `config/tools.json` to configure tool paths:

```json
{
  "tools": {
    "port_scanner": {
      "nmap": {
        "path": "tools/nmap/nmap.exe",
        "name": "Nmap"
      }
    }
  }
}
```

#### Application Settings
Edit `config/settings.yaml` for application preferences:

```yaml
general:
  theme: "light"
  language: "zh_CN"
  auto_save: true
  
scan:
  timeout: 300
  max_threads: 10
```

### Project Structure

```
WebSecToolkit/
├── config/                 # Configuration files
│   ├── settings.yaml      # Application settings
│   └── tools.json         # Tool configurations
├── core/                   # Core functionality
│   ├── engine.py          # Main engine
│   ├── database.py        # Database operations
│   └── tool_manager.py    # Tool management
├── gui/                    # GUI components
│   ├── main_window.py     # Main window
│   ├── dialogs/           # Dialog windows
│   └── widgets/           # Custom widgets
├── modules/                # Security modules
│   ├── recon.py           # Reconnaissance
│   ├── web.py             # Web security
│   ├── vuln_scan.py       # Vulnerability scanning
│   ├── password.py        # Password attacks
│   └── internal.py        # Internal network
├── tools/                  # External tools
├── payloads/               # Payload templates
├── templates/              # Report templates
├── main.py                 # Entry point
└── requirements.txt        # Dependencies
```

### Building from Source

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller --onefile --windowed --name "WebSecToolkit" \
  --add-data "config;config" \
  --add-data "gui;gui" \
  --hidden-import PyQt6 \
  --hidden-import requests \
  main.py
```

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Disclaimer

This tool is intended for **educational purposes** and **authorized security testing only**. Users must ensure they have proper authorization before using this tool against any target. The developers are not responsible for any misuse or damage caused by this tool.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Acknowledgments

- All the amazing open-source security tools integrated in this project
- The security community for continuous support and feedback

---

<a name="中文"></a>
## 中文

### 概述

**WebSec Toolkit** 是一款综合性的Web安全集成工具，专为渗透测试人员、安全研究人员和漏洞赏金猎人设计。它提供了友好的图形用户界面，集成了多种流行的安全工具，实现高效的安全评估和漏洞发现。

### 功能特性

#### 🔍 信息收集
- **子域名枚举**: Subfinder、Amass、Assetfinder
- **端口扫描**: Nmap、Naabu
- **DNS枚举**: DNSX
- **HTTP探测**: HTTPX、Httprobe

#### 🌐 Web安全
- **目录扫描**: Dirsearch、Gobuster、FFUF
- **指纹识别**: WhatWeb、HTTPX
- **技术检测**: 类Wappalyzer分析

#### 🔓 漏洞扫描
- **模板扫描**: Nuclei
- **SQL注入**: SQLMap
- **XSS扫描**: Dalfox
- **SSL/TLS分析**: TLSX
- **CVE查询**: SearchSploit

#### 🔑 密码破解
- **哈希破解**: Hashcat、John the Ripper
- **在线爆破**: THC-Hydra

#### 🔒 内网渗透
- **信息收集**: Seatbelt、BloodHound
- **凭证提取**: Mimikatz
- **Kerberos攻击**: Rubeus

#### 🚇 代理隧道
- **TCP隧道**: Chisel
- **安全隧道**: Gost

#### 📊 报告生成
- **多种格式**: HTML、PDF、DOCX、Markdown
- **自定义模板**: 专业报告模板
- **数据导出**: JSON、CSV、XML

### 安装方法

#### 方法一：使用预编译版本（推荐）

1. 从 [Releases](../../releases) 页面下载 `WebSecToolkit.exe`
2. 下载 `config` 和 `tools` 文件夹
3. 将所有文件放在同一目录下
4. 双击 `WebSecToolkit.exe` 运行

#### 方法二：从源码运行

```bash
# 克隆仓库
git clone https://github.com/dyfawa4/WebSecToolkit.git
cd WebSecToolkit

# 创建虚拟环境（推荐）
python -m venv venv
venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 运行程序
python main.py
```

### 系统要求

- Python 3.11+
- Windows 10/11

#### Python依赖
```
PyQt6>=6.6.0
requests>=2.31.0
cryptography>=41.0.0
Pillow>=10.0.0
reportlab>=4.0.0
python-docx>=0.8.11
markdown>=3.4.0
PyYAML>=6.0.0
```

### 集成工具列表

| 分类 | 工具 | 描述 |
|------|------|------|
| 网络扫描 | Nmap | 网络发现和安全审计 |
| 网络扫描 | Naabu | 快速端口扫描器 |
| 信息收集 | Subfinder | 子域名发现工具 |
| 信息收集 | Amass | 攻击面映射框架 |
| 信息收集 | Assetfinder | 域名和子域名查找 |
| Web扫描 | Dirsearch | 目录/文件扫描器 |
| Web扫描 | Gobuster | 目录/DNS/VHost爆破 |
| Web扫描 | FFUF | 快速Web模糊测试 |
| 漏洞扫描 | Nuclei | 基于模板的漏洞扫描器 |
| 漏洞扫描 | SQLMap | 自动SQL注入工具 |
| 漏洞扫描 | Dalfox | XSS扫描和分析工具 |
| 密码破解 | Hashcat | 高级密码恢复工具 |
| 密码破解 | John | 密码安全审计工具 |
| 密码破解 | Hydra | 网络登录破解器 |
| 内网渗透 | Mimikatz | Windows凭证提取 |
| 内网渗透 | Seatbelt | Windows安全审计工具 |
| 内网渗透 | Rubeus | Kerberos攻击工具包 |
| 代理隧道 | Chisel | 快速TCP隧道 |
| 代理隧道 | Gost | GO简单隧道 |

### 使用指南

#### 1. 工具管理
- 通过 `工具` → `工具管理` 菜单访问
- 查看所有集成工具及其状态
- 手动配置工具路径或使用自动检测
- 直接从界面下载缺失的工具

#### 2. 执行扫描
1. 从左侧边栏选择模块
2. 输入目标URL/IP/域名
3. 配置扫描选项
4. 点击"开始扫描"按钮
5. 实时查看结果

#### 3. 生成报告
1. 完成安全评估
2. 导航到 `文件` → `生成报告`
3. 选择报告格式（HTML/PDF/DOCX/MD）
4. 自定义报告内容
5. 导出并保存

### 配置说明

#### 工具路径配置
编辑 `config/tools.json` 配置工具路径：

```json
{
  "tools": {
    "port_scanner": {
      "nmap": {
        "path": "tools/nmap/nmap.exe",
        "name": "Nmap"
      }
    }
  }
}
```

#### 应用程序设置
编辑 `config/settings.yaml` 配置应用偏好：

```yaml
general:
  theme: "light"
  language: "zh_CN"
  auto_save: true
  
scan:
  timeout: 300
  max_threads: 10
```

### 项目结构

```
WebSecToolkit/
├── config/                 # 配置文件
│   ├── settings.yaml      # 应用设置
│   └── tools.json         # 工具配置
├── core/                   # 核心功能
│   ├── engine.py          # 主引擎
│   ├── database.py        # 数据库操作
│   └── tool_manager.py    # 工具管理
├── gui/                    # 图形界面
│   ├── main_window.py     # 主窗口
│   ├── dialogs/           # 对话框
│   └── widgets/           # 自定义控件
├── modules/                # 安全模块
│   ├── recon.py           # 信息收集
│   ├── web.py             # Web安全
│   ├── vuln_scan.py       # 漏洞扫描
│   ├── password.py        # 密码攻击
│   └── internal.py        # 内网渗透
├── tools/                  # 外部工具
├── payloads/               # Payload模板
├── templates/              # 报告模板
├── main.py                 # 程序入口
└── requirements.txt        # 依赖列表
```

### 从源码构建

```bash
# 安装 PyInstaller
pip install pyinstaller

# 构建可执行文件
pyinstaller --onefile --windowed --name "WebSecToolkit" \
  --add-data "config;config" \
  --add-data "gui;gui" \
  --hidden-import PyQt6 \
  --hidden-import requests \
  main.py
```

### 参与贡献

欢迎提交 Pull Request 参与贡献！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

### 免责声明

本工具仅供**教育目的**和**授权安全测试**使用。用户在对任何目标使用本工具之前，必须确保已获得适当授权。开发者不对因滥用本工具而造成的任何损害负责。

### 许可证

本项目采用 MIT 许可证 - 详情请查看 [LICENSE](LICENSE) 文件。

### 致谢

- 感谢所有集成在本项目中的优秀开源安全工具
- 感谢安全社区的持续支持和反馈

---

## Star History

If you find this project helpful, please consider giving it a ⭐️!

[![Star History Chart](https://api.star-history.com/svg?repos=dyfawa4/WebSecToolkit&type=Date)](https://star-history.com/#dyfawa4/WebSecToolkit&Date)
