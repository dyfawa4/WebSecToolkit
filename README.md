# WebSec Toolkit

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

### Overview

**WebSec Toolkit** is a comprehensive Web Security Integrated Tool designed for penetration testers, security researchers, and bug bounty hunters. It provides a user-friendly GUI interface that integrates multiple popular security tools, enabling efficient security assessments and vulnerability discovery.

![Version](https://img.shields.io/badge/Version-v1.1.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![PyQt6](https://img.shields.io/badge/PyQt6-6.6+-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

### Features

#### 🔍 Information Gathering
- **Port Scanning**: Nmap, Naabu, RustScan, Masscan
- **Subdomain Enumeration**: Subfinder, Subdominator, Chaos, Assetfinder
- **Directory Scanning**: Dirsearch, Gobuster, FFUF, Feroxbuster
- **Fingerprint Recognition**: WhatWeb, HTTPX
- **SSL/TLS Analysis**: TLSX
- **Email Collector**: Email enumeration and validation

#### 🌐 Web Security
- **SQL Injection**: SQLMap integration
- **XSS Scanning**: Dalfox
- **LFI/RFI**: Local/Remote File Inclusion testing
- **RCE**: Remote Code Execution testing
- **SSRF**: Server-Side Request Forgery
- **XXE**: XML External Entity injection
- **SSTI**: Server-Side Template Injection
- **CSRF**: Cross-Site Request Forgery analysis
- **API Security**: API vulnerability testing
- **Framework Vulnerabilities**: Common framework exploits
- **Authentication Vulnerabilities**: Auth bypass testing
- **File Vulnerabilities**: Upload/Include vulnerabilities
- **Cache Poisoning**: Web cache exploitation
- **HTTP Smuggling**: Request smuggling detection
- **Open Redirect**: Redirect vulnerability scanning
- **Clickjacking**: UI redress attack testing
- **Business Logic**: Logic flaw detection
- **JWT Security**: JWT vulnerability analysis
- **Supply Chain**: Dependency vulnerability scanning
- **Prototype Pollution**: JavaScript prototype analysis
- **Cloud Security**: Cloud metadata exploitation
- **WebSocket Security**: WebSocket vulnerability testing
- **AI Security**: AI/LLM application security testing

#### 🔓 Vulnerability Scanning
- **Template-based Scanning**: Nuclei
- **CVE Search**: SearchSploit
- **Batch Scanning**: Multi-target vulnerability scanning
- **PoC Management**: Proof of Concept management
- **Exploit Search**: Exploit database search

#### 🔑 Password Attacks
- **Hash Cracking**: Hashcat, John the Ripper
- **Online Brute Force**: THC-Hydra
- **Hash Identification**: Automatic hash type detection
- **Password Generator**: Secure password generation

#### 🔒 Internal Network Penetration
- **Information Gathering**: Seatbelt, system info collection
- **Credential Extraction**: Mimikatz
- **Kerberos Attacks**: Rubeus
- **Lateral Movement**: Network pivoting tools
- **Domain Attacks**: Active Directory exploitation
- **ADCS Attacks**: Certificate Services attacks
- **Evasion**: AV/EDS bypass techniques
- **Exchange**: Microsoft Exchange exploitation
- **SharePoint**: SharePoint vulnerability testing
- **Persistence**: Persistence mechanism management
- **Privilege Escalation**: Local privilege escalation

#### 🚇 Proxy & Tunneling
- **HTTP Proxy**: Built-in HTTP proxy
- **TCP Tunnel**: Chisel
- **Secure Tunnel**: Gost
- **Reverse Proxy**: Reverse connection proxy

#### 🤖 AI Assistant
- **Multi-Model Support**: OpenAI, Claude, DeepSeek, Qwen, local models
- **Security Analysis**: AI-powered vulnerability analysis
- **Code Review**: Security code review assistance
- **Report Generation**: AI-assisted report writing
- **Chat Interface**: Interactive security consultation

#### �️ Utility Tools
- **IP Tools**: IP address analysis and calculation
- **HTTP Tools**: HTTP request building and testing
- **JSON Tools**: JSON formatting and analysis
- **Regex Tools**: Regular expression testing
- **Time Tools**: Timestamp conversion
- **Diff Tools**: Text comparison

#### 🔧 Encoding & Crypto
- **Base Encoding**: Base64, Base32, Base58, Base85
- **URL Encoding**: URL encode/decode
- **Hash Calculator**: Multiple hash algorithms
- **JWT Tools**: JWT encode/decode/forgery
- **Cryptography**: Encryption/decryption tools
- **Classic Ciphers**: Caesar, Vigenère, etc.

#### 📦 Payload Generation
- **Payload Generator**: Custom payload creation
- **Encoder**: Payload encoding and obfuscation
- **Exploit DB**: Exploit database search
- **Reverse Shell**: Reverse shell generator
- **Webshell**: Webshell management
- **MSF Payload**: Metasploit payload generation

#### 📊 Report & Project Management
- **Password Generator**: Custom wordlist generation
- **Username Generator**: Username enumeration lists
- **Directory Generator**: Path wordlist creation
- **Subdomain Generator**: Subdomain wordlist creation
- **Dictionary Manager**: Wordlist management
- **Report Generator**: Professional security reports
- **Project Management**: Engagement tracking
- **Data Export**: Multiple export formats
- **Vulnerability Statistics**: Finding analytics
- **History**: Operation history tracking

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
| Network Scanning | RustScan | Modern port scanner |
| Network Scanning | Masscan | Mass IP port scanner |
| Information Gathering | Subfinder | Subdomain discovery tool |
| Information Gathering | Assetfinder | Find domains and subdomains |
| Web Scanning | Dirsearch | Directory/file scanner |
| Web Scanning | Gobuster | Directory/DNS/VHost busting tool |
| Web Scanning | FFUF | Fast Web Fuzzer |
| Web Scanning | Feroxbuster | Fast, simple, recursive content discovery |
| Vulnerability Scanning | Nuclei | Template-based vulnerability scanner |
| Vulnerability Scanning | SQLMap | Automatic SQL injection tool |
| Vulnerability Scanning | Dalfox | XSS scanning and analysis tool |
| Vulnerability Scanning | SearchSploit | Exploit database search |
| Vulnerability Scanning | SSTImap | Server-Side Template Injection detection and exploitation |
| Vulnerability Scanning | Fenjing | Flask/Jinja2 SSTI exploitation tool for CTF |
| Password Cracking | Hashcat | Advanced password recovery |
| Password Cracking | John | Password security auditing tool |
| Password Cracking | Hydra | Network logon cracker |
| Internal Network | Mimikatz | Windows credential extraction |
| Internal Network | Seatbelt | Windows security audit tool |
| Internal Network | Rubeus | Kerberos abuse toolkit |
| Proxy/Tunnel | Chisel | Fast TCP tunnel |
| Proxy/Tunnel | Gost | GO Simple Tunnel |
| SSL/TLS | TLSX | TLS analysis tool |
| HTTP | HTTPX | HTTP toolkit |

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

#### 3. AI Assistant
1. Configure AI provider in Settings
2. Enter API key for your preferred provider
3. Use chat interface for security questions
4. Enable auto-analysis for scan results

#### 4. Report Generation
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
  theme: "dark"
  language: "zh_CN"
  auto_save: true
  
scan:
  timeout: 300
  max_threads: 10

ai:
  provider: "openai"
  model: "gpt-4"
  api_key: "your-api-key"
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
│   ├── tool_manager.py    # Tool management
│   └── ai_service.py      # AI service integration
├── gui/                    # GUI components
│   ├── main_window.py     # Main window
│   ├── dialogs/           # Dialog windows
│   └── widgets/           # Custom widgets
├── modules/                # Security modules
│   ├── recon.py           # Reconnaissance
│   ├── web.py             # Web security
│   ├── web_adv.py         # Advanced web security
│   ├── vuln_scan.py       # Vulnerability scanning
│   ├── password.py        # Password attacks
│   ├── internal.py        # Internal network
│   ├── internal_adv.py    # Advanced internal
│   ├── ai_assistant.py    # AI assistant
│   ├── payload.py         # Payload generation
│   ├── payload_adv.py     # Advanced payloads
│   ├── tools.py           # Utility tools
│   ├── utils.py           # General utilities
│   ├── proxy.py           # Proxy tools
│   └── gen.py             # Generators
├── tools/                  # External tools
├── payloads/               # Payload templates
├── templates/              # Report templates
├── main.py                 # Entry point
├── WebSecToolkit.exe      # Compiled executable
└── requirements.txt        # Dependencies
```

### Building from Source

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
pyinstaller WebSecToolkit.spec --noconfirm
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
- **端口扫描**: Nmap、Naabu、RustScan、Masscan
- **子域名枚举**: Subfinder、Subdominator、Chaos、Assetfinder
- **目录扫描**: Dirsearch、Gobuster、FFUF、Feroxbuster
- **指纹识别**: WhatWeb、HTTPX
- **SSL/TLS分析**: TLSX
- **邮箱收集**: 邮箱枚举和验证

#### 🌐 Web安全
- **SQL注入**: SQLMap集成
- **XSS扫描**: Dalfox
- **LFI/RFI**: 本地/远程文件包含测试
- **RCE**: 远程代码执行测试
- **SSRF**: 服务端请求伪造
- **XXE**: XML外部实体注入
- **SSTI**: 服务端模板注入
- **CSRF**: 跨站请求伪造分析
- **API安全**: API漏洞测试
- **框架漏洞**: 常见框架漏洞利用
- **认证漏洞**: 认证绕过测试
- **文件漏洞**: 上传/包含漏洞
- **缓存投毒**: Web缓存利用
- **HTTP走私**: 请求走私检测
- **开放重定向**: 重定向漏洞扫描
- **点击劫持**: UI伪装攻击测试
- **业务逻辑**: 逻辑缺陷检测
- **JWT安全**: JWT漏洞分析
- **供应链**: 依赖漏洞扫描
- **原型污染**: JavaScript原型分析
- **云安全**: 云元数据利用
- **WebSocket安全**: WebSocket漏洞测试
- **AI安全**: AI/LLM应用安全测试

#### 🔓 漏洞扫描
- **模板扫描**: Nuclei
- **CVE查询**: SearchSploit
- **批量扫描**: 多目标漏洞扫描
- **PoC管理**: 漏洞验证管理
- **漏洞搜索**: 漏洞库搜索

#### 🔑 密码攻击
- **哈希破解**: Hashcat、John the Ripper
- **在线爆破**: THC-Hydra
- **哈希识别**: 自动哈希类型检测
- **密码生成**: 安全密码生成

#### 🔒 内网渗透
- **信息收集**: Seatbelt、系统信息收集
- **凭证提取**: Mimikatz
- **Kerberos攻击**: Rubeus
- **横向移动**: 网络 pivoting 工具
- **域攻击**: Active Directory 利用
- **ADCS攻击**: 证书服务攻击
- **免杀**: AV/EDS 绕过技术
- **Exchange**: Microsoft Exchange 利用
- **SharePoint**: SharePoint 漏洞测试
- **权限维持**: 持久化机制管理
- **权限提升**: 本地权限提升

#### 🚇 代理隧道
- **HTTP代理**: 内置HTTP代理
- **TCP隧道**: Chisel
- **安全隧道**: Gost
- **反向代理**: 反向连接代理

#### 🤖 AI助手
- **多模型支持**: OpenAI、Claude、DeepSeek、通义千问、本地模型
- **安全分析**: AI驱动的漏洞分析
- **代码审计**: 安全代码审查辅助
- **报告生成**: AI辅助报告撰写
- **对话界面**: 交互式安全咨询

#### 🛠️ 实用工具
- **IP工具**: IP地址分析和计算
- **HTTP工具**: HTTP请求构建和测试
- **JSON工具**: JSON格式化和分析
- **正则工具**: 正则表达式测试
- **时间工具**: 时间戳转换
- **对比工具**: 文本比较

#### 🔧 编码与加密
- **Base编码**: Base64、Base32、Base58、Base85
- **URL编码**: URL编码/解码
- **哈希计算**: 多种哈希算法
- **JWT工具**: JWT编码/解码/伪造
- **加密解密**: 加密/解密工具
- **古典密码**: 凯撒、维吉尼亚等

#### 📦 Payload生成
- **Payload生成器**: 自定义Payload创建
- **编码器**: Payload编码和混淆
- **漏洞库**: 漏洞数据库搜索
- **反弹Shell**: 反弹Shell生成器
- **Webshell**: Webshell管理
- **MSF Payload**: Metasploit Payload生成

#### 📊 报告与项目管理
- **密码生成**: 自定义字典生成
- **用户名生成**: 用户名枚举列表
- **目录生成**: 路径字典创建
- **子域名生成**: 子域名字典创建
- **字典管理**: 字典文件管理
- **报告生成**: 专业安全报告
- **项目管理**: 项目跟踪管理
- **数据导出**: 多种导出格式
- **漏洞统计**: 发现结果分析
- **历史记录**: 操作历史追踪

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
| 网络扫描 | RustScan | 现代端口扫描器 |
| 网络扫描 | Masscan | 大规模IP端口扫描 |
| 信息收集 | Subfinder | 子域名发现工具 |
| 信息收集 | Assetfinder | 域名和子域名查找 |
| Web扫描 | Dirsearch | 目录/文件扫描器 |
| Web扫描 | Gobuster | 目录/DNS/VHost爆破 |
| Web扫描 | FFUF | 快速Web模糊测试 |
| Web扫描 | Feroxbuster | 快速递归内容发现 |
| 漏洞扫描 | Nuclei | 基于模板的漏洞扫描器 |
| 漏洞扫描 | SQLMap | 自动SQL注入工具 |
| 漏洞扫描 | Dalfox | XSS扫描和分析工具 |
| 漏洞扫描 | SearchSploit | 漏洞数据库搜索 |
| 漏洞扫描 | SSTImap | 服务端模板注入检测与利用 |
| 漏洞扫描 | Fenjing | Flask/Jinja2 SSTI漏洞利用工具(CTF专用) |
| 密码破解 | Hashcat | 高级密码恢复工具 |
| 密码破解 | John | 密码安全审计工具 |
| 密码破解 | Hydra | 网络登录破解器 |
| 内网渗透 | Mimikatz | Windows凭证提取 |
| 内网渗透 | Seatbelt | Windows安全审计工具 |
| 内网渗透 | Rubeus | Kerberos攻击工具包 |
| 代理隧道 | Chisel | 快速TCP隧道 |
| 代理隧道 | Gost | GO简单隧道 |
| SSL/TLS | TLSX | TLS分析工具 |
| HTTP | HTTPX | HTTP工具包 |

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

#### 3. AI助手
1. 在设置中配置AI提供商
2. 输入您首选提供商的API密钥
3. 使用聊天界面进行安全咨询
4. 启用扫描结果自动分析

#### 4. 生成报告
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
  theme: "dark"
  language: "zh_CN"
  auto_save: true
  
scan:
  timeout: 300
  max_threads: 10

ai:
  provider: "openai"
  model: "gpt-4"
  api_key: "your-api-key"
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
│   ├── tool_manager.py    # 工具管理
│   └── ai_service.py      # AI服务集成
├── gui/                    # 图形界面
│   ├── main_window.py     # 主窗口
│   ├── dialogs/           # 对话框
│   └── widgets/           # 自定义控件
├── modules/                # 安全模块
│   ├── recon.py           # 信息收集
│   ├── web.py             # Web安全
│   ├── web_adv.py         # 高级Web安全
│   ├── vuln_scan.py       # 漏洞扫描
│   ├── password.py        # 密码攻击
│   ├── internal.py        # 内网渗透
│   ├── internal_adv.py    # 高级内网
│   ├── ai_assistant.py    # AI助手
│   ├── payload.py         # Payload生成
│   ├── payload_adv.py     # 高级Payload
│   ├── tools.py           # 实用工具
│   ├── utils.py           # 通用工具
│   ├── proxy.py           # 代理工具
│   └── gen.py             # 生成器
├── tools/                  # 外部工具
├── payloads/               # Payload模板
├── templates/              # 报告模板
├── main.py                 # 程序入口
├── WebSecToolkit.exe      # 编译后的可执行文件
└── requirements.txt        # 依赖列表
```

### 从源码构建

```bash
# 安装 PyInstaller
pip install pyinstaller

# 构建可执行文件
pyinstaller WebSecToolkit.spec --noconfirm
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
