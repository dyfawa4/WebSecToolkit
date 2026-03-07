import os
import sys
import subprocess
import urllib.request
import zipfile
import shutil
from pathlib import Path


TOOLS_DIR = Path(__file__).parent.parent / "tools"
TOOLS_CONFIG = {
    "windows": {
        "nmap": {
            "url": "https://nmap.org/dist/nmap-7.95-win.zip",
            "filename": "nmap-7.95-win.zip",
            "extract_dir": "nmap",
            "executable": "nmap.exe"
        },
        "sqlmap": {
            "url": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
            "filename": "sqlmap.zip",
            "extract_dir": "sqlmap",
            "executable": "sqlmap.py"
        },
        "gobuster": {
            "url": "https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Windows_x86_64.zip",
            "filename": "gobuster.zip",
            "extract_dir": "gobuster",
            "executable": "gobuster.exe"
        },
        "nuclei": {
            "url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_windows_amd64.zip",
            "filename": "nuclei.zip",
            "extract_dir": "nuclei",
            "executable": "nuclei.exe"
        },
        "subfinder": {
            "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_windows_amd64.zip",
            "filename": "subfinder.zip",
            "extract_dir": "subfinder",
            "executable": "subfinder.exe"
        },
        "httpx": {
            "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_windows_amd64.zip",
            "filename": "httpx.zip",
            "extract_dir": "httpx",
            "executable": "httpx.exe"
        },
        "naabu": {
            "url": "https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_windows_amd64.zip",
            "filename": "naabu.zip",
            "extract_dir": "naabu",
            "executable": "naabu.exe"
        },
        "ffuf": {
            "url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip",
            "filename": "ffuf.zip",
            "extract_dir": "ffuf",
            "executable": "ffuf.exe"
        },
        "massdns": {
            "url": "https://github.com/blechschmidt/massdns/releases/download/v1.0.0/massdns_1.0.0_windows_amd64.zip",
            "filename": "massdns.zip",
            "extract_dir": "massdns",
            "executable": "massdns.exe"
        },
        "john": {
            "url": "https://www.openwall.com/john/h/john180j1w.zip",
            "filename": "john.zip",
            "extract_dir": "john",
            "executable": "john.exe"
        },
        "dirsearch": {
            "url": "https://github.com/maurosoria/dirsearch/archive/refs/heads/master.zip",
            "filename": "dirsearch.zip",
            "extract_dir": "dirsearch",
            "executable": "dirsearch.py"
        },
        "amass": {
            "url": "https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_3.23.3_windows_amd64.zip",
            "filename": "amass.zip",
            "extract_dir": "amass",
            "executable": "amass.exe"
        },
        "assetfinder": {
            "url": "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-windows-amd64-0.1.1.zip",
            "filename": "assetfinder.zip",
            "extract_dir": "assetfinder",
            "executable": "assetfinder.exe"
        },
        "httprobe": {
            "url": "https://github.com/tomnomnom/httprobe/releases/download/v0.2/httprobe-windows-amd64-0.2.zip",
            "filename": "httprobe.zip",
            "extract_dir": "httprobe",
            "executable": "httprobe.exe"
        },
        "waybackurls": {
            "url": "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-windows-amd64-0.1.0.zip",
            "filename": "waybackurls.zip",
            "extract_dir": "waybackurls",
            "executable": "waybackurls.exe"
        },
        "dnsx": {
            "url": "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_windows_amd64.zip",
            "filename": "dnsx.zip",
            "extract_dir": "dnsx",
            "executable": "dnsx.exe"
        },
        "tlsx": {
            "url": "https://github.com/projectdiscovery/tlsx/releases/download/v1.1.6/tlsx_1.1.6_windows_amd64.zip",
            "filename": "tlsx.zip",
            "extract_dir": "tlsx",
            "executable": "tlsx.exe"
        },
        "katana": {
            "url": "https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_windows_amd64.zip",
            "filename": "katana.zip",
            "extract_dir": "katana",
            "executable": "katana.exe"
        },
        "dalfox": {
            "url": "https://github.com/hahwul/dalfox/releases/download/v2.9.0/dalfox_2.9.0_windows_amd64.zip",
            "filename": "dalfox.zip",
            "extract_dir": "dalfox",
            "executable": "dalfox.exe"
        },
        "nuclei-templates": {
            "url": "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip",
            "filename": "nuclei-templates.zip",
            "extract_dir": "nuclei-templates",
            "executable": ""
        },
        "secLists": {
            "url": "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip",
            "filename": "SecLists.zip",
            "extract_dir": "SecLists",
            "executable": ""
        },
        "payloadsAllTheThings": {
            "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/archive/refs/heads/master.zip",
            "filename": "PayloadsAllTheThings.zip",
            "extract_dir": "PayloadsAllTheThings",
            "executable": ""
        }
    }
}


def download_file(url: str, dest: Path) -> bool:
    print(f"  下载中: {url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            with open(dest, 'wb') as out_file:
                out_file.write(response.read())
        print(f"  已保存到: {dest}")
        return True
    except Exception as e:
        print(f"  下载失败: {e}")
        return False


def extract_zip(zip_path: Path, extract_to: Path) -> bool:
    print(f"  解压中: {zip_path}")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(f"  解压到: {extract_to}")
        return True
    except Exception as e:
        print(f"  解压失败: {e}")
        return False


def download_tool(tool_name: str, config: dict) -> bool:
    print(f"\n{'='*50}")
    print(f"下载工具: {tool_name}")
    print(f"{'='*50}")

    tool_dir = TOOLS_DIR / config.get("extract_dir", tool_name)
    tool_dir.mkdir(parents=True, exist_ok=True)

    zip_path = TOOLS_DIR / config["filename"]

    if not download_file(config["url"], zip_path):
        return False

    if not extract_zip(zip_path, tool_dir):
        return False

    try:
        os.remove(zip_path)
        print(f"  已删除临时文件: {zip_path}")
    except:
        pass

    print(f"  ✓ {tool_name} 安装完成!")
    return True


def check_python_tools():
    print("\n检查Python工具...")

    python_tools = [
        ("sqlmap", "sqlmap", "python -m sqlmap --version"),
        ("impacket", "impacket", "python -m impacket.examples.wmiexec --help"),
        ("pwntools", "pwntools", "python -c \"from pwn import *; print('pwntools installed')\""),
        ("requests", "requests", "python -c \"import requests; print('requests installed')\""),
        ("beautifulsoup4", "beautifulsoup4", "python -c \"import bs4; print('bs4 installed')\""),
        ("scapy", "scapy", "python -c \"from scapy.all import *; print('scapy installed')\""),
    ]

    for name, package, test_cmd in python_tools:
        print(f"  检查 {name}...")
        try:
            result = subprocess.run(
                test_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"  ✓ {name} 已安装")
            else:
                print(f"  ✗ {name} 未安装，尝试安装...")
                install_result = subprocess.run(
                    f"pip install {package}",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if install_result.returncode == 0:
                    print(f"  ✓ {name} 安装成功")
                else:
                    print(f"  ✗ {name} 安装失败")
        except Exception as e:
            print(f"  ✗ {name} 检查失败: {e}")


def download_wordlists():
    print("\n下载常用字典...")

    wordlists_dir = TOOLS_DIR.parent / "wordlists"
    wordlists_dir.mkdir(parents=True, exist_ok=True)

    wordlists = {
        "passwords": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-common.txt",
        ],
        "directories": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
        ],
        "subdomains": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
        ],
        "usernames": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/xato-net-10-million-usernames.txt",
        ]
    }

    for category, urls in wordlists.items():
        category_dir = wordlists_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)

        for url in urls:
            filename = url.split("/")[-1]
            dest = category_dir / filename

            if dest.exists():
                print(f"  ✓ {filename} 已存在")
                continue

            print(f"  下载 {filename}...")
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req) as response:
                    with open(dest, 'wb') as out_file:
                        out_file.write(response.read())
                print(f"  ✓ {filename} 下载完成")
            except Exception as e:
                print(f"  ✗ {filename} 下载失败: {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="安全工具下载脚本")
    parser.add_argument('-y', '--yes', action='store_true', help='自动确认下载')
    parser.add_argument('--tools', nargs='+', help='指定要下载的工具')
    args = parser.parse_args()

    print("="*60)
    print("    安全工具下载脚本")
    print("="*60)

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    platform = "windows" if sys.platform == "win32" else "linux"

    if platform not in TOOLS_CONFIG:
        print(f"不支持的操作系统: {platform}")
        return

    tools = TOOLS_CONFIG[platform]

    if args.tools:
        tools = {k: v for k, v in tools.items() if k in args.tools}

    print(f"\n将下载以下工具:")
    for tool_name in tools:
        print(f"  - {tool_name}")

    if args.yes:
        response = 'y'
    else:
        response = input("\n是否继续? (y/n): ").strip().lower()

    if response != 'y':
        print("已取消")
        return

    success_count = 0
    for tool_name, config in tools.items():
        if download_tool(tool_name, config):
            success_count += 1

    check_python_tools()
    download_wordlists()

    print("\n" + "="*60)
    print(f"下载完成! 成功: {success_count}/{len(tools)}")
    print("="*60)


if __name__ == "__main__":
    main()