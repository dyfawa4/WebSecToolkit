import os
import sys
import subprocess
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def clean():
    print("清理构建目录...")

    dirs_to_clean = [DIST_DIR, BUILD_DIR]
    for dir_path in dirs_to_clean:
        if dir_path.exists():
            shutil.rmtree(dir_path)
            print(f"  已删除: {dir_path}")

    spec_file = PROJECT_ROOT / "main.spec"
    if spec_file.exists():
        os.remove(spec_file)
        print(f"  已删除: {spec_file}")

    print("  清理完成!")


def install_pyinstaller():
    print("检查PyInstaller...")
    try:
        import PyInstaller
        print("  PyInstaller 已安装")
    except ImportError:
        print("  安装 PyInstaller...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pyinstaller"],
            check=True
        )
        print("  PyInstaller 安装完成")


def build():
    print("\n开始构建...")

    main_py = PROJECT_ROOT / "main.py"
    if not main_py.exists():
        print(f"错误: 找不到 {main_py}")
        return False

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=WebSecToolkit",
        "--windowed",
        "--onefile",
        "--clean",
        "--noconfirm",
        f"--add-data={PROJECT_ROOT / 'config'};config",
        f"--add-data={PROJECT_ROOT / 'wordlists'};wordlists",
        f"--add-data={PROJECT_ROOT / 'payloads'};payloads",
        f"--add-data={PROJECT_ROOT / 'templates'};templates",
        f"--icon={PROJECT_ROOT / 'assets' / 'icon.ico'}",
        str(main_py)
    ]

    cmd = [c for c in cmd if not c.startswith("--icon=") or (PROJECT_ROOT / "assets" / "icon.ico").exists()]

    print(f"  执行: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)

    if result.returncode == 0:
        print("  构建成功!")
        return True
    else:
        print("  构建失败!")
        return False


def create_portable():
    print("\n创建便携版...")

    portable_dir = DIST_DIR / "WebSecToolkit-Portable"
    if portable_dir.exists():
        shutil.rmtree(portable_dir)

    portable_dir.mkdir(parents=True, exist_ok=True)

    exe_src = DIST_DIR / "WebSecToolkit.exe"
    if exe_src.exists():
        shutil.copy(exe_src, portable_dir / "WebSecToolkit.exe")

    dirs_to_copy = ["config", "wordlists", "payloads", "templates", "tools"]
    for dir_name in dirs_to_copy:
        src = PROJECT_ROOT / dir_name
        if src.exists():
            dst = portable_dir / dir_name
            shutil.copytree(src, dst)

    readme_content = """# WebSec Toolkit - 便携版

## 使用方法
1. 双击 `WebSecToolkit.exe` 启动程序
2. 首次运行会自动创建必要的配置文件

## 目录说明
- `config/` - 配置文件目录
- `wordlists/` - 字典文件目录
- `payloads/` - Payload模板目录
- `templates/` - 报告模板目录
- `tools/` - 集成的安全工具

## 注意事项
- 请确保已安装必要的运行时环境
- 部分安全工具可能需要管理员权限运行
- 请在合法授权范围内使用本工具

## 免责声明
本工具仅供安全研究和授权测试使用，请勿用于非法用途。
使用者需自行承担使用本工具所产生的一切法律责任。
"""

    with open(portable_dir / "README.txt", "w", encoding="utf-8") as f:
        f.write(readme_content)

    print(f"  便携版创建完成: {portable_dir}")
    return portable_dir


def main():
    print("=" * 50)
    print("WebSec Toolkit 构建脚本")
    print("=" * 50)

    clean()
    install_pyinstaller()

    if build():
        portable_dir = create_portable()
        print("\n" + "=" * 50)
        print("构建完成!")
        print(f"  EXE: {DIST_DIR / 'WebSecToolkit.exe'}")
        print(f"  便携版: {portable_dir}")
        print("=" * 50)
    else:
        print("\n构建失败，请检查错误信息")
        sys.exit(1)


if __name__ == "__main__":
    main()
