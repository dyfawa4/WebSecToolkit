@echo off
chcp 65001 >nul
echo ============================================
echo    Security Toolkit 依赖安装脚本
echo ============================================
echo.

cd /d "%~dp0"

echo 检查 Python 版本...
python --version
if errorlevel 1 (
    echo 错误: 未找到 Python，请先安装 Python 3.10+
    pause
    exit /b 1
)

echo.
echo 创建虚拟环境...
if not exist "venv" (
    python -m venv venv
    echo 虚拟环境已创建
) else (
    echo 虚拟环境已存在
)

echo.
echo 激活虚拟环境...
call venv\Scripts\activate.bat

echo.
echo 升级 pip...
python -m pip install --upgrade pip -q

echo.
echo 安装依赖...
pip install -r requirements.txt

echo.
echo 安装可选依赖...
pip install impacket pwntools dnspython aiohttp -q

echo.
echo ============================================
echo    安装完成!
echo ============================================
echo.
echo 运行 run.bat 启动程序
echo.
pause
