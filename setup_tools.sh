#!/bin/bash
# ============================================================
# Auto-Hacker Agent - CVM 环境工具安装脚本
# 目标环境: Ubuntu 24, 8C16G
# ============================================================

set -e

echo "========================================"
echo " Auto-Hacker Agent 工具安装脚本"
echo "========================================"

# 更新软件源
echo "[1/8] 更新软件源..."
sudo apt-get update -qq

# 安装基础工具
echo "[2/8] 安装基础工具..."
sudo apt-get install -y -qq \
    curl wget git vim unzip \
    net-tools iputils-ping dnsutils \
    build-essential python3-pip python3-venv \
    jq

# 安装网络扫描工具
echo "[3/8] 安装网络扫描工具..."
sudo apt-get install -y -qq \
    nmap \
    masscan \
    netcat-openbsd

# 安装 Web 渗透工具
echo "[4/8] 安装 Web 渗透工具..."
sudo apt-get install -y -qq \
    nikto \
    dirb \
    gobuster \
    whatweb \
    wfuzz

# 安装 SQLMap
echo "[5/8] 安装 SQLMap..."
sudo apt-get install -y -qq sqlmap

# 安装密码破解工具
echo "[6/8] 安装密码破解工具..."
sudo apt-get install -y -qq \
    hydra \
    john \
    hashcat

# 安装其他渗透工具
echo "[7/8] 安装其他渗透工具..."
sudo apt-get install -y -qq \
    smbclient \
    enum4linux \
    sshpass \
    proxychains4 \
    socat

# 安装 Metasploit Framework（可选，较大）
echo "[8/8] 安装 Metasploit Framework..."
if ! command -v msfconsole &> /dev/null; then
    curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
    chmod 755 /tmp/msfinstall
    /tmp/msfinstall || echo "警告: Metasploit 安装失败，可跳过"
else
    echo "Metasploit 已安装，跳过"
fi

# 安装 Python 依赖
echo "安装 Python 依赖..."
cd "$(dirname "$0")"
pip3 install -r requirements.txt

# 创建日志目录
mkdir -p logs

echo ""
echo "========================================"
echo " 安装完成！"
echo "========================================"
echo ""
echo "已安装工具列表:"
echo "  - nmap, masscan, netcat"
echo "  - nikto, dirb, gobuster, whatweb, wfuzz"
echo "  - sqlmap"
echo "  - hydra, john, hashcat"
echo "  - smbclient, enum4linux, proxychains"
echo "  - metasploit (如安装成功)"
echo ""
echo "下一步: 复制 .env.example 为 .env 并配置 API Key"
echo "  cp .env.example .env"
echo "  vim .env"
