#!/usr/bin/env python3
"""
Nuitka打包脚本，用于将h_side_init.py打包成exe文件
"""

import subprocess
import sys
import os
import platform
import requests
from pathlib import Path


def download_icon():
    """下载图标文件"""
    icon_url = "https://raw.githubusercontent.com/trustedinster/ZASCA/refs/heads/master/static/img/favicon.ico"
    icon_path = "app_icon.ico"
    
    try:
        print("正在下载图标文件...")
        response = requests.get(icon_url)
        response.raise_for_status()
        
        with open(icon_path, 'wb') as f:
            f.write(response.content)
        
        print(f"✓ 图标文件已保存至 {icon_path}")
        return icon_path
    except Exception as e:
        print(f"✗ 下载图标失败: {e}")
        return None


def build_with_nuitka():
    """使用Nuitka构建exe文件"""
    try:
        # 检查h_side_init.py是否存在
        if not os.path.exists("h_side_init.py"):
            print("错误: 找不到h_side_init.py文件")
            return False
        
        # 下载图标文件
        icon_path = download_icon()
        
        # 构建命令
        cmd = [
            "python", "-m", "nuitka",
            "--standalone",
            "--onefile",
            "--assume-yes-for-downloads",
            "--windows-file-description=ZASCA主机端自动化部署程序",
            "--windows-product-name=ZASCA H-Side",
            "--windows-company-name=Supercmd",
            "--windows-file-version=1.0.0",
            "--windows-product-version=1.0.0",
            "--include-package=requests",
            "--windows-uac-admin",  # 请求管理员权限
            "--enable-plugin=tk-inter",  # 如果使用tkinter的话
        ]
        
        # 如果图标下载成功，添加图标参数
        if icon_path and os.path.exists(icon_path):
            cmd.append(f"--windows-icon-from-ico={icon_path}")
            print(f"✓ 将使用图标: {icon_path}")
        
        cmd.extend([
            "--output-filename=h_side_init.exe",
            "h_side_init.py"
        ])
        
        print("正在使用Nuitka构建exe文件...")
        print(f"执行命令: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ exe文件构建成功!")
            print(f"输出文件: h_side_init.exe")
            return True
        else:
            print(f"✗ 构建失败")
            print(f"错误信息: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("错误: 找不到nuitka，请先安装: pip install nuitka")
        return False
    except Exception as e:
        print(f"构建过程中出现错误: {e}")
        return False


def install_dependencies():
    """安装必要的依赖"""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        subprocess.check_call([sys.executable, "-m", "pip", "install", "nuitka"])
        print("✓ 依赖安装完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ 依赖安装失败: {e}")
        return False


if __name__ == "__main__":
    print("ZASCA H端初始化脚本 - Nuitka构建工具")
    print("=" * 50)
    
    # 安装依赖
    if not install_dependencies():
        sys.exit(1)
    
    # 构建exe
    if build_with_nuitka():
        print("\n构建完成! 可以在当前目录找到 h_side_init.exe 文件")
    else:
        print("\n构建失败，请检查错误信息")
        sys.exit(1)