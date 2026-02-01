#!/usr/bin/env python3
"""
ZASCA H端初始化脚本
此脚本在H端运行，通过secret参数从C端获取所有必要的配置，
包括CA根证书、服务器证书、WinRM配置等，并完成一次性初始化
"""

import sys
import os
import subprocess
import tempfile
import json
import base64
import argparse
from urllib.parse import urlparse
import requests
import platform
import socket
import re
import shutil
from datetime import datetime


class HSideInitializer:
    def __init__(self, secret):
        self.secret = secret
        self.decoded_secret = self._decode_secret(secret)
        self.c_side_url = self.decoded_secret.get('c_side_url')
        self.token = self.decoded_secret.get('token')
        self.hostname = socket.gethostname()
        self.ip_address = self._get_local_ip()
        
    def _decode_secret(self, secret):
        """
        解码从C端获取的secret
        secret格式: base64(json({c_side_url: "...", token: "..."}))
        """
        try:
            decoded_bytes = base64.b64decode(secret)
            decoded_str = decoded_bytes.decode('utf-8')
            return json.loads(decoded_str)
        except Exception as e:
            raise ValueError(f"无法解码secret: {e}")
    
    def _get_local_ip(self):
        """获取本地IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _verify_environment(self):
        """验证运行环境"""
        if platform.system().lower() != 'windows':
            raise EnvironmentError("此脚本只能在Windows系统上运行")
        
        # 检查PowerShell是否可用
        try:
            result = subprocess.run(['powershell', '-Command', '$PSVersionTable.PSVersion'], 
                                  capture_output=True, text=True, check=True)
            print(f"✓ PowerShell版本: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            raise EnvironmentError("PowerShell不可用或版本过低")
        
        # 检查WinRM服务状态
        try:
            result = subprocess.run(['powershell', '-Command', 'Get-Service WinRM'], 
                                  capture_output=True, text=True, check=True)
            print(f"✓ WinRM服务状态: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            print("⚠ WinRM服务未安装，将启用它")
    
    def _enable_winrm_service(self):
        """启用WinRM服务"""
        print("1. 启用WinRM服务...")
        ps_script = '''
        Enable-PSRemoting -Force
        Set-Service -Name WinRM -StartupType Automatic
        Get-Service WinRM
        '''
        
        result = subprocess.run(['powershell', '-Command', ps_script], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"启用WinRM服务失败: {result.stderr}")
        
        print("✓ WinRM服务已启用")
    
    def _configure_winrm_https(self, certificate_thumbprint):
        """配置WinRM HTTPS监听器"""
        print("2. 配置WinRM HTTPS监听器...")
        
        ps_script = f'''
        $selectorset = @{{Transport="HTTPS"}}
        Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selectorset -ErrorAction SilentlyContinue | Remove-WSManInstance

        $resourceset = @{{Port="5986"; CertificateThumbprint="{certificate_thumbprint}"}}
        New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet $selectorset -ValueSet $resourceset

        # 配置基本认证
        Set-Item -Path "WSMan:\\localhost\\Service\\Auth\\Basic" -Value $true
        Set-Item -Path "WSMan:\\localhost\\Service\\AllowUnencrypted" -Value $false
        
        # 重启WinRM服务
        Restart-Service WinRM
        '''
        
        result = subprocess.run(['powershell', '-Command', ps_script], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"配置WinRM HTTPS监听器失败: {result.stderr}")
        
        print("✓ WinRM HTTPS监听器已配置")
    
    def _configure_firewall(self):
        """配置防火墙规则"""
        print("3. 配置防火墙规则...")
        
        ps_script = '''
        if (-not (Get-NetFirewallRule -Name "WinRM-HTTPS-In-TCP-Public" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "WinRM-HTTPS-In-TCP-Public" -DisplayName "WinRM HTTPS Inbound" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -Profile Public,Private,Domain
        }
        '''
        
        result = subprocess.run(['powershell', '-Command', ps_script], 
                              capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"配置防火墙规则失败: {result.stderr}")
        
        print("✓ 防火墙规则已配置")
    
    def _install_ca_certificate(self, ca_cert_pem):
        """安装CA根证书"""
        print("4. 安装CA根证书...")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as cert_file:
            cert_file.write(ca_cert_pem)
            cert_file_path = cert_file.name
        
        try:
            ps_script = f'''
            Import-Certificate -FilePath "{cert_file_path}" -CertStoreLocation Cert:\\LocalMachine\\Root
            '''
            
            result = subprocess.run(['powershell', '-Command', ps_script], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"安装CA根证书失败: {result.stderr}")
            
            print("✓ CA根证书已安装")
        finally:
            # 清理临时文件
            os.unlink(cert_file_path)
    
    def _install_server_certificate(self, server_cert_pem, server_key_pem, pfx_data_b64):
        """安装服务器证书"""
        print("5. 安装服务器证书...")
        
        # 实际的PFX文件应该是二进制格式，我们需要正确处理
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pfx', delete=False) as pfx_file:
            pfx_file.write(base64.b64decode(pfx_data_b64))
            pfx_file_path = pfx_file.name
        
        try:
            ps_script = f'''
            $certPass = ""  # 如果PFX有密码保护，则在此处指定
            $securePass = ConvertTo-SecureString -String $certPass -Force -AsPlainText
            Import-PfxCertificate -FilePath "{pfx_file_path}" -CertStoreLocation Cert:\\LocalMachine\\My -Password $securePass -Exportable
            
            # 获取刚导入的证书
            $cert = Get-ChildItem -Path Cert:\\LocalMachine\\My | Where-Object {{$_.Subject -eq "CN={self.hostname}"}} | Select-Object -First 1
            if ($cert) {{
                $cert.Thumbprint
            }} else {{
                Write-Error "未能找到安装的证书"
            }}
            '''
            
            result = subprocess.run(['powershell', '-Command', ps_script], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"安装服务器证书失败: {result.stderr}")
            
            # 获取证书指纹
            thumbprint = result.stdout.strip()
            if not thumbprint or "Error" in result.stderr:
                raise RuntimeError(f"获取证书指纹失败: {result.stderr}")
            
            print(f"✓ 服务器证书已安装，指纹: {thumbprint}")
            return thumbprint
        finally:
            # 清理临时文件
            os.unlink(pfx_file_path)
    
    def _get_bootstrap_config(self):
        """从C端获取初始化配置"""
        print("正在从C端获取配置...")
        
        url = f"{self.c_side_url}/bootstrap/config/"
        
        payload = {
            'auth_token': self.token,
            'hostname': self.hostname,
            'ip_address': self.ip_address
        }
        
        try:
            response = requests.post(url, json=payload, timeout=30)
            
            if response.status_code != 200:
                raise RuntimeError(f"获取配置失败，状态码: {response.status_code}, 错误: {response.text}")
            
            result = response.json()
            
            if not result.get('success'):
                raise RuntimeError(f"C端返回错误: {result.get('error', '未知错误')}")
            
            config_data = result.get('data', {})
            print("✓ 成功获取C端配置")
            return config_data
            
        except requests.RequestException as e:
            raise RuntimeError(f"网络请求失败: {e}")
        except json.JSONDecodeError:
            raise RuntimeError(f"响应不是有效的JSON格式: {response.text}")
    
    def _report_completion_to_c_side(self, certificate_thumbprint):
        """向C端报告初始化完成"""
        print("向C端报告初始化完成...")
        
        url = f"{self.c_side_url}/bootstrap/status/"
        
        payload = {
            'token': self.token,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'status': 'completed',
            'certificate_thumbprint': certificate_thumbprint
        }
        
        headers = {
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code != 200:
                print(f"⚠ 向C端报告状态失败，状态码: {response.status_code}")
                print(f"  响应: {response.text}")
                # 不抛出异常，因为配置已完成
            else:
                result = response.json()
                if result.get('success'):
                    print("✓ 成功向C端报告初始化完成")
                else:
                    print(f"⚠ C端返回状态报告错误: {result.get('error', '未知错误')}")
                    
        except requests.RequestException as e:
            print(f"⚠ 向C端报告状态时网络错误: {e}")
        except json.JSONDecodeError:
            print(f"⚠ C端响应不是有效的JSON格式: {response.text}")
    
    def initialize(self):
        """执行完整的初始化流程"""
        print("=" * 60)
        print("ZASCA H端一次性初始化开始")
        print(f"主机名: {self.hostname}")
        print(f"IP地址: {self.ip_address}")
        print(f"C端地址: {self.c_side_url}")
        print("=" * 60)
        
        try:
            # 1. 验证运行环境
            self._verify_environment()
            
            # 2. 从C端获取配置
            config = self._get_bootstrap_config()
            
            # 3. 启用WinRM服务
            self._enable_winrm_service()
            
            # 4. 安装CA根证书
            ca_cert = config.get('ca_cert')
            if not ca_cert:
                raise ValueError("配置中缺少CA根证书")
            self._install_ca_certificate(ca_cert)
            
            # 5. 安装服务器证书
            pfx_data = config.get('pfx_data')
            if not pfx_data:
                raise ValueError("配置中缺少PFX证书数据")
            thumbprint = self._install_server_certificate(
                config.get('server_cert', ''), 
                config.get('server_key', ''), 
                pfx_data
            )
            
            # 6. 配置WinRM HTTPS监听器
            self._configure_winrm_https(thumbprint)
            
            # 7. 配置防火墙规则
            self._configure_firewall()
            
            # 8. 向C端报告完成
            self._report_completion_to_c_side(thumbprint)
            
            print("=" * 60)
            print("ZASCA H端初始化完成！")
            print("✓ WinRM服务已配置在端口 5986")
            print(f"✓ 证书指纹: {thumbprint}")
            print("✓ H端现在处于ZeroAgent状态，等待C端连接")
            print("=" * 60)
            
            # 自毁脚本
            self._self_destruct()
            
        except Exception as e:
            print(f"❌ 初始化失败: {e}")
            raise
    
    def _self_destruct(self):
        """自毁脚本文件"""
        try:
            script_path = os.path.abspath(__file__)
            if os.path.exists(script_path):
                os.remove(script_path)
                print("✓ 初始化脚本已自毁")
            else:
                print("⚠ 初始化脚本文件不存在，无需删除")
        except Exception as e:
            print(f"⚠ 删除初始化脚本时出错: {e}")
            print("  请手动删除脚本文件以确保ZeroAgent状态")


def main():
    parser = argparse.ArgumentParser(description='ZASCA H端初始化脚本')
    parser.add_argument('secret', help='从C端获取的加密secret字符串')
    parser.add_argument('--dry-run', action='store_true', help='仅显示将要执行的操作，不实际执行')
    
    args = parser.parse_args()
    
    if os.getenv('ZASCA_DEMO', '').lower() == '1':
        print("错误: 此脚本不能在DEMO模式下运行")
        sys.exit(1)
    
    if not args.secret:
        print("错误: 必须提供secret参数")
        parser.print_help()
        sys.exit(1)
    
    if args.dry_run:
        print("Dry run模式: 将显示操作步骤但不会实际执行")
        # 在dry run模式下，我们不实际执行任何操作
        initializer = HSideInitializer(args.secret)
        print(f"主机名: {initializer.hostname}")
        print(f"IP地址: {initializer.ip_address}")
        print(f"C端地址: {initializer.c_side_url}")
        print("此模式下将执行以下操作:")
        print("1. 验证运行环境")
        print("2. 从C端获取配置")
        print("3. 启用WinRM服务")
        print("4. 安装CA根证书")
        print("5. 安装服务器证书")
        print("6. 配置WinRM HTTPS监听器")
        print("7. 配置防火墙规则")
        print("8. 向C端报告完成")
        print("9. 自毁脚本")
        return
    
    try:
        initializer = HSideInitializer(args.secret)
        initializer.initialize()
    except Exception as e:
        print(f"初始化过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()