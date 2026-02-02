#!/usr/bin/env python3
"""
ZASCA H端初始化脚本
根据技术契约规范，H端负责解析配置、计算TOTP、发起网络请求、处理Token生命周期
"""

import sys
import os
import json
import base64
import argparse
import hashlib
import hmac
import pyotp
import requests
import socket
import time


class HSideInitializer:
    def __init__(self, secret):
        self.secret = secret
        self.decoded_secret = self._decode_secret(secret)
        self.c_side_url = self.decoded_secret.get('c_side_url')
        self.token = self.decoded_secret.get('token')
        self.host_id = self.decoded_secret.get('host_id')
        self.expires_at = self.decoded_secret.get('expires_at')
        self.hostname = socket.gethostname()
        self.ip_address = self._get_local_ip()
        
    def _decode_secret(self, secret):
        """
        解码从C端获取的secret
        secret格式: base64(json({c_side_url: "...", token: "...", host_id: "...", expires_at: "..."}))
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
    
    def _derive_totp_key(self):
        """
        根据技术契约规范计算TOTP密钥
        1. 拼接字符串: input_string = token + "|" + host_id + "|" + expires_at
        2. 哈希计算: raw_hash = HMAC-SHA256(key="SHARED_STATIC_SALT", message=input_string)
        3. 截取与编码: 取raw_hash的前20个字节，进行Base32编码
        """
        SHARED_STATIC_SALT = "MY_SECRET_2024"  # 与C端约定的共享盐值
        
        input_string = f"{self.token}|{self.host_id}|{self.expires_at}"
        raw_hash = hmac.new(
            key=SHARED_STATIC_SALT.encode('utf-8'),
            msg=input_string.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        
        # 取前20个字节并进行Base32编码
        truncated_hash = raw_hash[:20]
        k_totp = base64.b32encode(truncated_hash).decode('utf-8')
        
        return k_totp
    
    def _generate_and_display_totp(self):
        """生成并显示TOTP码供用户输入到C端"""
        k_totp = self._derive_totp_key()
        
        # 创建TOTP实例，使用技术契约中规定的参数
        totp = pyotp.TOTP(
            k_totp,
            digits=6,           # 6位数字
            interval=30         # 30秒时间步长
        )
        
        # 获取当前TOTP码
        current_code = totp.now()
        
        print("=" * 60)
        print("ZASCA H端初始化 - TOTP验证阶段")
        print(f"主机ID: {self.host_id}")
        print(f"主机名: {self.hostname}")
        print(f"IP地址: {self.ip_address}")
        print("=" * 60)
        print(f"请访问 C 端管理后台，输入主机 ID [{self.host_id}] 和验证码 [{current_code}] 进行激活")
        print("激活完成后按回车键继续...")
        
        # 显示当前码的有效剩余时间
        time_remaining = 30 - (int(time.time()) % 30)
        print(f"当前验证码剩余有效时间: {time_remaining}秒")
        
        # 等待用户确认
        input()
        
        return current_code
    
    def _exchange_token(self):
        """向C端发起token交换请求"""
        print("正在向C端发起token交换请求...")
        
        url = f"{self.c_side_url}/api/exchange_token"
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response = requests.post(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    session_token = result.get('session_token')
                    expires_in = result.get('expires_in')
                    
                    print("✓ Token交换成功!")
                    print(f"  会话令牌: {session_token}")
                    print(f"  有效期: {expires_in}秒")
                    
                    # 保存session token到本地配置
                    self._save_session_token(session_token)
                    
                    return session_token
                
                elif response.status_code == 400:
                    error_msg = response.text
                    if "Wait To Active" in error_msg:
                        print("⚠ 状态: 等待激活，请确认已在C端完成TOTP验证")
                        time.sleep(5)  # 等待5秒后重试
                        retry_count += 1
                        continue
                    else:
                        print(f"❌ 请求错误 (400): {error_msg}")
                        break
                
                elif response.status_code == 403:
                    print("❌ 访问被拒绝 (403): 请检查TOTP是否输入正确，或Base64是否有效")
                    break
                
                else:
                    print(f"❌ 请求失败，状态码: {response.status_code}")
                    print(f"  响应: {response.text}")
                    break
                    
            except requests.exceptions.Timeout:
                print(f"⚠ 请求超时，正在进行第 {retry_count + 1} 次重试...")
                retry_count += 1
                time.sleep(5)
                
            except requests.exceptions.RequestException as e:
                print(f"⚠ 网络请求错误: {e}")
                break
        
        if retry_count >= max_retries:
            print("❌ 已达到最大重试次数，Token交换失败")
            
        raise RuntimeError("Token交换失败")
    
    def _save_session_token(self, session_token):
        """保存session token到本地配置"""
        config = {
            'session_token': session_token,
            'host_id': self.host_id,
            'c_side_url': self.c_side_url,
            'ip_address': self.ip_address
        }
        
        # 保存到本地配置文件
        config_path = 'h_side_config.json'
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"✓ 会话令牌已保存到本地配置文件: {config_path}")
    
    def _activate_with_totp(self):
        """执行TOTP激活流程"""
        # 1. 生成并显示TOTP码
        totp_code = self._generate_and_display_totp()
        
        # 2. 向C端发起token交换请求
        session_token = self._exchange_token()
        
        print("=" * 60)
        print("ZASCA H端初始化完成！")
        print(f"✓ H端已激活，会话令牌: {session_token}")
        print("✓ H端现在处于ZeroAgent状态，等待C端连接")
        print("=" * 60)
        
        return session_token
    
    def initialize(self):
        """执行完整的初始化流程"""
        print("开始ZASCA H端初始化流程...")
        
        try:
            # 执行TOTP激活流程
            session_token = self._activate_with_totp()
            
            # 自毁脚本（如果需要）
            # self._self_destruct()
            
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
        initializer = HSideInitializer(args.secret)
        print(f"主机名: {initializer.hostname}")
        print(f"IP地址: {initializer.ip_address}")
        print(f"C端地址: {initializer.c_side_url}")
        print(f"主机ID: {initializer.host_id}")
        print(f"过期时间: {initializer.expires_at}")
        print("此模式下将执行以下操作:")
        print("1. 计算TOTP密钥")
        print("2. 生成并显示TOTP码")
        print("3. 向C端发起token交换请求")
        print("4. 保存会话令牌")
        return
    
    try:
        initializer = HSideInitializer(args.secret)
        initializer.initialize()
    except Exception as e:
        print(f"初始化过程中发生错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()