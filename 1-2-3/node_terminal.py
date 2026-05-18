import socket
import os
import time

# 从统一重构后的工具库导入国密安全套件
try:
    from sm_utils import SMCryptoProvider
except ImportError:
    print("❌ 错误: 找不到 sm_utils.py 文件，请确保将其与当前脚本放在同一目录下。")
    exit(1)


def notify_monitor(node_id, message):
    """异步向大屏监控中心发送运行日志"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except Exception:
        pass  # 即使监控中心未启动，也不影响核心业务的正常执行


def check_and_prepare_assets(img_name="picture.jpg"):
    """【环境自检】若缺失资产则自动补齐，确保课设联调演示 100% 成功"""
    if not os.path.exists(img_name):
        print(f"⚠️  未发现测试图片 {img_name}，正在利用 Pillow 库自动生成基础非遗档案资产...")
        try:
            from PIL import Image, ImageDraw
            # 创建一张 300x300 的蓝色背景测试图
            img = Image.new('RGB', (300, 300), color=(73, 109, 137))
            d = ImageDraw.Draw(img)
            d.text((20, 140), "ICH Digital Archive (gjq)", fill=(255, 255, 255))
            img.save(img_name)
            print(f"✅ 成功自动生成虚拟非遗档案图片: {img_name}")
        except ImportError:
            # 如果没有安装 Pillow 库，则生成一个虚拟的文本二进制流充当资产
            with open(img_name, "wb") as f:
                f.write(b"ICH_Digital_Archive_Binary_Mock_Data_gjq_23072018")
            print(f"✅ 成功生成虚拟二进制非遗档案资产: {img_name}")


def run_terminal():
    print("📸 [1/4] 采集端（Terminal）已启动...")
    img_name = "picture.jpg"

    # 确保运行环境中有资产存在
    check_and_prepare_assets(img_name)

    # 1. 异步通知监控中心大屏
    notify_monitor('A', '📸 正在读取非遗图像数据...')
    with open(img_name, "rb") as f:
        raw_data = f.read()
    print(f"📖 原始档案读取完毕，文件大小: {len(raw_data)} 字节")

    # 2. 实例化国密加解密提供者
    # 它会自动读取或生成全组共享的密钥文件 "feiyi_system.key"
    crypto = SMCryptoProvider()

    # 3. 核心加密改造（融合小组成员 3 的功能）：执行 SM4 CBC 模式加密
    notify_monitor('A', '🔐 正在执行国密 SM4 对称加密...')
    encrypted_data = crypto.sm4_encrypt(raw_data)

    # 4. 完整性校验计算（保持小组成员 1 的功能）：计算密文的 SM3 摘要值
    # 遵循标准的 Encrypted-then-MAC 规范，保护传输过程中的密文安全
    cipher_hash = crypto.sm3_hash(encrypted_data)
    print(f"🧬 [安全锁死] SM4密文生成完毕，长度: {len(encrypted_data)} 字节")
    print(f"🧬 [数字指纹] 密文 SM3 摘要: {cipher_hash[:16]}...")

    # 5. 按照成员 1 约定的网络通信协议进行协议包组装
    # 报文格式：[SM4密文] + [|HASH|占位符] + [密文SM3十六进制字符串] + [END_OF_FILE结束符]
    send_payload = encrypted_data + b"|HASH|" + cipher_hash.encode('utf-8') + b"END_OF_FILE"

    # 6. 建立网络通信，推送至下一级接收点：档案馆（9001 端口）
    notify_monitor('A', '📤 正在向档案馆推送（含国密SM4机密性与SM3完整性双重守卫）...')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)  # 设置 5 秒超时保护
            s.connect(('127.0.0.1', 9001))
            s.sendall(send_payload)

        print("🚀 [传输成功] 加密后的非遗档案数据已安全送达档案馆。")
        notify_monitor('A', '🟢 数据包安全送达档案馆')
    except ConnectionRefusedError:
        print("❌ 传输失败: 档案馆节点（node_archive.py）似乎未启动，请先运行它！")
        notify_monitor('A', '🔴 档案馆连接被拒绝')
    except Exception as e:
        print(f"❌ 网络传输期间发生异常: {e}")
        notify_monitor('A', f'🔴 发送异常: {str(e)[:15]}')


if __name__ == "__main__":
    # 留出 0.5 秒时间让用户看清启动提示
    time.sleep(0.5)
    run_terminal()