import os
import sys
import socket
import json
import time

# ================= 路径自动修复盾（防止 PyCharm 报 ImportError） =================
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
# =========================================================================

try:
    from ich_protocol import ICHPacket
    from sm_utils import SMCryptoProvider, HashChainAudit
    from wm_utils import DWTBlindWatermark  # 新增整合：导入频域水印模块
except ImportError as e:
    print(f"❌ 错误: 引入依赖失败。详情: {e}")
    print(f"📍 当前系统查找路径: {sys.path[:3]}")
    exit(1)

# 实例化统一审计日志、国密安全套件及盲水印组件
audit_logger = HashChainAudit()
crypto = SMCryptoProvider()
wm = DWTBlindWatermark(strength=0.15)  # 新增整合：实例化水印工具


def notify_monitor(node_id, message):
    """异步向大屏监控中心发送运行日志"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except Exception:
        pass


def run_datacenter():
    print("🖥️  [3/4] 数据中心安全存储节点已启动...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 监听 9002 端口（接收来自档案馆转发的跨馆随行包）
    server.bind(('0.0.0.0', 9002))
    server.listen(5)

    notify_monitor('C', '🟢 数据中心存储节点已就绪（国密解密+DWT盲水印复合版）')
    print("⚙️  正在监听 9002 端口，等待档案馆同步安全数据...")

    while True:
        conn, addr = server.accept()
        raw_data = b""

        # 循环接收 TCP 字节流，直到遇到约定的结束符
        while not raw_data.endswith(b"END_OF_FILE"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw_data += chunk

        if not raw_data:
            conn.close()
            continue

        print(f"📥 收到来自档案馆的加密资产包，总计 {len(raw_data)} 字节")

        try:
            # 1. 解码并清理结束符，还原出 JSON 协议字符串
            packet_str = raw_data.replace(b"END_OF_FILE", b"").decode('utf-8')

            # 2. 调用协议层：执行随行完整性校验（防篡改检测）
            print("🔍 正在执行随行完整性校验...")
            is_valid, content_bytes, meta = ICHPacket.verify_and_unpack(packet_str)

            if is_valid:
                # 提取随行包里的密文摘要
                cipher_sm3 = meta.get('sm3_integrity', '')
                print(f"🛡️  SM3 随行校验通过！流转链路完整。密文指纹: {cipher_sm3[:16]}...")
                notify_monitor('C', '🔍 SM3随行校验通过，正在进行 SM4 安全解密...')

                # 3. 核心解密逻辑
                try:
                    print("🔐 正在使用系统通用密钥进行 SM4 块解密与去填充...")
                    decrypted_content = crypto.sm4_decrypt(content_bytes)

                    # 4. 记录不可篡改哈希链审计日志
                    audit_logger.record("数据中心", "RECEIVE_AND_STORE_ICH", cipher_sm3)

                    # 5. 安全持久化落库（先写入解密后的原始图像）
                    save_filename = "center_storage.jpg"
                    with open(save_filename, "wb") as f:
                        f.write(decrypted_content)

                    print(f"💾 [解密成功] 原始档案已还原。")

                    # 6. 新增整合：无缝嵌入 DWT 频域盲水印进行数字版权锁死
                    notify_monitor('C', '🎨 原始图像已还原，正在注入 DWT 频域盲水印...')
                    print("🎨 [安全升级] 正在为落库资产动态注入 DWT 频域隐形追踪水印...")

                    # 模拟读取请求上下文的用户ID（这里以学号和名字标识）
                    current_user_id = "gjq_23072018"

                    # 调用成员2核心算法，原地对 center_storage.jpg 注入盲水印
                    wm.embed(
                        cover_path=save_filename,
                        file_hash=cipher_sm3,
                        user_id=current_user_id,
                        output_path=save_filename
                    )

                    print(f"💾 [解密与水印注入完工] 档案具备追溯力，成功存储为: {save_filename}")
                    notify_monitor('C', '✅ 档案安全解密并加注隐形水印，已安全存储落库')

                except Exception as decrypt_err:
                    print(f"❌ SM4 解密或水印注入失败！数据拒绝入库: {decrypt_err}")
                    notify_monitor('C', '⚠️ 警告：数据处理失败，拒绝入库')
            else:
                print("❌ [严重警告] SM3 随行校验不匹配！数据在流转中遭到篡改。")
                notify_monitor('C', '⚠️ 发现数据篡改告警！')
                audit_logger.record("数据中心", "SECURITY_ALARM_TAMPERED", "VERIFICATION_FAILED")

        except Exception as e:
            print(f"❌ 数据处理期间发生内部异常: {e}")
            notify_monitor('C', f'🔴 数据中心异常: {str(e)[:15]}')

        conn.close()


if __name__ == "__main__":
    run_datacenter()