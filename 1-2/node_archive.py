import socket
import time
import json
import os

# 引入统一重构后的工具库和随行协议
try:
    from ich_protocol import ICHPacket
    from sm_utils import SMCryptoProvider, HashChainAudit
except ImportError:
    print("❌ 错误: 找不到 ich_protocol.py 或 sm_utils.py，请检查当前目录。")
    exit(1)

# 实例化统一审计日志和国密安全套件
audit_logger = HashChainAudit()
crypto = SMCryptoProvider()


def notify_monitor(node_id, message):
    """异步向大屏监控中心发送运行日志"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except Exception:
        pass


def run_archive():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 监听 9001 端口（接收来自采集端的数据）
    server.bind(('0.0.0.0', 9001))
    server.listen(5)

    notify_monitor('B', '🟢 档案馆审核节点已就绪（SM3+SM4安全增强版）')
    print("🏛️  [节点 2: 档案馆] 已启动，正在监听 9001 端口...")

    while True:
        conn, addr = server.accept()
        raw_data = b""

        # 循环接收来自采集端的数据
        while not raw_data.endswith(b"END_OF_FILE"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw_data += chunk

        if not raw_data:
            conn.close()
            continue

        clean_data = raw_data.replace(b"END_OF_FILE", b"")

        try:
            # 1. 解包校验（采集端 -> 档案馆）
            if b"|HASH|" in clean_data:
                payload, terminal_hash = clean_data.split(b"|HASH|")
                calc_hash = crypto.sm3_hash(payload)

                if calc_hash != terminal_hash.decode('utf-8', errors='ignore'):
                    print("⚠️  [警告] 采集端传输过程数据指纹不匹配，可能遭到篡改！")
                    notify_monitor('B', '⚠️ 警告：采集端传输过程发现篡改！')
                    conn.close()
                    continue
                print("✅ [校验成功] 采集端 -> 档案馆 密文完整性核验通过")
            else:
                payload = clean_data
                print("⚠️ [提示] 收到未标记哈希的数据，按兼容模式处理")

            # 2. 模拟内部审核逻辑
            notify_monitor('B', '📝 审核通过，正在进行国密随行封装...')
            time.sleep(0.5)

            # 3. 跨馆传输的 SM3 随行校验打包（包裹内是安全受保护的 SM4 密文）
            meta = {
                "source": "First_Archive",
                "timestamp": time.time(),
                "type": "ICH_Archive_File"
            }
            secure_packet = ICHPacket.create(payload, meta)

            # 4. 记录统一哈希链审计日志
            # 注意：在向数据中心转发前，必须将密文摘要牢牢锁死在本地审计链中
            cipher_sm3 = crypto.sm3_hash(payload)
            audit_logger.record("档案馆", "VERIFY_AND_FORWARD", cipher_sm3)

            # 5. 转发给数据中心 (9002 端口)
            print("📤 正在安全同步至数据中心...")
            try:
                # 增加 with 块及超时保护，防止网络死锁
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_s:
                    client_s.settimeout(3.0)  # 设置 3 秒超时限制
                    client_s.connect(('127.0.0.1', 9002))

                    # 发送完整的 JSON 包数据
                    packet_bytes = secure_packet.encode('utf-8') + b"END_OF_FILE"
                    client_s.sendall(packet_bytes)

                    # 显式安全关闭输出流，向对端发送 FIN 信号，强制让对方跳出循环
                    client_s.shutdown(socket.SHUT_WR)

                print("🚀 [同步成功] 档案密文已安全转发至数据中心。")
                notify_monitor('B', '📤 档案密文已安全同步至中心')
            except (socket.timeout, ConnectionRefusedError):
                print("❌ 转发失败: 无法连接到数据中心（9002），请确保 node_datacenter.py 已经运行！")
                notify_monitor('B', '❌ 无法连接数据中心，转发中断')
            except Exception as forward_err:
                print(f"❌ 转发网络异常: {forward_err}")
                notify_monitor('B', f'❌ 转发异常: {str(forward_err)[:15]}')

        except Exception as e:
            print(f"❌ 档案馆处理业务异常: {e}")
            notify_monitor('B', '❌ 内部逻辑错误')

        # 处理完当前请求，必须显式断开与采集端的连接
        conn.close()
        print("--------------------------------------------------")


if __name__ == "__main__":
    run_archive()