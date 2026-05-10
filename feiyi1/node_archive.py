import socket
import time
import json
import os
from ich_protocol import ICHPacket
from gmssl import sm3


def notify_monitor(node_id, message):
    """将当前节点的状态发送给监控端，修复了引号转义报错"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 修正后的字符串拼接方式
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except:
        pass


def write_audit_log(op, data_hash):
    """
    任务 3：实现哈希链审计日志
    逻辑：每一条日志的 current_hash 都依赖于上一条的 hash
    """
    log_file = "audit_chain.json"
    logs = []

    # 读取现有日志
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except:
            logs = []

    # 获取前一环哈希，若为首条则用初始值
    prev_hash = logs[-1]['current_hash'] if logs else "0" * 64

    # 构造日志条目
    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "node": "档案馆",
        "operation": op,
        "payload_sm3": data_hash,
        "prev_hash": prev_hash
    }

    # 计算当前条目的哈希（形成链条）
    # 使用 sort_keys=True 保证 JSON 序列化顺序一致，防止哈希失效
    entry_str = json.dumps(entry, sort_keys=True).encode('utf-8')
    current_hash = sm3.sm3_hash(list(entry_str))
    entry['current_hash'] = current_hash

    logs.append(entry)

    # 持久化存储
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)
    print(f"📊 [审计] 哈希链更新成功。当前位置: {len(logs)}, 摘要末尾: {current_hash[-8:]}")


def run_archive():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9001))
    server.listen(5)

    notify_monitor('B', '🟢 档案馆审核节点已就绪（SM3安全增强版）')
    print("🏛️  [节点 2: 档案馆] 已启动，正在监听 9001 端口...")

    while True:
        conn, addr = server.accept()
        print(f"📩 收到来自 {addr} 的连接")

        raw_data = b""
        while not raw_data.endswith(b"END_OF_FILE"):
            chunk = conn.recv(4096)
            if not chunk: break
            raw_data += chunk

        # 1. 拆解采集端数据
        # 约定：采集端发送格式为 [原始数据]|HASH|[原始数据的SM3]END_OF_FILE
        clean_data = raw_data.replace(b"END_OF_FILE", b"")

        try:
            if b"|HASH|" in clean_data:
                # 链路 A -> B 的校验
                payload, terminal_hash = clean_data.split(b"|HASH|")
                calc_hash = sm3.sm3_hash(list(payload))

                if calc_hash != terminal_hash.decode():
                    notify_monitor('B', '⚠️ 警告：采集端传输过程发现篡改！')
                    print("❌ [校验失败] 原始数据在传输至档案馆过程中被修改。")
                    conn.close()
                    continue
                print("✅ [校验成功] 采集端 -> 档案馆 完整性核验通过")
            else:
                # 如果没有 HASH 标记，视为旧版协议，直接处理
                payload = clean_data
                print("⚠️ [提示] 收到未标记哈希的数据，按兼容模式处理")

            # 2. 模拟内部审核逻辑
            notify_monitor('B', '📝 审核通过，正在进行SM3随行封装...')
            time.sleep(1)

            # 3. 任务 2：实现跨馆传输的 SM3 随行校验打包
            # 这一步会将 payload 封装进 ICHProtocol，并自动在 metadata 里生成新的 SM3 摘要
            meta = {
                "source": "First_Archive",
                "timestamp": time.time(),
                "type": "ICH_Archive_File"
            }
            # 调用封装好的协议层
            secure_packet = ICHPacket.create(payload, meta)

            # 4. 任务 3：记录哈希链审计日志
            # 记录“转发”这一操作，并将数据的哈希锁死在审计链中
            write_audit_log("VERIFY_AND_FORWARD", sm3.sm3_hash(list(payload)))

            # 5. 转发给数据中心 (9002 端口)
            try:
                with socket.socket() as client_s:
                    client_s.connect(('127.0.0.1', 9002))
                    # 按照数据中心要求，发送打包后的字符串并带上结束符
                    client_s.sendall(secure_packet.encode('utf-8') + b"END_OF_FILE")
                notify_monitor('B', '📤 档案已安全同步至中心')
                print("🚀 [转发成功] 数据已发送至中心节点")
            except Exception as e:
                notify_monitor('B', '❌ 无法连接数据中心')
                print(f"❌ 转发失败: {e}")

        except Exception as e:
            print(f"❌ 节点处理异常: {e}")
            notify_monitor('B', '❌ 内部逻辑错误')

        conn.close()


if __name__ == "__main__":
    run_archive()