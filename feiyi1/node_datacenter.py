import socket
import json
import os
import time
from ich_protocol import ICHPacket
from gmssl import sm3


def notify_monitor(node_id, message):
    """将当前节点的状态发送给监控端"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except:
        pass


def write_audit_log(op, data_hash):
    """
    任务 3：实现哈希链审计日志
    逻辑：读取 audit_chain.json，确保 prev_hash 指向上一条记录
    """
    log_file = "audit_chain.json"
    logs = []

    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    # 获取前一环哈希，若为空则初始化
    prev_hash = logs[-1]['current_hash'] if logs else "0" * 64

    entry = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "node": "数据中心",
        "operation": op,
        "payload_sm3": data_hash,
        "prev_hash": prev_hash
    }

    # 计算当前条目的哈希，形成不可篡改链条
    # 使用 sort_keys 确保 JSON 字符串的一致性
    entry_str = json.dumps(entry, sort_keys=True).encode('utf-8')
    current_hash = sm3.sm3_hash(list(entry_str))
    entry['current_hash'] = current_hash

    logs.append(entry)

    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)
    print(f"🔗 [哈希链审计] 记录成功！当前链条长度: {len(logs)}")


def run_datacenter():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9002))
    server.listen(5)

    notify_monitor('C', '🟢 数据中心安全存储服务已就绪')
    print("☁️  [节点 3: 数据中心] 安全校验服务已启动，监听端口: 9002")

    while True:
        conn, addr = server.accept()
        print(f"\n📡 收到来自档案馆 {addr} 的连接")

        raw_data = b""
        try:
            # 循环接收数据直到检测到结束标志
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw_data += chunk
                if b"END_OF_FILE" in raw_data:
                    break

            if not raw_data:
                print("⚠️  收到空数据，跳过处理")
                conn.close()
                continue

            print(f"📥 数据接收完毕，总计 {len(raw_data)} 字节")

            # 1. 解码并清理结束符
            packet_str = raw_data.replace(b"END_OF_FILE", b"").decode('utf-8')

            # 2. 任务 2：执行 SM3 随行校验 (Integrity Check)
            print("🔍 正在执行 SM3 随行完整性校验...")
            is_valid, content, meta = ICHPacket.verify_and_unpack(packet_str)

            if is_valid:
                # 校验通过
                print(f"🛡️  SM3 校验通过！数据完整。指纹: {meta.get('sm3_integrity')[:16]}...")
                notify_monitor('C', '✅ SM3随行校验通过，数据准予入库')

                # 3. 任务 3：记录哈希链审计日志
                write_audit_log("RECEIVE_AND_STORE_ICH", meta.get('sm3_integrity'))

                # 持久化存储
                save_filename = "center_storage.jpg"
                with open(save_filename, "wb") as f:
                    f.write(content)
                print(f"💾 档案已成功入库存储为: {save_filename}")
            else:
                # 校验失败：说明传输过程中发生了篡改
                print("❌ [严重警告] SM3 校验不匹配！数据完整性已被破坏。")
                notify_monitor('C', '⚠️ 发现数据篡改告警！')
                write_audit_log("SECURITY_ALARM_TAMPERED", "VERIFICATION_FAILED")

        except Exception as e:
            print(f"❌ 数据处理过程出错: {e}")
            notify_monitor('C', f'❌ 错误: {str(e)[:20]}')
        finally:
            conn.close()
            print("---------------------------------------------")


if __name__ == "__main__":
    run_datacenter()