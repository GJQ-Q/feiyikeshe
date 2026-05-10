import socket
import os
import time
from gmssl import sm3

def notify_monitor(node_id, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            msg = f"{node_id}|{message}"
            s.sendto(msg.encode(), ('127.0.0.1', 9999))
    except:
        pass

def run_terminal():
    img_name = "picture.jpg"
    if not os.path.exists(img_name):
        print(f"❌ 找不到图片 {img_name}")
        return

    notify_monitor('A', '📸 正在读取非遗图像数据...')
    with open(img_name, "rb") as f:
        data = f.read()

    # --- 任务：实现采集端 SM3 摘要计算 ---
    data_hash = sm3.sm3_hash(list(data))
    print(f"🧬 [采集端] 生成原始指纹: {data_hash[:16]}...")

    # 发送：原始数据 + 分隔符 + 哈希值 + 结束符
    # 这样档案馆就能拆分出来进行核对
    send_payload = data + b"|HASH|" + data_hash.encode() + b"END_OF_FILE"

    notify_monitor('A', '📤 正在向档案馆推送（含完整性校验）...')
    try:
        with socket.socket() as s:
            s.connect(('127.0.0.1', 9001))
            s.sendall(send_payload)
        print("🚀 数据已送达档案馆。")
    except Exception as e:
        print(f"❌ 发送失败: {e}")

if __name__ == "__main__":
    run_terminal()