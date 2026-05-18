import os
import socket

def notify_monitor(node_id, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(f"{node_id}|{message}".encode(), ('127.0.0.1', 9999))
    except:
        pass # 监控没开也不影响业务运行
def run_consumer():
    print("👤 [4/4] 调用端：检查中心数据...")
    if os.path.exists("center_storage.jpg"):
        print("🖼️ 成功拿到图片！正在打开预览...")
        os.startfile("center_storage.jpg") # 自动打开图片
    else:
        print("❌ 中心还没数据。")

if __name__ == "__main__": run_consumer()