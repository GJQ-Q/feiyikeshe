import socket
import os
import time

# =====================================================
# 国密模块
# =====================================================
try:
    from sm_utils import SMCryptoProvider
except ImportError:
    print("❌ 找不到 sm_utils.py")
    exit(1)

# =====================================================
# 可信采集模块
# =====================================================
try:
    from collection import CollectionTerminal
except ImportError:
    print("❌ 找不到 collection.py")
    exit(1)


# =====================================================
# 通知监控中心
# =====================================================
def notify_monitor(node_id, message):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

            msg = f"{node_id}|{message}"

            s.sendto(msg.encode(), ('127.0.0.1', 9999))

    except Exception:
        pass


# =====================================================
# 自动生成测试图片
# =====================================================
def check_and_prepare_assets(img_name="picture.jpg"):

    if not os.path.exists(img_name):

        print(f"⚠️ 未发现测试图片 {img_name}，正在自动生成...")

        try:

            from PIL import Image, ImageDraw

            img = Image.new(
                'RGB',
                (300, 300),
                color=(73, 109, 137)
            )

            d = ImageDraw.Draw(img)

            d.text(
                (20, 140),
                "ICH Digital Archive",
                fill=(255, 255, 255)
            )

            img.save(img_name)

            print(f"✅ 已自动生成测试图片: {img_name}")

        except ImportError:

            with open(img_name, "wb") as f:

                f.write(b"ICH_TEST_BINARY_DATA")

            print(f"✅ 已自动生成测试文件: {img_name}")


# =====================================================
# 生成可信采集 metadata
# =====================================================
def generate_collection_metadata(file_path):

    print("\n📋 正在生成可信采集凭证...")

    collector = CollectionTerminal()

    # =================================================
    # 自动设备初始化
    # =================================================
    current_device = collector.device_manager.get_current_device()

    if not current_device:

        print("⚠️ 未发现采集设备，自动注册默认设备...")

        device = collector.device_manager.register_device(
            device_name="佳能G12(可信采集终端)",
            device_type="camera"
        )

        collector.device_manager.select_device(
            device.device_id
        )

    # =================================================
    # 自动录入采集员
    # =================================================
    collector.current_collector = {
        'id': 'COLLECTOR_GJQ_001',
        'name': 'gjq',
        'department': '非遗数字化保护中心'
    }

    # =================================================
    # 采集信息
    # =================================================
    collection_info = {
        'location': '非遗数字化采集中心',
        'remarks': '系统自动采集',
        'gps_latitude': None,
        'gps_longitude': None
    }

    # =================================================
    # 生成 metadata
    # =================================================
    success = collector.process_file(
        file_path,
        collection_info
    )

    if success:

        print("✅ 可信采集 metadata 已生成")

    else:

        print("❌ metadata 生成失败")


# =====================================================
# 主流程
# =====================================================
def run_terminal():

    print("\n" + "=" * 60)
    print("📸 [1/4] 可信采集终端已启动")
    print("🔐 当前模式：可信采集 + 国密安全流转")
    print("=" * 60)

    img_name = "picture.jpg"

    # =================================================
    # 自动准备测试图片
    # =================================================
    check_and_prepare_assets(img_name)

    # =================================================
    # 生成可信采集 metadata
    # =================================================
    notify_monitor(
        'A',
        '📋 正在生成可信采集凭证'
    )

    generate_collection_metadata(img_name)

    # =================================================
    # 读取原始图片（保持原系统不变）
    # =================================================
    with open(img_name, "rb") as f:

        raw_data = f.read()

    print(
        f"\n📷 原始图片读取完成，大小: "
        f"{len(raw_data)} 字节"
    )

    # =================================================
    # SM4 加密
    # =================================================
    crypto = SMCryptoProvider()

    notify_monitor(
        'A',
        '🔐 正在执行 SM4 国密加密'
    )

    encrypted_data = crypto.sm4_encrypt(raw_data)

    print("🔒 SM4 加密完成")

    # =================================================
    # SM3 摘要
    # =================================================
    cipher_hash = crypto.sm3_hash(
        encrypted_data
    )

    print(
        f"🧬 SM3 密文摘要: "
        f"{cipher_hash[:32]}..."
    )

    # =================================================
    # 原协议封装（完全兼容旧系统）
    # =================================================
    send_payload = (
        encrypted_data +
        b"|HASH|" +
        cipher_hash.encode('utf-8') +
        b"END_OF_FILE"
    )

    # =================================================
    # 发送到档案馆
    # =================================================
    notify_monitor(
        'A',
        '📤 正在向档案馆发送安全档案'
    )

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as s:

            s.settimeout(5.0)

            s.connect(('127.0.0.1', 9001))

            s.sendall(send_payload)

        print("\n🚀 安全档案已成功送达档案馆")

        notify_monitor(
            'A',
            '🟢 档案已送达档案馆'
        )

    except ConnectionRefusedError:

        print("\n❌ 档案馆节点未启动")

        notify_monitor(
            'A',
            '🔴 档案馆连接失败'
        )

    except Exception as e:

        print(f"\n❌ 网络异常: {e}")

        notify_monitor(
            'A',
            f'🔴 网络异常: {str(e)[:15]}'
        )


# =====================================================
# 程序入口
# =====================================================
if __name__ == "__main__":

    time.sleep(0.5)

    run_terminal()