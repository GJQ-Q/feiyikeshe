import os
import sys
import socket
import time
import numpy as np
from PIL import Image

# ================= 路径自动修复盾（防止 PyCharm 报 ImportError） =================
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
# =========================================================================

try:
    from wm_utils import DWTBlindWatermark  # 引入整合的水印追溯模块
except ImportError as e:
    print(f"❌ 错误: 找不到 wm_utils.py 模块。详情: {e}")
    exit(1)


def notify_monitor(node_id, message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(f"{node_id}|{message}".encode(), ('127.0.0.1', 9999))
    except:
        pass


def run_robustness_test(file_path):
    """完美补全：复刻成员2原本代码中的鲁棒性测试机制"""
    print("\n💥 开始对该非遗资产进行鲁棒性破坏测试...")
    if not os.path.exists(file_path):
        print("❌ 找不到指定图片")
        return

    wm = DWTBlindWatermark()

    # 1. 提取原始状态
    orig_res = wm.extract(file_path)
    print(f" 🟩 原始未破坏图提取哈希: {orig_res['hash'][:16]}...")

    # 2. 模拟 JPEG 攻击 (压缩质量降到 70%)
    print(" 🛠️ 模拟攻击1：进行 70% 质量的攻击性 JPEG 压缩...")
    img = Image.open(file_path)
    attack_path = "attacked_compressed.jpg"
    img.save(attack_path, "JPEG", quality=70)

    # 3. 再次盲提取
    attack_res = wm.extract(attack_path)
    print(f" 🟨 遭受压缩攻击后提取哈希: {attack_res['hash'][:16]}...")

    # 4. 计算信度比对得分
    score = 0
    for i in range(min(32, len(orig_res['hash']), len(attack_res['hash']))):
        if orig_res['hash'][i] == attack_res['hash'][i]:
            score += 1

    print("\n" + "=" * 50)
    print("📊 鲁棒性攻击对抗测试报告：")
    print("=" * 50)
    print(f"   📐 对抗 JPEG 强压缩匹配度: {score} / 32")
    if score >= 20:
        print("   ✅ 结论：在频域低频分量保护下，算法成功抵御了压缩破坏，仍具备追踪效力！")
    else:
        print("   ⚠️ 结论：破坏程度过大，信息发生失真。")
    print("=" * 50)

    # 清理测试产生的临时破坏图
    if os.path.exists(attack_path):
        os.remove(attack_path)


def run_consumer():
    print("\n" + "=" * 50)
    print("👤 [4/4] 终端调用与追溯消费端已就绪（全功能对齐版）")
    print("=" * 50)
    print(" 1. 正常业务：申请查看中心非遗档案图片")
    print(" 2. 安全合规：对涉嫌泄漏的图片进行离线溯源分析")
    print(" 3. 算法验证：对落库资产进行鲁棒性对抗测试（成员2原版功能）")

    choice = input("\n请选择操作模式 (1/3): ").strip()

    if choice == "1":
        print("\n📥 正在调取中心安全数据存储...")
        if os.path.exists("center_storage.jpg"):
            print("🖼️  成功拿到图片（该图片已被注入 DWT 隐形溯源水印）！正在打开预览...")
            notify_monitor('A', '👤 用户GJQ成功读取非遗档案图片并查看')
            os.startfile("center_storage.jpg")
        else:
            print("❌ 中心还没数据，请确保链路正常流转并已生成 center_storage.jpg。")

    elif choice == "2":
        print("\n🔍 进入非遗数字档案跨馆共享泄露溯源模式...")
        file_path = input("请输入涉嫌泄漏的图片路径 (例如 center_storage.jpg): ").strip()
        if os.path.exists(file_path):
            wm = DWTBlindWatermark()
            print("⏳ 正在从小波变换频域盲提取隐形数字版权指纹...")
            result = wm.trace(file_path)

            print("\n" + "=" * 50)
            print("📋 盲水印流转溯源分析报告：")
            print("=" * 50)
            if result.get("matched"):
                print(f"   ✅ 状态: 成功精准定位泄漏源头与责任人！")
                print(f"   👤 泄漏责任人 ID: {result['user_id']}")
                print(f"   ⏰ 资产分发时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result['timestamp']))}")
                print(f"   📁 原始密文指纹: {result.get('file_hash', '')[:32]}...")
                print(f"   📊 算法信度比对得分: {result.get('match_score', 0)} / 32 (具有高法律效力)")
            else:
                print(f"   ❌ 状态: 无法定位明确责任人")
                print(f"   🔍 盲提取原始标识: {result.get('extracted_hash', 'N/A')[:32]}...")
                print(f"   ⚠️  原因说明: {result.get('error', '未找到匹配记录')}")
            print("=" * 50)
        else:
            print("❌ 错误：指定的涉嫌泄漏图片不存在，请检查路径。")

    elif choice == "3":
        run_robustness_test("center_storage.jpg")
    else:
        print("❌ 无效的选项。")


if __name__ == "__main__":
    run_consumer()