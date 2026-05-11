"""
非遗数字档案跨馆共享安全系统
集成任务一、二、三
"""

import os
import time
import json
from crypto_utils import SM_CryptoTool, get_system_key
from watermark import DWTBlindWatermark


class NonHeritageSecuritySystem:
    """
    非遗档案安全系统（完整集成）
    """

    def __init__(self):
        # 初始化国密工具（任务三）
        self.key = get_system_key()
        self.crypto = SM_CryptoTool(self.key)

        # 初始化水印工具（任务二）
        self.watermark = DWTBlindWatermark()

    def archive_encrypt_and_send(self, file_path: str, dest_center: str = "数据中心"):
        """
        档案馆端：加密 + 发送（任务三）

        :param file_path: 原始档案文件路径
        :return: 加密文件路径和摘要
        """
        print(f"\n{'=' * 50}")
        print(f"[档案馆] 准备发送档案: {file_path}")
        print(f"[档案馆] 目标: {dest_center}")

        # 1. 读取原始文件
        with open(file_path, 'rb') as f:
            raw_data = f.read()

        # 2. 计算 SM3 摘要
        file_hash = self.crypto.sm3_hash(raw_data)

        # 3. SM4 加密
        encrypted_data = self.crypto.sm4_encrypt(raw_data)

        # 4. 保存加密文件
        enc_path = file_path + ".enc"
        with open(enc_path, 'wb') as f:
            f.write(encrypted_data)

        # 5. 记录元数据
        metadata = {
            "file_hash": file_hash,
            "original_name": os.path.basename(file_path),
            "encrypted_path": enc_path,
            "timestamp": int(time.time())
        }
        with open(enc_path + ".meta", 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        print(f"[✓] 加密完成")
        print(f"    - 摘要: {file_hash[:32]}...")
        print(f"    - 加密文件: {enc_path}")

        return enc_path, file_hash, metadata

    def data_center_receive_and_distribute(
            self,
            enc_file_path: str,
            user_id: str,
            need_watermark: bool = True
    ):
        """
        数据中心端：接收解密 + 分发（带水印）

        :param enc_file_path: 接收到的加密文件路径
        :param user_id: 申请用户ID
        :param need_watermark: 是否需要嵌入盲水印
        :return: 分发文件路径
        """
        print(f"\n{'=' * 50}")
        print(f"[数据中心] 接收加密档案: {enc_file_path}")

        # 1. 读取加密文件
        with open(enc_file_path, 'rb') as f:
            encrypted_data = f.read()

        # 2. 解密
        decrypted_data = self.crypto.sm4_decrypt(encrypted_data)

        # 3. 计算摘要并校验
        decrypted_hash = self.crypto.sm3_hash(decrypted_data)

        # 读取元数据
        meta_path = enc_file_path + ".meta"
        if os.path.exists(meta_path):
            with open(meta_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            original_hash = metadata.get("file_hash", "")

            if decrypted_hash == original_hash:
                print(f"[✓] 完整性校验通过")
            else:
                print(f"[✗] 警告：文件完整性校验失败！")
                print(f"    期望: {original_hash[:32]}...")
                print(f"    实际: {decrypted_hash[:32]}...")

        # 4. 保存解密后的原始文件
        temp_file = enc_file_path.replace(".enc", "_decrypted")
        with open(temp_file, 'wb') as f:
            f.write(decrypted_data)

        # 5. 判断文件类型（简单判断是否为图片）
        is_image = temp_file.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff'))

        if need_watermark and is_image:
            # 嵌入盲水印（任务二）
            print(f"\n[数据中心] 检测到图片文件，嵌入盲水印...")
            watermarked_file = self.watermark.embed(
                cover_path=temp_file,
                file_hash=decrypted_hash,
                user_id=user_id,
                timestamp=int(time.time())
            )
            result_file = watermarked_file
        else:
            # 非图片文件，直接分发
            result_file = temp_file
            if need_watermark:
                print(f"[!] 非图片格式，跳过水印嵌入（仅对图片/视频生效）")

        print(f"\n[✓] 分发完成")
        print(f"    - 用户: {user_id}")
        print(f"    - 文件: {result_file}")

        return result_file, decrypted_hash

    def trace_leak(self, leaked_file_path: str) -> dict:
        """
        泄露溯源：提取盲水印 + 定位责任人（任务二）

        :param leaked_file_path: 泄露的文件路径
        :return: 溯源结果
        """
        print(f"\n{'=' * 50}")
        print(f"[溯源系统] 分析泄露文件: {leaked_file_path}")

        # 1. 检查是否为图片
        if not leaked_file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
            print("[✗] 不支持的文件类型（仅支持图片溯源）")
            return {"success": False, "error": "文件类型不支持"}

        # 2. 提取盲水印
        try:
            extracted = self.watermark.extract(leaked_file_path)

            print(f"\n[✅ 溯源成功]")
            print(f"    - 责任人标识: {extracted.get('extracted_hash', '未知')[:32]}...")
            print(f"    - 建议: 比对数据库中的分发记录")

            return {
                "success": True,
                "extracted_info": extracted
            }
        except Exception as e:
            print(f"[✗] 水印提取失败: {e}")
            return {"success": False, "error": str(e)}

    def full_demo(self):
        """
        完整业务流程演示
        """
        print("\n" + "=" * 60)
        print("非遗数字档案跨馆共享安全系统 - 完整演示")
        print("=" * 60)

        # 创建测试文件
        test_file = "demo_heritage.jpg"
        if not os.path.exists(test_file):
            import cv2
            import numpy as np
            img = np.ones((400, 600, 3), dtype=np.uint8) * 240
            cv2.putText(img, "非遗珍贵档案 - 传统技艺", (50, 200),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
            cv2.imwrite(test_file, img)
            print(f"创建测试档案: {test_file}")

        # 步骤1：档案馆加密发送
        enc_file, file_hash, _ = self.archive_encrypt_and_send(test_file)

        # 步骤2：数据中心接收并分发（带水印）
        distributed_file, _ = self.data_center_receive_and_distribute(
            enc_file_path=enc_file,
            user_id="researcher_zhang"
        )

        # 步骤3：模拟泄露（研究人员无意中分享出去）
        print(f"\n{'=' * 50}")
        print("[模拟] 研究人员将文件泄露到外部...")
        time.sleep(1)

        # 步骤4：泄露溯源
        result = self.trace_leak(distributed_file)

        # 输出总结
        print(f"\n{'=' * 60}")
        print("演示完成总结：")
        print(f"  ✓ 文件指纹 (SM3): {file_hash[:32]}...")
        print(f"  ✓ 传输加密 (SM4): 已启用")
        print(f"  ✓ 盲水印溯源: {'成功' if result['success'] else '失败'}")
        print("=" * 60)


def main():
    system = NonHeritageSecuritySystem()

    print("\n请选择操作模式：")
    print("1. 完整演示（推荐）")
    print("2. 单独测试 - 档案馆加密")
    print("3. 单独测试 - 数据中心分发（嵌入水印）")
    print("4. 单独测试 - 泄露溯源")

    choice = input("\n请输入选项 (1-4): ").strip()

    if choice == "1":
        system.full_demo()

    elif choice == "2":
        file_path = input("请输入待加密文件路径: ").strip()
        if os.path.exists(file_path):
            system.archive_encrypt_and_send(file_path)
        else:
            print("文件不存在！")

    elif choice == "3":
        enc_file = input("请输入加密文件路径 (.enc): ").strip()
        user_id = input("请输入用户ID: ").strip()
        if os.path.exists(enc_file):
            system.data_center_receive_and_distribute(enc_file, user_id)
        else:
            print("文件不存在！")

    elif choice == "4":
        leaked_file = input("请输入疑似泄露文件路径: ").strip()
        if os.path.exists(leaked_file):
            system.trace_leak(leaked_file)
        else:
            print("文件不存在！")

    else:
        print("无效选项，运行默认演示...")
        system.full_demo()


if __name__ == "__main__":
    main()