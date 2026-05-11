"""
任务二：DWT频域盲水印模块 - 非遗档案溯源系统
功能：
1. DWT频域嵌入水印（分发前调用）- 抗裁剪、抗压缩
2. DWT频域提取水印与比对（泄露溯源）
"""

import hashlib
import time
import json
import os
import numpy as np
import pywt
from PIL import Image, ImageDraw


class DWTBlindWatermark:
    """
    基于DWT频域的盲水印算法
    水印嵌入在图像频域，抗裁剪、抗JPEG压缩
    """

    def __init__(self, strength=0.1, embed_size=32):
        """
        初始化
        :param strength: 水印强度 (0.05-0.2)
        :param embed_size: 嵌入区域大小 (32x32 可嵌入 1024 bits)
        """
        self.strength = strength
        self.embed_size = embed_size
        print(f"[初始化] DWT频域盲水印工具")
        print(f"    - 强度: {strength}")
        print(f"    - 嵌入区域: {embed_size}x{embed_size}")

    def _text_to_bits(self, text: str, target_len: int = 256) -> list:
        """
        将文本转为比特序列
        """
        # 计算 SHA256
        hash_bytes = hashlib.sha256(text.encode()).digest()

        # 转为比特
        bits = []
        for b in hash_bytes:
            for j in range(7, -1, -1):
                bits.append((b >> j) & 1)

        # 截取或填充到目标长度
        if len(bits) > target_len:
            bits = bits[:target_len]
        else:
            # 重复填充
            original = bits.copy()
            while len(bits) < target_len:
                bits.extend(original[:min(len(original), target_len - len(bits))])

        return bits

    def _bits_to_hex(self, bits: list) -> str:
        """
        将比特序列转为十六进制
        """
        # 补齐到8的倍数
        while len(bits) % 8 != 0:
            bits.append(0)

        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val |= (bits[i + j] << (7 - j))
            byte_array.append(byte_val)

        return byte_array.hex()

    def _embed_bits_to_coeffs(self, coeffs, bits):
        """
        将比特嵌入到 DWT 系数中
        """
        cA, (cH, cV, cD) = coeffs
        h, w = cA.shape

        # 只使用左上角 embed_size x embed_size 区域
        embed_h = min(h, self.embed_size)
        embed_w = min(w, self.embed_size)

        idx = 0
        for i in range(embed_h):
            for j in range(embed_w):
                if idx >= len(bits):
                    break
                # 修改系数值（强度调制）
                if bits[idx] == 1:
                    cA[i, j] += self.strength * abs(cA[i, j])
                else:
                    cA[i, j] -= self.strength * abs(cA[i, j])
                idx += 1
            if idx >= len(bits):
                break

        return (cA, (cH, cV, cD))

    def _extract_bits_from_coeffs(self, coeffs, original_coeffs=None):
        """
        从 DWT 系数中提取比特
        如果有原始系数，使用差分提取；否则使用阈值提取
        """
        cA, _ = coeffs
        h, w = cA.shape

        embed_h = min(h, self.embed_size)
        embed_w = min(w, self.embed_size)

        if original_coeffs is not None:
            # 差分提取（更准确，需要知道原始图像）
            orig_cA, _ = original_coeffs
            bits = []
            for i in range(embed_h):
                for j in range(embed_w):
                    if len(bits) >= 256:
                        break
                    diff = cA[i, j] - orig_cA[i, j]
                    bits.append(1 if diff > 0 else 0)
                if len(bits) >= 256:
                    break
        else:
            # 盲提取（不需要原图，使用局部均值作为阈值）
            embed_region = cA[:embed_h, :embed_w]
            threshold = np.mean(embed_region)

            bits = []
            for i in range(embed_h):
                for j in range(embed_w):
                    if len(bits) >= 256:
                        break
                    bits.append(1 if cA[i, j] > threshold else 0)
                if len(bits) >= 256:
                    break

        return bits

    def embed(self, cover_path: str, file_hash: str, user_id: str,
              timestamp: int = None, output_path: str = None) -> str:
        """
        在频域嵌入水印（分发前调用）

        :param cover_path: 原始图片路径
        :param file_hash: 文件SM3摘要
        :param user_id: 用户ID
        :param timestamp: 时间戳
        :param output_path: 输出路径
        :return: 输出路径
        """
        if timestamp is None:
            timestamp = int(time.time())

        if output_path is None:
            base, ext = os.path.splitext(cover_path)
            output_path = f"{base}_dwt_wm{ext}"

        # 构建水印信息
        watermark_str = f"{file_hash[:16]}|{user_id[:10]}|{timestamp}"
        bits = self._text_to_bits(watermark_str, 256)

        print(f"\n[嵌入] DWT频域盲水印")
        print(f"    - 原始文件: {cover_path}")
        print(f"    - 用户ID: {user_id}")
        print(f"    - 水印信息: {watermark_str}")
        print(f"    - 比特数: {len(bits)}")

        # 读取图片并转换为 YCbCr
        img = Image.open(cover_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')

        # 转为 YCbCr，在 Y 通道嵌入（鲁棒性最好）
        img_ycbcr = img.convert('YCbCr')
        ycbcr_array = np.array(img_ycbcr, dtype=np.float32)
        y_channel = ycbcr_array[:, :, 0]

        # 保存原始 Y 通道（用于后续差分提取）
        original_y = y_channel.copy()

        # DWT 变换
        coeffs = pywt.dwt2(y_channel, 'haar')

        # 嵌入水印到系数
        new_coeffs = self._embed_bits_to_coeffs(coeffs, bits)

        # 逆 DWT
        new_y = pywt.idwt2(new_coeffs, 'haar')
        new_y = np.clip(new_y, 0, 255).astype(np.uint8)

        # 更新 Y 通道
        ycbcr_array[:, :, 0] = new_y

        # 转回 RGB
        result_ycbcr = Image.fromarray(ycbcr_array.astype(np.uint8), 'YCbCr')
        result_rgb = result_ycbcr.convert('RGB')
        result_rgb.save(output_path, quality=95)

        # 保存日志（用于溯源）
        log_entry = {
            "watermark_str": watermark_str,
            "watermark_hash": hashlib.sha256(watermark_str.encode()).hexdigest(),
            "file_hash": file_hash,
            "user_id": user_id,
            "timestamp": timestamp,
            "output_path": output_path,
            "embed_size": self.embed_size,
            "strength": self.strength
        }
        self._save_log(log_entry)

        # 可选：保存原始 Y 通道用于精确提取（不必须，盲提取不需要）
        # np.save(output_path + ".original_y.npy", original_y)

        print(f"[✓] DWT水印嵌入成功！")
        print(f"    - 输出: {output_path}")
        print(f"    - 水印哈希: {log_entry['watermark_hash'][:16]}...")

        return output_path

    def extract(self, img_path: str, original_y_path: str = None, verbose: bool = True) -> dict:
        """
        从频域提取水印（泄露溯源时调用）

        :param img_path: 待检测图片路径
        :param original_y_path: 原始Y通道文件（可选，用于更精确提取）
        :param verbose: 是否打印详细信息
        :return: 提取结果
        """
        if verbose:
            print(f"\n[提取] DWT频域盲水印提取")
            print(f"    - 文件: {img_path}")

        # 读取图片
        img = Image.open(img_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')

        img_ycbcr = img.convert('YCbCr')
        ycbcr_array = np.array(img_ycbcr, dtype=np.float32)
        y_channel = ycbcr_array[:, :, 0]

        # DWT 变换
        coeffs = pywt.dwt2(y_channel, 'haar')

        # 尝试加载原始 Y 通道（如果有）
        original_coeffs = None
        if original_y_path and os.path.exists(original_y_path):
            original_y = np.load(original_y_path)
            original_coeffs = pywt.dwt2(original_y, 'haar')

        # 提取比特
        bits = self._extract_bits_from_coeffs(coeffs, original_coeffs)

        # 转为十六进制
        hex_result = self._bits_to_hex(bits)

        if verbose:
            print(f"[✓] 水印提取完成")
            print(f"    - 提取标识: {hex_result[:32]}...")

        return {
            "success": True,
            "hex": hex_result,
            "hash": hex_result[:32],
            "bits": bits
        }

    def trace(self, img_path: str) -> dict:
        """
        溯源：提取水印并匹配日志
        """
        print(f"\n[溯源] DWT频域盲水印溯源")

        # 提取水印
        extracted = self.extract(img_path, verbose=True)

        if not extracted.get("success"):
            return {"success": False, "error": "水印提取失败"}

        extracted_hash = extracted["hash"]

        # 读取日志
        log_file = "dwt_watermark_log.json"
        if not os.path.exists(log_file):
            return {
                "success": False,
                "error": "未找到水印日志",
                "extracted_hash": extracted_hash
            }

        with open(log_file, 'r', encoding='utf-8') as f:
            logs = json.load(f)

        # 匹配
        best_match = None
        best_score = 0

        for log in logs:
            log_hash = log.get("watermark_hash", "")

            # 计算匹配度
            score = 0
            for i in range(min(32, len(extracted_hash), len(log_hash))):
                if extracted_hash[i] == log_hash[i]:
                    score += 1

            if score > best_score:
                best_score = score
                best_match = log

        # 匹配度大于20认为成功
        if best_match and best_score >= 20:
            return {
                "success": True,
                "matched": True,
                "user_id": best_match.get("user_id", ""),
                "timestamp": best_match.get("timestamp", 0),
                "file_hash": best_match.get("file_hash", ""),
                "watermark_str": best_match.get("watermark_str", ""),
                "match_score": best_score
            }

        return {
            "success": False,
            "matched": False,
            "extracted_hash": extracted_hash,
            "best_score": best_score,
            "error": "未找到匹配记录"
        }

    def _save_log(self, log_entry: dict):
        """保存日志"""
        log_file = "dwt_watermark_log.json"
        logs = []

        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)

        logs.append(log_entry)

        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)

    def verify(self, img_path: str, expected_user_id: str) -> bool:
        """验证图片是否属于某用户"""
        result = self.trace(img_path)
        return result.get("matched") and result.get("user_id") == expected_user_id

    def test_robustness(self, img_path: str):
        """
        测试水印鲁棒性
        """
        print(f"\n[鲁棒性测试]")

        # 原始提取
        original_result = self.extract(img_path, verbose=False)
        print(f"原始提取: {original_result['hash'][:16]}...")

        # 测试1：JPEG压缩
        from PIL import Image
        compressed_path = img_path.replace('.jpg', '_compressed.jpg')
        img = Image.open(img_path)
        img.save(compressed_path, quality=70)
        compressed_result = self.extract(compressed_path, verbose=False)
        print(f"JPEG压缩(70%): {compressed_result['hash'][:16]}...")

        # 测试2：缩放
        scaled_path = img_path.replace('.jpg', '_scaled.jpg')
        img = Image.open(img_path)
        scaled = img.resize((int(img.width * 0.8), int(img.height * 0.8)))
        scaled.save(scaled_path)
        scaled_result = self.extract(scaled_path, verbose=False)
        print(f"缩放80%: {scaled_result['hash'][:16]}...")

        # 计算匹配度
        def match_score(h1, h2):
            score = 0
            for i in range(min(len(h1), len(h2))):
                if h1[i] == h2[i]:
                    score += 1
            return score

        print(f"\n匹配度（与原始比较）:")
        print(f"  JPEG压缩: {match_score(original_result['hash'], compressed_result['hash'])}/32")
        print(f"  缩放: {match_score(original_result['hash'], scaled_result['hash'])}/32")


# ==========================================
# 测试函数
# ==========================================

def create_test_image():
    """创建测试图片"""
    test_file = "test_heritage.jpg"

    if os.path.exists(test_file):
        return test_file

    img = Image.new('RGB', (600, 400), color='white')
    draw = ImageDraw.Draw(img)
    draw.text((50, 180), "非遗珍贵档案 - 传统技艺", fill=(255, 0, 0))
    draw.text((150, 280), "非物质文化遗产保护中心", fill=(100, 100, 100))

    img.save(test_file)
    print(f"[测试] 创建: {test_file}")

    return test_file


def demo_full():
    """完整演示"""
    print("\n" + "=" * 60)
    print("DWT频域盲水印 - 完整溯源演示")
    print("=" * 60)

    wm = DWTBlindWatermark(strength=0.15, embed_size=32)
    test_img = create_test_image()

    # 阶段1：档案馆
    with open(test_img, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"\n📍 阶段1：档案馆")
    print(f"   档案摘要: {file_hash[:32]}...")

    # 阶段2：数据中心分发（嵌入水印）
    user_id = "researcher_zhang_san"
    print(f"\n📍 阶段2：数据中心")
    print(f"   申请人: {user_id}")

    wm_img = wm.embed(test_img, file_hash, user_id)

    # 阶段3：模拟泄露
    print(f"\n📍 阶段3：模拟泄露")
    print(f"   ⚠️  {user_id} 违规分享档案")

    # 阶段4：溯源
    print(f"\n📍 阶段4：溯源")
    result = wm.trace(wm_img)

    print(f"\n" + "=" * 60)
    print("📋 溯源结果：")

    if result.get("matched"):
        print(f"   ✅ 成功定位泄露责任人！")
        print(f"   👤 责任人: {result['user_id']}")
        print(f"   ⏰ 时间戳: {result['timestamp']}")
        print(f"   📁 档案摘要: {result.get('file_hash', '')[:32]}...")
        print(f"   📊 匹配度: {result.get('match_score', 0)}/32")
    else:
        print(f"   ❌ 未定位到责任人")
        print(f"   🔍 提取标识: {result.get('extracted_hash', 'N/A')[:32]}...")

    print("=" * 60)

    # 可选：测试鲁棒性
    print(f"\n是否测试水印鲁棒性？")
    if input("输入 y 测试: ").lower() == 'y':
        wm.test_robustness(wm_img)


def main():
    print("\n" + "=" * 60)
    print("任务二：DWT频域盲水印溯源系统")
    print("非遗数字档案跨馆共享安全方案")
    print("=" * 60)

    print("\n请选择：")
    print("  1. 完整演示（嵌入+提取+溯源）")
    print("  2. 从图片提取水印并溯源")
    print("  3. 鲁棒性测试")

    choice = input("\n请输入选项 (1-3): ").strip()

    if choice == "1":
        demo_full()
    elif choice == "2":
        file_path = input("请输入图片路径: ").strip()
        if os.path.exists(file_path):
            wm = DWTBlindWatermark()
            result = wm.trace(file_path)
            if result.get("matched"):
                print(f"\n✅ 责任人: {result['user_id']}")
            else:
                print(f"\n❌ 未找到匹配")
        else:
            print(f"文件不存在")
    elif choice == "3":
        wm = DWTBlindWatermark()
        test_img = create_test_image()
        with open(test_img, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        wm_img = wm.embed(test_img, file_hash, "test_user")
        wm.test_robustness(wm_img)
    else:
        demo_full()


if __name__ == "__main__":
    main()