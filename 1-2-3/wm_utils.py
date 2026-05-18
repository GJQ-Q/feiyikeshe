# wm_utils.py
import hashlib
import time
import json
import os
import numpy as np
import pywt
from PIL import Image

class DWTBlindWatermark:
    """
    基于DWT频域的盲水印算法（成员2贡献核心模块）
    水印嵌入在图像频域，抗裁剪、抗JPEG压缩
    """
    def __init__(self, strength=0.15, embed_size=32):
        self.strength = strength
        self.embed_size = embed_size

    def _text_to_bits(self, text: str, target_len: int = 256) -> list:
        hash_bytes = hashlib.sha256(text.encode()).digest()
        bits = []
        for b in hash_bytes:
            for j in range(7, -1, -1):
                bits.append((b >> j) & 1)
        if len(bits) > target_len:
            bits = bits[:target_len]
        else:
            original = bits.copy()
            while len(bits) < target_len:
                bits.extend(original[:min(len(original), target_len - len(bits))])
        return bits

    def _bits_to_hex(self, bits: list) -> str:
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
        cA, (cH, cV, cD) = coeffs
        h, w = cA.shape
        embed_h = min(h, self.embed_size)
        embed_w = min(w, self.embed_size)
        idx = 0
        for i in range(embed_h):
            for j in range(embed_w):
                if idx >= len(bits): break
                if bits[idx] == 1:
                    cA[i, j] += self.strength * abs(cA[i, j])
                else:
                    cA[i, j] -= self.strength * abs(cA[i, j])
                idx += 1
            if idx >= len(bits): break
        return (cA, (cH, cV, cD))

    def _extract_bits_from_coeffs(self, coeffs, original_coeffs=None):
        cA, _ = coeffs
        h, w = cA.shape
        embed_h = min(h, self.embed_size)
        embed_w = min(w, self.embed_size)

        if original_coeffs is not None:
            orig_cA, _ = original_coeffs
            bits = []
            for i in range(embed_h):
                for j in range(embed_w):
                    if len(bits) >= 256: break
                    diff = cA[i, j] - orig_cA[i, j]
                    bits.append(1 if diff > 0 else 0)
                if len(bits) >= 256: break
        else:
            embed_region = cA[:embed_h, :embed_w]
            threshold = np.mean(embed_region)
            bits = []
            for i in range(embed_h):
                for j in range(embed_w):
                    if len(bits) >= 256: break
                    bits.append(1 if cA[i, j] > threshold else 0)
                if len(bits) >= 256: break
        return bits

    def embed(self, cover_path: str, file_hash: str, user_id: str,
              timestamp: int = None, output_path: str = None) -> str:
        if timestamp is None:
            timestamp = int(time.time())
        if output_path is None:
            output_path = cover_path

        watermark_str = f"{file_hash[:16]}|{user_id[:10]}|{timestamp}"
        bits = self._text_to_bits(watermark_str, 256)

        img = Image.open(cover_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')

        img_ycbcr = img.convert('YCbCr')
        ycbcr_array = np.array(img_ycbcr, dtype=np.float32)
        y_channel = ycbcr_array[:, :, 0]

        coeffs = pywt.dwt2(y_channel, 'haar')
        new_coeffs = self._embed_bits_to_coeffs(coeffs, bits)
        new_y = pywt.idwt2(new_coeffs, 'haar')
        new_y = np.clip(new_y, 0, 255).astype(np.uint8)

        ycbcr_array[:, :, 0] = new_y
        result_ycbcr = Image.fromarray(ycbcr_array.astype(np.uint8), 'YCbCr')
        result_rgb = result_ycbcr.convert('RGB')
        result_rgb.save(output_path, quality=95)

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
        return output_path

    def extract(self, img_path: str, original_y_path: str = None) -> dict:
        img = Image.open(img_path)
        if img.mode == 'RGBA':
            img = img.convert('RGB')
        img_ycbcr = img.convert('YCbCr')
        ycbcr_array = np.array(img_ycbcr, dtype=np.float32)
        y_channel = ycbcr_array[:, :, 0]

        coeffs = pywt.dwt2(y_channel, 'haar')
        original_coeffs = None
        if original_y_path and os.path.exists(original_y_path):
            original_y = np.load(original_y_path)
            original_coeffs = pywt.dwt2(original_y, 'haar')

        bits = self._extract_bits_from_coeffs(coeffs, original_coeffs)
        hex_result = self._bits_to_hex(bits)
        return {"success": True, "hex": hex_result, "hash": hex_result[:32], "bits": bits}

    def trace(self, img_path: str) -> dict:
        extracted = self.extract(img_path)
        if not extracted.get("success"):
            return {"success": False, "error": "水印提取失败"}
        extracted_hash = extracted["hash"]

        log_file = "dwt_watermark_log.json"
        if not os.path.exists(log_file):
            return {"success": False, "error": "未找到水印日志", "extracted_hash": extracted_hash}

        with open(log_file, 'r', encoding='utf-8') as f:
            logs = json.load(f)

        best_match = None
        best_score = 0
        for log in logs:
            log_hash = log.get("watermark_hash", "")
            score = 0
            for i in range(min(32, len(extracted_hash), len(log_hash))):
                if extracted_hash[i] == log_hash[i]: score += 1
            if score > best_score:
                best_score = score
                best_match = log

        if best_match and best_score >= 20:
            return {
                "success": True, "matched": True,
                "user_id": best_match.get("user_id", ""),
                "timestamp": best_match.get("timestamp", 0),
                "file_hash": best_match.get("file_hash", ""),
                "watermark_str": best_match.get("watermark_str", ""),
                "match_score": best_score
            }
        return {"success": False, "matched": False, "extracted_hash": extracted_hash, "best_score": best_score, "error": "未找到匹配记录"}

    def _save_log(self, log_entry: dict):
        log_file = "dwt_watermark_log.json"
        logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        logs.append(log_entry)
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)