import os
import json
from gmssl import sm3, sm4


# ==========================================
# 1. 智能密钥管理：确保全组只有一把“万能钥匙”
# ==========================================
def get_system_key(key_file="feiyi_system.key"):
    """
    智能获取密钥：
    1. 如果本地有 key 文件，直接读取。
    2. 如果没有，则生成一个随机的 16 字节密钥并保存。
    """
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
        print(f"[!] 发现现有密钥文件，已成功加载。")
    else:
        # 随机生成 16 字节密钥
        key = os.urandom(16)
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"[+] 未发现密钥文件，已自动生成随机密钥并保存至: {key_file}")

    return key


# ==========================================
# 2. 国密工具类：封装 SM3 和 SM4
# ==========================================
class SM_Crypto_Tool:
    def __init__(self, key: bytes):
        # 严格检查 SM4 密钥长度（必须为16字节）
        if len(key) != 16:
            raise ValueError("密钥长度必须为 16 字节！")
        self.key = key
        self.crypt_sm4 = sm4.CryptSM4()

    def _pad(self, data: bytes) -> bytes:
        padding_len = 16 - (len(data) % 16)
        return data + bytes([padding_len] * padding_len)

    def _unpad(self, data: bytes) -> bytes:
        return data[:-data[-1]]

    def sm4_encrypt(self, data: bytes) -> bytes:
        """执行 SM4 加密（保护核心资源安全）"""
        self.crypt_sm4.set_key(self.key, sm4.SM4_ENCRYPT)
        iv = b'\x00' * 16  # 固定 IV 方便课设演示
        return self.crypt_sm4.crypt_cbc(iv, self._pad(data))

    def sm4_decrypt(self, data: bytes) -> bytes:
        """执行 SM4 解密（还原非遗档案内容）"""
        self.crypt_sm4.set_key(self.key, sm4.SM4_DECRYPT)
        iv = b'\x00' * 16
        return self._unpad(self.crypt_sm4.crypt_cbc(iv, data))

    def sm3_hash(self, data: bytes) -> str:
        """生成 SM3 数字指纹（用于完整性校验）[cite: 1]"""
        return sm3.sm3_hash(list(data))


# ==========================================
# 3. 业务逻辑与演示
# ==========================================
if __name__ == "__main__":
    # 第一步：获取密钥（全组通用）
    SYSTEM_KEY = get_system_key()
    crypto = SM_Crypto_Tool(SYSTEM_KEY)

    # 第二步：档案馆加密档案（模拟任务 3 流程）[cite: 1]
    test_file = "feiyi_demo.txt"
    with open(test_file, "w", encoding="utf-8") as f:
        f.write("这是非遗馆 A 的珍贵史料，准备分享给数据中心。")

    print("\n--- 📤 档案馆处理中 ---")
    with open(test_file, 'rb') as f:
        raw_data = f.read()

    # 1. 算指纹[cite: 1]
    file_digest = crypto.sm3_hash(raw_data)
    # 2. 加锁[cite: 1]
    encrypted_data = crypto.sm4_encrypt(raw_data)

    with open(test_file + ".enc", "wb") as f:
        f.write(encrypted_data)

    print(f"[*] 摘要: {file_digest}")
    print(f"[*] 加密文件已生成: {test_file}.enc")

    # 第三步：模拟数据中心解密验证（模拟任务 2 流程）[cite: 1]
    print("\n--- 📥 数据中心处理中 ---")
    with open(test_file + ".enc", "rb") as f:
        received_data = f.read()

    # 3. 开锁[cite: 1]
    decrypted_data = crypto.sm4_decrypt(received_data)
    # 4. 验真[cite: 1]
    if crypto.sm3_hash(decrypted_data) == file_digest:
        print(f"[√] 校验通过！内容原文: {decrypted_data.decode('utf-8')}")
    else:
        print("[X] 校验失败！")
