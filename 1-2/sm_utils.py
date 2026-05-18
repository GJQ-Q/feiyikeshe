import json
import os
import time
from gmssl import sm3, sm4

# ==========================================
# 1. 智能密钥管理（由成员3贡献）
# ==========================================
def get_system_key(key_file="feiyi_system.key"):
    """确保全组节点在本地自动加载或生成同一把 SM4 密钥"""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = os.urandom(16)
        with open(key_file, "wb") as f:
            f.write(key)
    return key

# ==========================================
# 2. 统一国密加解密服务提供者
# ==========================================
class SMCryptoProvider:
    def __init__(self):
        self.key = get_system_key()
        self.crypt_sm4 = sm4.CryptSM4()

    @staticmethod
    def sm3_hash(data_bytes):
        """计算数据的 SM3 哈希值 (返回十六进制字符串)"""
        return sm3.sm3_hash(list(data_bytes))

    def _pad(self, data: bytes) -> bytes:
        """PKCS#7 填充"""
        padding_len = 16 - (len(data) % 16)
        return data + bytes([padding_len] * padding_len)

    def _unpad(self, data: bytes) -> bytes:
        """PKCS#7 去除填充"""
        padding_len = data[-1]
        return data[:-padding_len]

    def sm4_encrypt(self, data: bytes) -> bytes:
        """SM4 CBC 模式加密"""
        self.crypt_sm4.set_key(self.key, sm4.SM4_ENCRYPT)
        iv = b'\x00' * 16  # 保持成员3约定的固定IV便于演示
        padded_data = self._pad(data)
        return self.crypt_sm4.crypt_cbc(iv, padded_data)

    def sm4_decrypt(self, data: bytes) -> bytes:
        """SM4 CBC 模式解密"""
        self.crypt_sm4.set_key(self.key, sm4.SM4_DECRYPT)
        iv = b'\x00' * 16
        return self._unpad(self.crypt_sm4.crypt_cbc(iv, data))

# ==========================================
# 3. 哈希链审计日志（统一调用，移除节点内手写函数）
# ==========================================
class HashChainAudit:
    """不可篡改哈希链审计日志"""
    def __init__(self, log_path="audit_chain.json"):
        self.log_path = log_path
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    def record(self, node_id, operation, data_sm3):
        with open(self.log_path, 'r+', encoding='utf-8') as f:
            try:
                logs = json.load(f)
            except:
                logs = []

            prev_hash = logs[-1]['current_hash'] if logs else "0" * 64

            entry = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "node": node_id,
                "operation": operation,
                "payload_sm3": data_sm3,
                "prev_hash": prev_hash
            }

            # 统一计算当前条目的哈希链（注意：成员1原本在节点中错用 entry_str 且含动态 time，
            # 这里规范化为只对业务关键凭证 [prev_hash + data_sm3] 进行哈希，确保审计链稳定）
            chain_src = f"{prev_hash}{data_sm3}{operation}".encode('utf-8')
            current_hash = SMCryptoProvider.sm3_hash(chain_src)
            entry['current_hash'] = current_hash

            logs.append(entry)
            f.seek(0)
            f.truncate()
            json.dump(logs, f, indent=4, ensure_ascii=False)
            print(f"📊 [审计哈希链] {node_id} 更新成功。环位: {len(logs)}, 摘要末尾: {current_hash[-8:]}")