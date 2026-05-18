import json
import os
import hashlib

class DeviceSignatureProvider:
    """提取自成员4的采集端安全系统，保持独立不污染国密库"""
    _PRIVATE_KEY = {'n': 0x00c1e3934d161, 'd': 0x23a109bf33}
    _PUBLIC_KEY = {'n': 0x00c1e3934d161, 'e': 0x10001}

    def __init__(self, config_path="device_config.json"):
        self.config_path = config_path
        self._prepare_mock_config()

    def _prepare_mock_config(self):
        """保证本地环境中 device_config.json 设备特征配置自动配齐"""
        if not os.path.exists(self.config_path):
            default_config = {
                "devices": {
                    "CAMERA_02FEA96F": {
                        "device_id": "CAMERA_02FEA96F",
                        "device_name": "佳能G12(课设专用)",
                        "device_type": "camera",
                        "certificate_id": "CERT_gjq_23072018"
                    }
                },
                "current_device": "CAMERA_02FEA96F"
            }
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)

    def get_current_device_info(self):
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            curr = cfg.get("current_device")
            return cfg["devices"][curr]
        except:
            return {"device_id": "UNKNOWN_DEV", "device_name": "未知授权设备", "certificate_id": "NONE"}

    def sign_asset(self, data_bytes: bytes) -> str:
        """对原始采集的非遗图片计算哈希并进行签名"""
        sha256_hash = hashlib.sha256(data_bytes).hexdigest()
        h_int = int(sha256_hash[:10], 16)
        signature_int = pow(h_int, self._PRIVATE_KEY['d'], self._PRIVATE_KEY['n'])
        return f"{signature_int:x}"

    def verify_signature(self, data_bytes: bytes, sig_hex: str) -> bool:
        """用公钥还原指纹验证采集源头"""
        try:
            sha256_hash = hashlib.sha256(data_bytes).hexdigest()
            h_int = int(sha256_hash[:10], 16)
            sig_int = int(sig_hex, 16)
            decrypted_hash = pow(sig_int, self._PUBLIC_KEY['e'], self._PUBLIC_KEY['n'])
            return (decrypted_hash % 0xFFFFFF) == (h_int % 0xFFFFFF)
        except:
            return False