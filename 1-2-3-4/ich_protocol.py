import json
import base64
from gmssl import sm3


class ICHPacket:
    @staticmethod
    def create(payload_bytes, metadata):
        """创建带 SM3 随行哈希的数据包"""
        # 计算随行哈希并存入元数据
        data_hash = sm3.sm3_hash(list(payload_bytes))
        metadata['sm3_integrity'] = data_hash

        packet_dict = {
            "metadata": metadata,
            "payload": base64.b64encode(payload_bytes).decode('utf-8')
        }
        return json.dumps(packet_dict)

    @staticmethod
    def verify_and_unpack(raw_str):
        """校验并解包"""
        data = json.loads(raw_str)
        metadata = data['metadata']
        payload_bytes = base64.b64decode(data['payload'])

        # 重新计算哈希比对
        calc_hash = sm3.sm3_hash(list(payload_bytes))
        is_valid = (calc_hash == metadata.get('sm3_integrity'))

        return is_valid, payload_bytes, metadata

    @staticmethod
    def get_hash(data_bytes):
        """SM3 哈希工具函数"""
        return sm3.sm3_hash(list(data_bytes))