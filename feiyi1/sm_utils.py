import json
import os
import time
from gmssl import sm3, func


class SM3Provider:
    @staticmethod
    def hash_data(data_bytes):
        """计算数据的 SM3 哈希值 (返回十六进制字符串)"""
        return sm3.sm3_hash(list(data_bytes))


class HashChainAudit:
    """哈希链审计日志：每一条日志都包含上一条日志的哈希"""

    def __init__(self, log_path="audit_chain.json"):
        self.log_path = log_path
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w', encoding='utf-8') as f:
                json.dump([], f)

    def record(self, node_id, operation, data_sm3):
        with open(self.log_path, 'r+', encoding='utf-8') as f:
            logs = json.load(f)

            # 获取上一条记录的哈希值（作为链条的起点）
            prev_hash = logs[-1]['current_hash'] if logs else "00000000000000000000000000000000"

            # 构造当前日志项
            entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "node": node_id,
                "op": operation,
                "payload_sm3": data_sm3,
                "prev_hash": prev_hash
            }

            # 计算当前条目的哈希链值：SM3(当前内容 + 上一环摘要)
            entry_str = json.dumps(entry, sort_keys=True)
            current_hash = SM3Provider.hash_data(entry_str.encode('utf-8'))
            entry['current_hash'] = current_hash

            logs.append(entry)
            f.seek(0)
            f.truncate()
            json.dump(logs, f, indent=4, ensure_ascii=False)
            print(f"🔗 [哈希链] 节点 {node_id} 已存证，环位: {len(logs)}")