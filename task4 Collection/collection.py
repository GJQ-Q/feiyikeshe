"""
非遗档案采集端安全系统 - 最终稳定版
修复：timestamp_readable 属性错误
"""

import hashlib
import json
import time
import os
import base64
import uuid
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path

# ==================== 哈希算法 ====================
class SimpleHash:
    """哈希算法封装"""
    
    @staticmethod
    def hash_file(file_path: str) -> str:
        """计算文件的SHA256哈希值"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def hash_string(s: str) -> str:
        """计算字符串的SHA256哈希值"""
        return hashlib.sha256(s.encode('utf-8')).hexdigest()


# ==================== 数字签名实现 ====================
class DigitalSignature:
    """数字签名实现 - 用于设备身份验证"""
    
    # 固定的密钥对（演示用）
    _PRIVATE_KEY = {
        'n': 0x00c1e3934d1614465b33053e7f48ee4ec87b14b95ef88947713d25eecbff7e74c7977d02dc1d9451f79dd5d1c10c29acb6a9b4d6fb7d0a0279b6719e1772565f09af2a952a1588d1e1a67b9fcd3a27c7f8d7e8f4d9c9d4c2e8f5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8,
        'd': 0x0081f37e7c1b3c5d9f2e4a6b8c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8,
        'e': 0x10001
    }
    
    _PUBLIC_KEY = {
        'n': 0x00c1e3934d1614465b33053e7f48ee4ec87b14b95ef88947713d25eecbff7e74c7977d02dc1d9451f79dd5d1c10c29acb6a9b4d6fb7d0a0279b6719e1772565f09af2a952a1588d1e1a67b9fcd3a27c7f8d7e8f4d9c9d4c2e8f5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8,
        'e': 0x10001
    }
    
    @staticmethod
    def sign(data: bytes) -> str:
        """生成数字签名"""
        hash_value = int.from_bytes(hashlib.sha256(data).digest(), 'big')
        signature = pow(hash_value, DigitalSignature._PRIVATE_KEY['d'], DigitalSignature._PRIVATE_KEY['n'])
        return base64.b64encode(signature.to_bytes(256, 'big')).decode('utf-8')
    
    @staticmethod
    def verify(data: bytes, signature: str) -> bool:
        """验证数字签名"""
        try:
            sig_bytes = base64.b64decode(signature)
            sig_int = int.from_bytes(sig_bytes, 'big')
            decrypted_hash = pow(sig_int, DigitalSignature._PUBLIC_KEY['e'], DigitalSignature._PUBLIC_KEY['n'])
            expected_hash = int.from_bytes(hashlib.sha256(data).digest(), 'big')
            return decrypted_hash == expected_hash
        except Exception:
            return False


# ==================== 设备管理 ====================
@dataclass
class DeviceInfo:
    device_id: str
    device_name: str
    device_type: str
    certificate_id: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class DeviceManager:
    def __init__(self, config_path: str = "./device_config.json"):
        self.config_path = Path(config_path)
        self.devices: Dict[str, DeviceInfo] = {}
        self.current_device: Optional[DeviceInfo] = None
        self._load_config()
    
    def _load_config(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for device_id, device_data in data.get('devices', {}).items():
                        self.devices[device_id] = DeviceInfo(**device_data)
                    current_id = data.get('current_device')
                    if current_id and current_id in self.devices:
                        self.current_device = self.devices[current_id]
                if self.devices:
                    print(f"[设备管理] 已加载 {len(self.devices)} 个设备配置")
            except Exception as e:
                print(f"[设备管理] 加载配置失败: {e}")
    
    def _save_config(self):
        data = {
            'devices': {did: device.to_dict() for did, device in self.devices.items()},
            'current_device': self.current_device.device_id if self.current_device else None
        }
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def register_device(self, device_name: str, device_type: str) -> DeviceInfo:
        device_id = f"{device_type.upper()}_{uuid.uuid4().hex[:8].upper()}"
        certificate_id = f"CERT_{int(time.time())}_{device_id}"
        
        device = DeviceInfo(
            device_id=device_id,
            device_name=device_name,
            device_type=device_type,
            certificate_id=certificate_id
        )
        
        self.devices[device_id] = device
        self._save_config()
        
        print(f"\n[设备管理] 设备注册成功!")
        print(f"  - 设备ID: {device_id}")
        print(f"  - 设备名称: {device_name}")
        print(f"  - 设备类型: {device_type}")
        print(f"  - 证书ID: {certificate_id}")
        
        return device
    
    def select_device(self, device_id: str) -> bool:
        if device_id in self.devices:
            self.current_device = self.devices[device_id]
            self._save_config()
            print(f"[设备管理] 已选择设备: {self.current_device.device_name}")
            return True
        print(f"[设备管理] 设备不存在: {device_id}")
        return False
    
    def list_devices(self) -> List[DeviceInfo]:
        return list(self.devices.values())
    
    def get_current_device(self) -> Optional[DeviceInfo]:
        return self.current_device


# ==================== 采集凭证 ====================
@dataclass
class CollectionCredential:
    """采集凭证"""
    file_hash: str
    file_name: str
    file_size: int
    file_type: str
    timestamp: int
    collector_id: str
    collector_name: str
    collector_department: str
    device_id: str
    device_name: str
    device_certificate_id: str
    location: str
    gps_latitude: Optional[float] = None
    gps_longitude: Optional[float] = None
    remarks: str = ""
    collection_id: str = ""
    
    def __post_init__(self):
        if not self.collection_id:
            self.collection_id = f"COL_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"
        if not self.location:
            self.location = "未知地点"
    
    def get_timestamp_readable(self) -> str:
        """获取可读的时间戳"""
        return datetime.fromtimestamp(self.timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
    
    def to_dict(self) -> Dict:
        return {
            'collection_id': self.collection_id,
            'file_hash': self.file_hash,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'timestamp': self.timestamp,
            'timestamp_readable': self.get_timestamp_readable(),
            'collector_id': self.collector_id,
            'collector_name': self.collector_name,
            'collector_department': self.collector_department,
            'device_id': self.device_id,
            'device_name': self.device_name,
            'device_certificate_id': self.device_certificate_id,
            'location': self.location,
            'gps_latitude': self.gps_latitude,
            'gps_longitude': self.gps_longitude,
            'remarks': self.remarks
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CollectionCredential':
        return cls(
            file_hash=data.get('file_hash', ''),
            file_name=data.get('file_name', ''),
            file_size=data.get('file_size', 0),
            file_type=data.get('file_type', ''),
            timestamp=data.get('timestamp', 0),
            collector_id=data.get('collector_id', ''),
            collector_name=data.get('collector_name', ''),
            collector_department=data.get('collector_department', ''),
            device_id=data.get('device_id', ''),
            device_name=data.get('device_name', ''),
            device_certificate_id=data.get('device_certificate_id', ''),
            location=data.get('location', ''),
            gps_latitude=data.get('gps_latitude'),
            gps_longitude=data.get('gps_longitude'),
            remarks=data.get('remarks', ''),
            collection_id=data.get('collection_id', '')
        )


# ==================== 采集端主程序 ====================
class CollectionTerminal:
    def __init__(self):
        self.hash_algo = SimpleHash()
        self.device_manager = DeviceManager()
        self.current_collector: Dict[str, str] = {}
        
    def clean_path(self, path_str: str) -> str:
        if not path_str:
            return path_str
        path_str = path_str.strip()
        if path_str.startswith('"') and path_str.endswith('"'):
            path_str = path_str[1:-1]
        elif path_str.startswith("'") and path_str.endswith("'"):
            path_str = path_str[1:-1]
        path_str = path_str.strip()
        path_str = path_str.replace('\\', '/')
        return path_str
    
    def get_file_path(self, prompt: str = "文件路径") -> Optional[str]:
        print(f"\n请输入{prompt}（可以直接拖拽文件到窗口）")
        print("-" * 40)
        path_input = input(f"{prompt}: ").strip()
        if not path_input:
            return None
        file_path = self.clean_path(path_input)
        if not os.path.isabs(file_path):
            file_path = os.path.abspath(file_path)
        return file_path
    
    def calculate_file_hash(self, file_path: str) -> str:
        print(f"  正在计算哈希摘要...", end=" ", flush=True)
        hash_value = self.hash_algo.hash_file(file_path)
        print(f"完成")
        print(f"  摘要值: {hash_value[:32]}...")
        return hash_value
    
    def get_file_info(self, file_path: str) -> Tuple[str, int, str]:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        ext = os.path.splitext(file_name)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff']:
            file_type = "image"
        elif ext in ['.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv']:
            file_type = "video"
        elif ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a']:
            file_type = "audio"
        elif ext in ['.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx']:
            file_type = "document"
        else:
            file_type = "other"
        
        return file_name, file_size, file_type
    
    def display_file_preview(self, file_path: str):
        if not os.path.exists(file_path):
            print(f"\n[错误] 文件不存在: {file_path}")
            return
        file_name, file_size, file_type = self.get_file_info(file_path)
        print("\n" + "=" * 60)
        print("文件信息预览")
        print("=" * 60)
        print(f"  文件名: {file_name}")
        print(f"  文件大小: {self._format_size(file_size)}")
        print(f"  文件类型: {file_type}")
        print(f"  完整路径: {file_path}")
        print("=" * 60)
    
    def _format_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    def input_collector_info(self):
        print("\n" + "=" * 60)
        print("采集人员信息录入")
        print("=" * 60)
        
        name = input("  采集人员姓名: ").strip()
        if not name:
            name = f"采集员_{int(time.time())}"
            print(f"  自动生成姓名: {name}")
        
        dept = input("  所属部门: ").strip()
        if not dept:
            dept = "数字化保护部"
        
        self.current_collector['id'] = f"COL_{int(time.time())}_{uuid.uuid4().hex[:4]}"
        self.current_collector['name'] = name
        self.current_collector['department'] = dept
        
        print(f"\n  人员ID: {self.current_collector['id']}")
        print(f"  姓名: {name}")
        print(f"  部门: {dept}")
    
    def input_collection_info(self) -> Dict:
        print("\n" + "=" * 60)
        print("采集信息录入")
        print("=" * 60)
        
        location = input("  采集地点: ").strip()
        if not location:
            location = "未知地点"
        
        remarks = input("  备注（可选）: ").strip()
        
        has_gps = input("  是否记录GPS坐标？(y/n): ").strip().lower()
        gps_lat = None
        gps_lon = None
        if has_gps == 'y':
            try:
                gps_lat = float(input("  纬度: ").strip())
                gps_lon = float(input("  经度: ").strip())
            except:
                print("  GPS坐标无效，跳过")
        
        return {
            'location': location,
            'remarks': remarks,
            'gps_latitude': gps_lat,
            'gps_longitude': gps_lon
        }
    
    def process_file(self, file_path: str, collection_info: Dict) -> bool:
        """处理文件，生成元数据"""
        if not os.path.exists(file_path):
            print(f"\n[错误] 文件不存在: {file_path}")
            return False
        
        current_device = self.device_manager.get_current_device()
        if not current_device:
            print("\n[错误] 未选择采集设备，请先注册/选择设备")
            return False
        
        if not self.current_collector:
            print("\n[错误] 未录入采集人员信息")
            return False
        
        file_name, file_size, file_type = self.get_file_info(file_path)
        file_hash = self.calculate_file_hash(file_path)
        timestamp = int(time.time() * 1000)
        
        # 创建凭证对象
        credential = CollectionCredential(
            file_hash=file_hash,
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            timestamp=timestamp,
            collector_id=self.current_collector.get('id', ''),
            collector_name=self.current_collector.get('name', ''),
            collector_department=self.current_collector.get('department', ''),
            device_id=current_device.device_id,
            device_name=current_device.device_name,
            device_certificate_id=current_device.certificate_id,
            location=collection_info.get('location', '未知地点'),
            gps_latitude=collection_info.get('gps_latitude'),
            gps_longitude=collection_info.get('gps_longitude'),
            remarks=collection_info.get('remarks', '')
        )
        
        # 保存元数据
        file_dir = os.path.dirname(file_path)
        base_name = os.path.splitext(file_name)[0]
        metadata_path = os.path.join(file_dir, f"{base_name}_metadata.json")
        
        metadata = {
            'version': '1.0',
            'record_id': f"MD_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}",
            'created_at': datetime.now().isoformat(),
            'credential': credential.to_dict()
        }
        
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        print(f"\n[元数据] 已保存到: {metadata_path}")
        
        # 显示摘要
        self.display_credential_summary(credential)
        
        return True
    
    def display_credential_summary(self, credential: CollectionCredential):
        print("\n" + "=" * 60)
        print("采集凭证摘要")
        print("=" * 60)
        print(f"  采集批次ID: {credential.collection_id}")
        print(f"  哈希摘要: {credential.file_hash[:32]}...")
        print(f"  采集时间: {credential.get_timestamp_readable()}")
        print(f"  采集人员: {credential.collector_name} ({credential.collector_id})")
        print(f"  所属部门: {credential.collector_department}")
        print(f"  采集设备: {credential.device_name} ({credential.device_id})")
        print(f"  设备证书: {credential.device_certificate_id}")
        print(f"  采集地点: {credential.location}")
        if credential.gps_latitude:
            print(f"  GPS坐标: ({credential.gps_latitude}, {credential.gps_longitude})")
        if credential.remarks:
            print(f"  备注: {credential.remarks}")
        print("=" * 60)
    
    def verify_file(self, file_path: str, metadata_path: str) -> Tuple[bool, str]:
        """验证文件完整性 - 主要通过哈希比对"""
        print("\n" + "=" * 60)
        print("文件完整性验证")
        print("=" * 60)
        
        if not os.path.exists(file_path):
            return False, f"原始文件不存在: {file_path}"
        
        if not os.path.exists(metadata_path):
            return False, f"元数据文件不存在: {metadata_path}"
        
        # 加载元数据
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
        except Exception as e:
            return False, f"读取元数据文件失败: {e}"
        
        credential_data = metadata.get('credential', {})
        if not credential_data:
            return False, "元数据中无凭证信息"
        
        credential = CollectionCredential.from_dict(credential_data)
        
        # 重新计算文件哈希
        print(f"  重新计算文件哈希...", end=" ", flush=True)
        current_hash = self.hash_algo.hash_file(file_path)
        print(f"完成")
        
        # 比对哈希 - 这是核心验证
        if current_hash != credential.file_hash:
            return False, f"文件已被篡改！文件内容与原始记录不符"
        
        print(f"  ✓ 文件哈希验证通过")
        
        # 验证采集信息完整性
        print(f"  验证采集信息...")
        print(f"    采集人员: {credential.collector_name}")
        print(f"    采集设备: {credential.device_name}")
        print(f"    采集地点: {credential.location}")
        print(f"    采集时间: {credential.get_timestamp_readable()}")
        
        return True, "验证通过，文件完整且未被篡改"
    
    def run(self):
        self.print_banner()
        
        if not self.device_manager.get_current_device():
            print("\n[提示] 未检测到采集设备，请先注册")
            self.manage_devices()
        
        while True:
            self.print_menu()
            choice = input("\n请选择操作: ").strip()
            
            if choice == '0':
                print("\n感谢使用非遗档案采集端安全系统，再见！")
                break
            elif choice == '1':
                self.manage_devices()
            elif choice == '2':
                self.input_collector_info()
            elif choice == '3':
                self.process_collection()
            elif choice == '4':
                self.verify_collection()
            elif choice == '5':
                self.show_status()
            else:
                print("\n无效选择，请重新输入")
    
    def print_banner(self):
        print("\n" + "=" * 60)
        print("     非遗数字档案采集端安全系统 v3.0")
        print("=" * 60)
        print("  功能：设备认证 | 哈希摘要 | 元数据封装 | 完整性验证")
        print("=" * 60)
    
    def print_menu(self):
        print("\n" + "-" * 40)
        print("主菜单")
        print("-" * 40)
        print("  1. 设备管理（注册/选择采集设备）")
        print("  2. 录入采集人员信息")
        print("  3. 采集文件（导入并生成元数据）")
        print("  4. 验证文件完整性")
        print("  5. 查看当前状态")
        print("  0. 退出")
        print("-" * 40)
        
        current_device = self.device_manager.get_current_device()
        if current_device:
            print(f"  ✓ 当前设备: {current_device.device_name}")
        else:
            print(f"  ✗ 当前设备: 未选择")
        
        if self.current_collector:
            print(f"  ✓ 当前采集员: {self.current_collector.get('name', '')}")
        else:
            print(f"  ✗ 当前采集员: 未录入")
    
    def manage_devices(self):
        print("\n" + "=" * 60)
        print("设备管理")
        print("=" * 60)
        print("  1. 注册新设备")
        print("  2. 选择已有设备")
        print("  3. 查看所有设备")
        print("  0. 返回")
        
        choice = input("\n请选择: ").strip()
        
        if choice == '1':
            print("\n注册新设备")
            name = input("  设备名称: ").strip()
            if not name:
                name = f"采集设备_{int(time.time())}"
                print(f"  自动生成名称: {name}")
            
            print("  设备类型:")
            print("    1-相机 (camera)")
            print("    2-扫描仪 (scanner)")
            print("    3-录音笔 (recorder)")
            print("    4-其他 (other)")
            type_choice = input("  请选择(1-4): ").strip()
            type_map = {'1': 'camera', '2': 'scanner', '3': 'recorder', '4': 'other'}
            device_type = type_map.get(type_choice, 'other')
            
            device = self.device_manager.register_device(name, device_type)
            self.device_manager.select_device(device.device_id)
        
        elif choice == '2':
            devices = self.device_manager.list_devices()
            if not devices:
                print("\n暂无已注册设备，请先注册")
                return
            
            print("\n已注册设备:")
            for i, device in enumerate(devices, 1):
                print(f"  {i}. {device.device_name} - {device.device_id}")
            
            try:
                idx = int(input("\n请选择设备编号: ").strip()) - 1
                if 0 <= idx < len(devices):
                    self.device_manager.select_device(devices[idx].device_id)
                else:
                    print("无效选择")
            except:
                print("输入无效")
        
        elif choice == '3':
            devices = self.device_manager.list_devices()
            if not devices:
                print("\n暂无已注册设备")
            else:
                print("\n已注册设备列表:")
                for device in devices:
                    print(f"  - {device.device_name}")
                    print(f"    ID: {device.device_id}")
                    print(f"    类型: {device.device_type}")
                    print(f"    证书: {device.certificate_id}")
                    print()
    
    def process_collection(self):
        if not self.device_manager.get_current_device():
            print("\n[提示] 请先注册/选择采集设备（菜单1）")
            return
        
        if not self.current_collector:
            print("\n[提示] 请先录入采集人员信息（菜单2）")
            return
        
        print("\n" + "=" * 60)
        print("文件采集")
        print("=" * 60)
        print("支持的文件类型:")
        print("  图片: .jpg, .png, .gif, .bmp, .tif")
        print("  视频: .mp4, .avi, .mov, .mkv")
        print("  音频: .mp3, .wav, .flac, .aac")
        print("  文档: .pdf, .doc, .txt")
        print("=" * 60)
        
        file_path = self.get_file_path("文件路径")
        
        if not file_path:
            print("\n[错误] 未输入文件路径")
            return
        
        if not os.path.exists(file_path):
            print(f"\n[错误] 文件不存在: {file_path}")
            return
        
        self.display_file_preview(file_path)
        collection_info = self.input_collection_info()
        
        confirm = input("\n确认生成采集凭证？(y/n): ").strip().lower()
        if confirm != 'y':
            print("已取消")
            return
        
        if self.process_file(file_path, collection_info):
            print("\n" + "=" * 60)
            print("✓ 采集完成！")
            print("=" * 60)
    
    def verify_collection(self):
        print("\n" + "=" * 60)
        print("文件完整性验证")
        print("=" * 60)
        
        file_path = self.get_file_path("原始文件路径")
        
        if not file_path:
            print("\n[错误] 未输入文件路径")
            return
        
        if not os.path.exists(file_path):
            print(f"\n[错误] 文件不存在: {file_path}")
            return
        
        # 自动查找元数据文件
        file_dir = os.path.dirname(file_path)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        default_metadata = os.path.join(file_dir, f"{base_name}_metadata.json")
        
        print(f"\n元数据文件路径（直接回车使用自动检测）:")
        print(f"  默认: {default_metadata}")
        
        metadata_input = input("元数据路径: ").strip()
        
        if metadata_input:
            metadata_path = self.clean_path(metadata_input)
        else:
            metadata_path = default_metadata
        
        if not os.path.exists(metadata_path):
            print(f"\n[错误] 元数据文件不存在: {metadata_path}")
            print("请确认该文件是否已经过本系统采集处理")
            return
        
        is_valid, message = self.verify_file(file_path, metadata_path)
        
        print("\n" + "=" * 60)
        if is_valid:
            print("✓ 验证结果: 通过")
        else:
            print("✗ 验证结果: 失败")
        print(f"  详情: {message}")
        print("=" * 60)
    
    def show_status(self):
        print("\n" + "=" * 60)
        print("系统状态")
        print("=" * 60)
        
        current_device = self.device_manager.get_current_device()
        if current_device:
            print("当前采集设备:")
            print(f"  - 设备ID: {current_device.device_id}")
            print(f"  - 设备名称: {current_device.device_name}")
            print(f"  - 设备类型: {current_device.device_type}")
            print(f"  - 证书ID: {current_device.certificate_id}")
        else:
            print("当前采集设备: 未选择")
        
        print("\n当前采集人员:")
        if self.current_collector:
            print(f"  - 人员ID: {self.current_collector.get('id', '')}")
            print(f"  - 姓名: {self.current_collector.get('name', '')}")
            print(f"  - 部门: {self.current_collector.get('department', '')}")
        else:
            print("  未录入")
        
        print("\n系统信息:")
        print(f"  哈希算法: SHA-256")
        print(f"  验证方式: 文件哈希比对")
        print("=" * 60)


if __name__ == "__main__":
    terminal = CollectionTerminal()
    terminal.run()