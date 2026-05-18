import socket
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
import datetime

# 初始化 Rich 组件
console = Console()
layout = Layout()

# 全局状态存储
status = {"A": "离线", "B": "离线", "C": "离线", "log": []}
heartbeat_toggle = True  # 用于显示心跳闪烁


def make_layout():
    """创建全屏监控布局"""
    layout.split_column(
        Layout(name="top", size=3),
        Layout(name="main", size=10),
        Layout(name="bottom")
    )
    layout["main"].split_row(
        Layout(name="A"), Layout(name="B"), Layout(name="C")
    )
    return layout


def update_ui():
    """根据最新状态更新界面"""
    global heartbeat_toggle
    heartbeat_toggle = not heartbeat_toggle
    # 心跳图标
    hb = "[bold red]❤️[/bold red]" if heartbeat_toggle else "[dim red]💔[/dim red]"

    now = datetime.datetime.now().strftime("%H:%M:%S")

    layout["top"].update(Panel(
        f"{hb} [bold yellow]🏛️ 非遗数字档案全链路实时监控中心[/bold yellow] [dim](运行中: {now})[/dim]",
        border_style="yellow"
    ))

    # 渲染三个节点的状态面板
    layout["A"].update(Panel(f"\n[cyan]{status['A']}[/cyan]", title="采集端 (Node A)", border_style="blue"))
    layout["B"].update(Panel(f"\n[cyan]{status['B']}[/cyan]", title="档案馆 (Node B)", border_style="green"))
    layout["C"].update(Panel(f"\n[cyan]{status['C']}[/cyan]", title="数据中心 (Node C)", border_style="magenta"))

    # 渲染日志表格
    log_table = Table.grid(expand=True)
    display_logs = status["log"][-10:]
    for msg in display_logs:
        if "🟢" in msg:
            log_table.add_row(f"[dim green]{msg}[/dim green]")
        elif "✅" in msg:
            log_table.add_row(f"[bold green]{msg}[/bold green]")
        elif "❌" in msg:
            log_table.add_row(f"[bold red]{msg}[/bold red]")
        else:
            log_table.add_row(msg)

    layout["bottom"].update(Panel(log_table, title="📜 实时业务流转日志 (最近10条)", border_style="white"))


def run_monitor():
    """启动 UDP 监控监听"""
    mon_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 尝试绑定 0.0.0.0 以获得更好的兼容性
    try:
        mon_socket.bind(('0.0.0.0', 9999))
        mon_socket.settimeout(0.5)
    except Exception as e:
        console.print(f"[bold red]无法启动监听: {e}[/bold red]")
        return

    make_layout()

    with Live(layout, refresh_per_second=4, screen=True):
        while True:
            try:
                data, addr = mon_socket.recvfrom(1024)
                # 尝试多种编码防止解析失败
                try:
                    msg = data.decode('utf-8')
                except UnicodeDecodeError:
                    msg = data.decode('gbk', errors='ignore')

                if '|' in msg:
                    node, info = msg.split('|', 1)
                    node = node.strip().upper()
                    if node in status:
                        status[node] = info.strip()
                        timestamp = datetime.datetime.now().strftime("%M:%S")
                        status["log"].append(f"[{timestamp}] [{node}] {info.strip()}")

                update_ui()
            except (socket.timeout, TimeoutError):
                update_ui()
                continue
            except Exception as e:
                # 记录异常到日志，方便调试
                status["log"].append(f"[系统错误] {str(e)}")
                update_ui()
                continue


if __name__ == "__main__":
    run_monitor()