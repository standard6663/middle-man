import os
from midman.context import Context
from midman.manager import Manager
from midman.reporter import Reporter


if __name__ == "__main__":
    # 检查是否存在中间人进程 man.py
    pids = os.popen("ps -ef | grep man.py | grep -v grep | awk '{print $2}'").read().strip()
    if pids:
        print("[INFO] 停止中间人进程...")
        print(f"[INFO] kill {pids}")
        os.system(f"kill -9 {pids}")
    
    ctx = Context()

    reporter = Reporter(ctx)
    reporter.start()

    manager = Manager(ctx, reporter)
    manager.start()
