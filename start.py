import os
import signal
import sys
import time
from midman.context import Context
from midman.manager import Manager
from midman.reporter import Reporter


class Middleman:
    def __init__(self):
        self.ctx = Context()
        self.reporter = None
        self.manager = None
        self.running = True

    def cleanup(self):
        """优雅关闭所有资源"""
        print("[INFO] 开始关闭...")
        self.running = False

        # 1. 停止 manager（会关闭 mitmproxy 子进程）
        if self.manager:
            print("[INFO] 停止中间人进程...")
            self.manager.stop()

        # 2. 停止 reporter（会关闭数据库和 pipe）
        if self.reporter:
            print("[INFO] 停止数据采集...")
            self.reporter.stop()

        print("[INFO] 关闭完成")
        sys.exit(0)

    def signal_handler(self, signum, frame):
        sig_name = signal.Signals(signum).name
        print(f"[INFO] 收到信号 {sig_name}，开始关闭...")
        self.cleanup()

    def kill_existing_processes(self):
        """杀死已存在的中间人进程"""
        pids = os.popen("ps -ef | grep man.py | grep -v grep | awk '{print $2}'").read().strip()
        if pids:
            print(f"[INFO] 停止旧中间人进程: {pids}")
            os.system(f"kill -9 {pids}")
            time.sleep(0.5)

        # 清理残留的 pipe 文件
        pipe_path = self.ctx.PIPE_PATH
        if os.path.exists(pipe_path):
            print(f"[INFO] 清理残留 pipe: {pipe_path}")
            os.remove(pipe_path)

    def start(self):
        # 注册信号处理器
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # 清理旧进程
        self.kill_existing_processes()

        # 启动组件
        self.reporter = Reporter(self.ctx)
        self.reporter.start()

        self.manager = Manager(self.ctx, self.reporter)
        self.manager.start()


if __name__ == "__main__":
    m = Middleman()
    m.start()