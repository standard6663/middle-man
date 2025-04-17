import os
import stat
import json
import time


class PipeWriter:
    def __init__(self, path):
        self.path = path
        if not os.path.exists(self.path):
            raise ValueError(f"路径 '{self.path}' 不存在")
        self.pipe = open(self.path, 'w')

    def write(self, name: str, data):
        """
        写入数据到命名管道，若读取端未就绪则阻塞
        """
        data_json = json.dumps({'name': name, 'data': data})
        self.pipe.write(f"{data_json}\n")
        self.pipe.flush()

    def __del__(self):
        self.pipe.close()


class PipeReader:
    def __init__(self, path):
        self.path = path
        # 确保路径是 FIFO
        if not os.path.exists(self.path):
            os.mkfifo(self.path)
        else:
            if not stat.S_ISFIFO(os.stat(self.path).st_mode):
                raise ValueError(f"路径 '{self.path}' 已存在且不是 FIFO")

    def read_data(self):
        with open(self.path, 'r') as f:
            while True:
                line = f.readline()
                if not line:  # EOF
                    time.sleep(0.1)  # 等待数据
                    continue
                yield json.loads(line.strip())

    def __del__(self):
        if os.path.exists(self.path):
            os.remove(self.path)
