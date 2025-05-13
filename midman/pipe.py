import os
import stat
import json
import time
import base64


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
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                data = base64.b64encode(data).decode('utf-8')
        # print(f"[TODO] 写入: {name} - {data}")
        data_json = json.dumps({'name': name, 'data': data})
        self.pipe.write(f"{data_json}\n")
        self.pipe.flush()

    def __del__(self):
        self.pipe.close()


class PipeReader:
    def __init__(self, path):
        self.path = path
        if os.path.exists(self.path):
            os.remove(self.path)
        os.mkfifo(self.path)
        
        self.buffer = []
        self.pipe = None

    def __del__(self):
        self.pipe.close()
        os.remove(self.path)

    def get_data_from_pipe(self):
        while True:
            line = self.pipe.readline()
            if not line:  
                break
            yield json.loads(line.strip())

    def read_data(self):
        if self.pipe is None:
            self.pipe = open(self.path, 'r')
        data_generator = self.get_data_from_pipe()
        while True:
            self.buffer = [next(data_generator)] + self.buffer
            if len(self.buffer) == 0:
                time.sleep(0.01) # Sleep for a short time to avoid busy waiting
            while len(self.buffer) > 0:
                yield self.buffer.pop(0)
                
    def retry_data(self, data):
        self.buffer.append(data)

    def __del__(self):
        if os.path.exists(self.path):
            os.remove(self.path)

