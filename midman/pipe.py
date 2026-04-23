import os
import stat
import json
import time
import base64
import threading
import queue
import gc

# 全局追踪器
_pipe_writer_instances = 0
_pipe_writer_max = 0


class PipeWriter:
    def __init__(self, path, maxsize=10000):
        global _pipe_writer_instances, _pipe_writer_max
        _pipe_writer_instances += 1
        _pipe_writer_max = max(_pipe_writer_max, _pipe_writer_instances)

        self.path = path
        if not os.path.exists(self.path):
            raise ValueError(f"路径 '{self.path}' 不存在")
        self.pipe = open(self.path, 'w')
        self._queue = queue.Queue(maxsize=maxsize)
        self._closed = False
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()

    def _writer_loop(self):
        """后台线程：从队列取出数据写入管道"""
        while not self._closed:
            try:
                data = self._queue.get(timeout=0.1)
                if data is None:  # 关闭信号
                    break
                self.pipe.write(data)
                self.pipe.flush()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[WARN] PipeWriter 写入失败: {e}")
                time.sleep(0.01)

    def close(self):
        """关闭 writer，等待队列清空后退出后台线程"""
        global _pipe_writer_instances
        _pipe_writer_instances -= 1
        self._closed = True
        self._queue.put(None)  # 发送关闭信号
        self._thread.join(timeout=1.0)
        self.pipe.close()

    def __del__(self):
        self.close()

    def write(self, name: str, data):
        """
        写入数据到队列，后台线程异步写入管道，不阻塞
        """
        if self._closed:
            return
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                data = base64.b64encode(data).decode('utf-8')
        data_json = json.dumps({'name': name, 'data': data}) + '\n'
        try:
            self._queue.put_nowait(data_json)
        except queue.Full:
            print("[WARN] PipeWriter 队列满，丢弃数据")


def get_pipe_writer_stats():
    """获取 PipeWriter 统计信息"""
    global _pipe_writer_instances, _pipe_writer_max
    # 强制垃圾回收，触发 __del__
    gc.collect()
    return {
        "current_instances": _pipe_writer_instances,
        "max_instances": _pipe_writer_max,
    }


class PipeReader:
    def __init__(self, path):
        self.path = path
        if os.path.exists(self.path):
            os.remove(self.path)
        os.mkfifo(self.path)

        self.buffer = []
        self.pipe = None
        self._closed = False

    def stop(self):
        """停止读取数据"""
        self._closed = True
        if self.pipe:
            try:
                self.pipe.close()
            except Exception:
                pass
        if os.path.exists(self.path):
            try:
                os.remove(self.path)
            except Exception:
                pass

    def __del__(self):
        self.stop()

    def get_data_from_pipe(self):
        while not self._closed:
            try:
                line = self.pipe.readline()
                if not line:
                    break
                yield json.loads(line.strip())
            except Exception:
                if not self._closed:
                    time.sleep(0.01)
                continue

    def read_data(self):
        if self.pipe is None:
            self.pipe = open(self.path, 'r')
        data_generator = self.get_data_from_pipe()
        while not self._closed:
            try:
                self.buffer = [next(data_generator)] + self.buffer
            except StopIteration:
                break
            if len(self.buffer) == 0:
                time.sleep(0.01)
            while len(self.buffer) > 0 and not self._closed:
                yield self.buffer.pop(0)

    def retry_data(self, data):
        self.buffer.append(data)

