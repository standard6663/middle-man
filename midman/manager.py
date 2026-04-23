import json
import os
import struct
import subprocess
from midman.context import Context
from midman.reporter import Reporter
from cmdman.cmdman import Command, CommandManager, CommandPacket
from cmdman.cmdpkt import DateType, UpdateData,ErrorData

# PYTHON = '/middleman-venv/bin/python'
PYTHON = '/home/unumtu/Desktop/TLS_middle/middle-man/venv/bin/python'


class Manager:
    def __init__(self, ctx: Context, reporter: Reporter):
        self.ctx = ctx
        self.reporter = reporter
        self.cmdman: CommandManager = None
        self.midman_process: subprocess.Popen = None
        self.stopping = False

    def __del__(self):
        self.__stop_midman()

    def __run_midman(self):
        # write certs to file
        certs_data = f"{self.ctx.INTERMEDIATE_CA_KEY}\n"
        certs_data += f"{self.ctx.INTERMEDIATE_CA_CERT}\n"
        certs_data += f"{self.ctx.ROOT_CA_CERT}\n"
        with open(self.ctx.MIDMAN_CERT_PATH, 'w') as f:
            f.write(certs_data)
        # start midman
        command = f'{PYTHON} ./man.py'
        command += f' --set confdir={self.ctx.MIDMAN_CONF}'
        command += f' --set pipe_path={self.ctx.PIPE_PATH}'
        command += f' --set listen_port={self.ctx.INTERCEPT_PORT}'
        # TLS 1.2 套件：2 个选项
        commands = command.split()
        # 调整 TLS 1.3 套件优先级，让服务端倾向选 AES-128-GCM (0x1302)
        env = os.environ.copy()
        env["SSL_CIPHER_LIST"] = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        with open(self.ctx.MIDMAN_LOG_PATH, "a") as log_file:
            self.midman_process = subprocess.Popen(
                commands,
                stdout=None,
                stderr=subprocess.STDOUT,
                env=env,
            )
        print(f"[INFO] 启动中间人: {command}")

    def stop(self):
        """优雅停止中间人进程"""
        self.stopping = True
        # 关闭 socket 让阻塞的 recv() 抛出异常退出循环
        if self.cmdman and self.cmdman.socket:
            try:
                self.cmdman.socket.close()
            except Exception:
                pass
        if self.midman_process:
            self.midman_process.terminate()
            try:
                self.midman_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.midman_process.kill()
                self.midman_process.wait()
            print("[INFO] 中间人已停止")

    def __send_error_message(self, error_code: int, error_message: str):
        error_data = json.dumps({'code': error_code, 'message': error_message}).encode('utf-8')
        self.cmdman.send(CommandPacket(Command.ERROR, ErrorData(error_data)))

    def __check_runing_param(self) -> bool:
        success = True
        if not self.ctx.MIDMAN_PORT:
            success = False
            self.__send_error_message(int(DateType.PORT), "中间人端口未设置")
        if not (self.ctx.DB_HOST and self.ctx.DB_PORT and self.ctx.DB_NAME and self.ctx.DB_USER and self.ctx.DB_PASSWORD):
            success = False
            self.__send_error_message(int(DateType.DATABSE), "数据库主机未设置")
        if not (self.ctx.ROOT_CA_CERT and self.ctx.INTERMEDIATE_CA_KEY and self.ctx.INTERMEDIATE_CA_CERT):
            success = False
            self.__send_error_message(int(DateType.CERTS), "证书未设置")
        return success

    def cmd_update_handle(self, cmd: CommandPacket):
        data: UpdateData = cmd.data_obj
        data_type = DateType(data.date_type)
        if data_type == DateType.CERTS:
            certs_data: dict = json.loads(data.data.decode('utf-8'))
            self.ctx.ROOT_CA_CERT = certs_data.get('ROOT_CA_CERT')
            self.ctx.INTERMEDIATE_CA_KEY = certs_data.get('INTERMEDIATE_CA_KEY')
            self.ctx.INTERMEDIATE_CA_CERT = certs_data.get('INTERMEDIATE_CA_CERT')
        elif data_type == DateType.PORT:
            self.ctx.MIDMAN_PORT = struct.unpack('<H', data.data)[0]
        elif data_type == DateType.DATABSE:
            db_data: dict = json.loads(data.data.decode('utf-8'))
            self.ctx.DB_HOST = db_data.get('DB_HOST')
            self.ctx.DB_PORT = db_data.get('DB_PORT')
            self.ctx.DB_NAME = db_data.get('DB_NAME')
            self.ctx.DB_USER = db_data.get('DB_USER')
            self.ctx.DB_PASSWORD = db_data.get('DB_PASS')
            self.reporter.update_db()
        else:
            print(f"[ERROR] 未处理的数据类型: {data_type}")

    def cmd_start_handle(self, _):
        if self.__check_runing_param():
            self.__run_midman()
            pass
        else:
            print("[WARN] 中间人启动参数不完整")

    def cmd_stop_handle(self, _):
        self.__stop_midman()

    def start(self):
        self.cmdman = CommandManager(
            self.ctx.MIDMAN_SECRET,
            'midman',
            '0.0.0.0',
            self.ctx.MIDMAN_PORT
        )

        cmd_handlers = {
            Command.UPDATE_DATA: self.cmd_update_handle,
            Command.START: self.cmd_start_handle,
            Command.STOP: self.cmd_stop_handle,
        }

        while not self.stopping:
            try:
                cmd = self.cmdman.receive()
            except (OSError, ValueError, ConnectionResetError, BrokenPipeError):
                # socket 被关闭或连接断开，退出循环
                break
            handle_func = cmd_handlers.get(cmd.command_code)
            if handle_func:
                handle_func(cmd)
            else:
                print(f"[ERROR] 未处理的命令: {cmd.command_code}")
