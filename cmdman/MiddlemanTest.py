import struct
from cmdpkt import CommandPacket, Command, DateType, UpdateData
from cmdman import CommandManager

def g_finished(control: CommandManager, cmd: bytes):
    cmd_pkt = CommandPacket.from_bytes(cmd)
    command_code = cmd_pkt.command_code
    # 发送数据
    control.send(cmd_pkt)
    # 检查数据类型是否正确
    if command_code == Command.REQUEST_DATA:
        receive_cmd_pkt = control.receive
        if cmd_pkt.data_obj.date_type != receive_cmd_pkt.data_obj.date_type:
            raise ValueError("请求数据类型不一致")
    control.socket.close()

def m_finished(control: CommandManager):
    # 接收数据
    receive_cmd_pkt = control.receive()
    command_code = receive_cmd_pkt.command_code
    
    if command_code == Command.REQUEST_DATA: # 请求数据
        date_type = receive_cmd_pkt.data_obj.date_type
        data = getattr(control, date_type.name)
        cmd_pkt = CommandPacket(Command.UPDATE_DATA, UpdateData(date_type, data))
        control.send(cmd_pkt)
    elif command_code == Command.UPDATE_DATA: # 更新数据，不需要回复消息
        date_type = receive_cmd_pkt.date_type
        data = receive_cmd_pkt.data
        setattr(control, date_type, data)
    control.socket.close()

if __name__ == "__main__":
    midman = CommandManager(b'secret', 'midman', '127.0.0.1', 12345)
    midman.ROOT_CA_CERT = b'12345678'
    m_finished(midman)
    print("finished")