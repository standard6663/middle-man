# Delay 字段说明

## 定义

`delay` = 中间人发送密文的时间 - 中间人收到密文的时间，表示密文在中间人处的处理/转发延迟。

## 时序图

```
客户端  ──────────────►  中间人  ──────────────►  服务器

  发送密文 ──────────► │
                       │ ts_start (中间人收到)
                       │
                       │    delay = ts_end - ts_start
                       │
                       │ ts_end (中间人发送) ──────► 收到密文

◄───── delay (ms) ─────►
= ts_end - ts_start
```

## 变量说明

| 变量 | 含义 | 来源 |
|------|------|------|
| `ts_start` | 中间人**收到**密文的时间戳 | `conn.cipher_recv_tss` |
| `ts_end` | 中间人**发送**密文的时间戳 | `to_conn.cipher_send_tss` |
| `delay` | `ts_end - ts_start`（毫秒） | 处理延迟 |

## 代码位置

参考 [midman/reporter.py:241-256](midman/reporter.py#L241-L256)：

```python
if ts_start and ts_end:
    pkt = PacketType(
        ...
        delay=(ts_end - ts_start) * 1000,  # 转换为毫秒
        ...
    )
```

## 含义

正值表示中间人收到密文到转发密文的处理时间。值越大，说明密文在中间人处的处理/等待时间越长。
