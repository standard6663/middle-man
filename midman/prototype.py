class PacketType:
    def __init__(self, source_ip: str, source_port: int, destination_ip: str, destination_port: int,
                    cipher_suite: str, payload: bytes, protocol_version: str, packet_size: int, delay: int, timestamp: float,alpn: str,cipher_data: bytes):
            self.source_ip = source_ip
            self.source_port = source_port
            self.destination_ip = destination_ip
            self.destination_port = destination_port
            self.cipher_suite = cipher_suite
            self.payload = payload
            self.brief_payload = payload[:10] + b'...' if len(self.payload) > 10 else self.payload
            self.protocol_version = protocol_version
            self.packet_size = packet_size
            self.delay = delay
            self.timestamp = timestamp
            self.alpn=alpn
            self.cipher_data =cipher_data

    def __repr__(self):
        return f"PacketType(source_ip={self.source_ip}, source_port={self.source_port}, destination_ip={self.destination_ip}, destination_port={self.destination_port}, cipher_suite={self.cipher_suite}, payload={self.payload}, protocol_version={self.protocol_version}, packet_size={self.packet_size}, delay={self.delay}), payload={self.brief_payload})"
    
    def __str__(self):
        return f"PacketType: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}, cipher_suite={self.cipher_suite}, protocol_version={self.protocol_version}, packet_size={self.packet_size}, delay={self.delay}, payload={self.brief_payload}"

