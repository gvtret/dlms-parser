import binascii

def bytes_to_hex(data: bytes, sep: str = ' ') -> str:
    return binascii.hexlify(data).decode('ascii') if data else ''

def int_from_bytes(data: bytes, signed: bool = False) -> int:
    return int.from_bytes(data, byteorder='big', signed=signed)

def crc_check(data: bytes) -> int:
    """Calculate CRC-16 for HDLC frames"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc >>= 1
                crc ^= 0x8408
            else:
                crc >>= 1
    return crc

def format_offset(offset: int) -> str:
    return f"0x{offset:04X}"