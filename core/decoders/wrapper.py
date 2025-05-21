from .base import BaseDecoder
from ..utils.helpers import bytes_to_hex, int_from_bytes

class WrapperDecoder(BaseDecoder):
    def decode(self, data: bytes) -> Tuple[list, dict]:
        items = []
        
        # Check minimum length
        if len(data) < 8:  # 1B version + 1B src/dest + 2B length + 2B CRC + 1B sep + 1B end
            return [{'name': 'Error', 'value': 'Wrapper too short', 'type': 'Error'}], {}
        
        offset = 0
        
        # Version field
        version = data[offset]
        items.append({
            'name': 'Wrapper Version',
            'value': f'0x{version:02X}',
            'type': 'Unsigned8',
            'offset': hex(offset),
            'length': '1'
        })
        offset += 1
        
        # Source/Destination address
        src_dest = data[offset]
        items.append({
            'name': 'Source/Destination',
            'value': f'0x{src_dest:02X}',
            'type': 'Unsigned8',
            'offset': hex(offset),
            'length': '1'
        })
        offset += 1
        
        # Length field
        length = int_from_bytes(data[offset:offset+2])
        items.append({
            'name': 'Wrapper Length',
            'value': str(length),
            'type': 'Unsigned16',
            'offset': hex(offset),
            'length': '2'
        })
        offset += 2
        
        # Payload
        payload_length = length - 6  # Subtract version(1) + src/dest(1) + length(2) + CRC(2)
        payload = data[offset:offset+payload_length]
        items.append({
            'name': 'Wrapper Payload',
            'value': bytes_to_hex(payload),
            'type': 'OctetString',
            'offset': hex(offset),
            'length': str(payload_length)
        })
        offset += payload_length
        
        # CRC
        crc = int_from_bytes(data[offset:offset+2])
        items.append({
            'name': 'Wrapper CRC',
            'value': f'0x{crc:04X}',
            'type': 'Unsigned16',
            'offset': hex(offset),
            'length': '2'
        })
        offset += 2
        
        # Return payload for further decoding
        context = {'wrapper_payload': payload}
        return items, context