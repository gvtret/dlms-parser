from .base import BaseDecoder
from ..utils.helpers import bytes_to_hex, int_from_bytes, crc_check

class HDLCDecoder(BaseDecoder):
    def decode(self, data: bytes) -> Tuple[list, dict]:
        items = []
        
        # Check minimum length
        if len(data) < 8:  # 1B flag + 1B addr + 2B control + 2B length + 2B CRC
            return [{'name': 'Error', 'value': 'Frame too short', 'type': 'Error'}], {}
        
        # Find frame boundaries (0x7E flags)
        start_idx = data.find(b'\x7E')
        if start_idx == -1:
            return [{'name': 'Error', 'value': 'No start flag found', 'type': 'Error'}], {}
        
        end_idx = data.rfind(b'\x7E')
        if end_idx == start_idx:
            return [{'name': 'Error', 'value': 'No end flag found', 'type': 'Error'}], {}
        
        frame = data[start_idx+1:end_idx]
        
        # Decode HDLC frame
        frame_items, context = self.decode_hdlc_frame(frame)
        items.extend(frame_items)
        
        return items, context
    
    def decode_hdlc_frame(self, frame: bytes) -> Tuple[list, dict]:
        items = []
        offset = 0
        
        # Address field
        addr = frame[offset]
        items.append({
            'name': 'HDLC Address',
            'value': f'0x{addr:02X}',
            'type': 'Unsigned8',
            'offset': hex(offset),
            'length': '1'
        })
        offset += 1
        
        # Control field
        control = frame[offset]
        control_type = self.get_control_type(control)
        items.append({
            'name': 'HDLC Control',
            'value': f'0x{control:02X} ({control_type})',
            'type': 'Unsigned8',
            'offset': hex(offset),
            'length': '1'
        })
        offset += 1
        
        # Length field (optional, depends on format)
        length = int_from_bytes(frame[offset:offset+2])
        items.append({
            'name': 'HDLC Length',
            'value': str(length),
            'type': 'Unsigned16',
            'offset': hex(offset),
            'length': '2'
        })
        offset += 2
        
        # Information field (payload)
        payload_length = length - 4  # Subtract addr(1) + control(1) + CRC(2)
        payload = frame[offset:offset+payload_length]
        
        # Check CRC
        crc = int_from_bytes(frame[-2:])
        calculated_crc = crc_check(frame[:-2])
        crc_valid = crc == calculated_crc
        
        items.append({
            'name': 'HDLC Payload',
            'value': bytes_to_hex(payload),
            'type': 'OctetString',
            'offset': hex(offset),
            'length': str(payload_length),
            'children': [{
                'name': 'CRC Check',
                'value': f'0x{crc:04X} ({"Valid" if crc_valid else "Invalid"})',
                'type': 'Unsigned16'
            }]
        })
        offset += payload_length
        
        # Return payload for further decoding
        context = {'hdlc_payload': payload}
        return items, context
    
    def get_control_type(self, control: int) -> str:
        if control & 0x01 == 0:
            return "I-Frame"  # Information frame
        elif control & 0x03 == 1:
            return "S-Frame"  # Supervisory frame
        elif control & 0x03 == 3:
            return "U-Frame"  # Unnumbered frame
        return "Unknown"