from .base import BaseDecoder
from dlms_parser.utils.dlms_types import DLMS_TAGS, DLMS_DATA_TYPES
from ..utils.helpers import bytes_to_hex, int_from_bytes

class BERDecoder(BaseDecoder):
    def decode(self, data: bytes) -> Tuple[list, dict]:
        root_items = []
        offset = 0
        new_context = {}
        
        while offset < len(data):
            item, offset, context_update = self.decode_tag(data, offset)
            root_items.append(item)
            new_context.update(context_update)
        
        return root_items, new_context
    
    def decode_tag(self, data: bytes, offset: int) -> Tuple[dict, int, dict]:
        context_update = {}
        start_offset = offset
        
        # Read tag
        tag = data[offset]
        offset += 1
        
        # Read length
        length_byte = data[offset]
        offset += 1
        
        if length_byte & 0x80:  # Long form
            num_bytes = length_byte & 0x7f
            length = int_from_bytes(data[offset:offset+num_bytes])
            offset += num_bytes
        else:  # Short form
            length = length_byte
        
        # Get value
        value = data[offset:offset+length]
        
        # Determine tag class and type
        tag_class = (tag >> 6) & 0x03
        constructed = (tag >> 5) & 0x01
        tag_number = tag & 0x1f
        
        # DLMS-specific decoding
        decoded_value, value_type = self.decode_dlms_value(tag_class, tag_number, value, constructed)
        
        # Create item
        item = {
            'name': self.get_dlms_tag_name(tag_class, tag_number),
            'offset': hex(start_offset),
            'length': str(offset + length - start_offset),
            'value': decoded_value,
            'type': value_type,
            'children': []
        }
        
        # Handle constructed types
        if constructed:
            if tag_class == 1 and tag_number == 0:  # AARQ
                item['children'], ctx = self.decode_aarq(value)
                context_update.update(ctx)
            elif tag_class == 1 and tag_number == 1:  # AARE
                item['children'], ctx = self.decode_aare(value)
                context_update.update(ctx)
            else:
                child_items, ctx = self.decode(value)
                item['children'].extend(child_items)
                context_update.update(ctx)
        
        offset += length
        return item, offset, context_update
    
    def decode_dlms_value(self, tag_class: int, tag_number: int, 
                         value: bytes, constructed: bool) -> Tuple[str, str]:
        # Реализация декодирования значений (как в предыдущем коде)
        pass
    
    def decode_aarq(self, data: bytes) -> Tuple[list, dict]:
        # Реализация декодирования AARQ (как в предыдущем коде)
        pass
    
    def decode_aare(self, data: bytes) -> Tuple[list, dict]:
        # Реализация декодирования AARE (как в предыдущем коде)
        pass