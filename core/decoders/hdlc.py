"""
core/decoders/hdlc.py

Provides the HDLCDecoder class for decoding HDLC (High-Level Data Link Control)
frames. This decoder handles basic HDLC frame parsing, including extracting address,
control, and payload information, and performing a CRC check.
"""
from typing import Tuple, List, Dict, Any # Added for type hinting

from .base import BaseDecoder
from ..utils.helpers import bytes_to_hex, int_from_bytes, crc_check

class HDLCDecoder(BaseDecoder):
    """
    HDLC (High-Level Data Link Control) Frame Decoder.

    Parses HDLC frames, typically used in serial communication and by protocols
    like DLMS/COSEM. It identifies frame boundaries (flags), extracts address,
    control, and information (payload) fields, and validates the Frame Check
    Sequence (FCS/CRC).

    The primary method `decode` expects a byte string that may contain one or more
    HDLC frames. It attempts to find the first complete frame.
    """
    def decode(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the first complete HDLC frame found in the provided byte data.

        Args:
            data: A byte string potentially containing one or more HDLC frames.

        Returns:
            A tuple containing:
            - A list of dictionaries representing the decoded parts of the HDLC frame.
              If an error occurs (e.g., frame too short, no flags), the list will
              contain a single error item.
            - A context dictionary, which includes the extracted 'hdlc_payload'
              if a frame is successfully decoded, and 'hdlc_crc_error' if CRC fails.
        """
        items: List[Dict[str, Any]] = []
        context: Dict[str, Any] = {}
        
        # Minimum HDLC frame length: Flag(1) + Addr(1) + Ctrl(1) + Len(2) + CRC(2) + Flag(1) = 8 bytes.
        # The decoder logic itself checks for content between flags, which implies min 6 bytes for Addr,Ctrl,Len,CRC.
        if len(data) < 8:  # Check based on overall frame including flags.
            items.append({'name': 'Error', 'value': 'Frame too short (less than 8 bytes for flags and minimal content)', 'type': 'Error'})
            return items, context
        
        # Find HDLC frame boundaries (0x7E flags)
        try:
            start_idx = data.find(b'\x7E')
            if start_idx == -1:
                items.append({'name': 'Error', 'value': 'No start flag found', 'type': 'Error'})
                return items, context

            # Look for end flag after the start flag to get the first complete frame
            end_idx = data.find(b'\x7E', start_idx + 1)
            if end_idx == -1:
                items.append({'name': 'Error', 'value': 'No end flag found after start flag', 'type': 'Error'})
                return items, context
        except AttributeError: # Should not happen if data is bytes, but good for robustness
             items.append({'name': 'Error', 'value': 'Invalid input data type for HDLC frame search (expected bytes).', 'type': 'Error'})
             return items, context

        # Extract the frame content (data between the flags)
        # This content includes: Address, Control, Length, Information (Payload), CRC
        frame_content = data[start_idx + 1 : end_idx]
        
        # Minimum length for frame_content: Addr(1) + Ctrl(1) + Length(2) + CRC(2) = 6 bytes.
        # Payload can be empty.
        if len(frame_content) < 6:
            items.append({'name': 'Error', 'value': 'Frame content between flags is too short for essential fields (Addr, Ctrl, Length, CRC).', 'type': 'Error'})
            return items, context

        # Decode the extracted HDLC frame content
        frame_items, context_update = self.decode_hdlc_frame(frame_content)
        items.extend(frame_items)
        context.update(context_update) # Merge context (e.g. hdlc_payload)
        
        return items, context
    
    def decode_hdlc_frame(self, frame_content: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an HDLC frame (data between the start and end flags).

        The frame content is expected to contain:
        Address (1 byte), Control (1 byte), Length (2 bytes),
        Information/Payload (...), and CRC (2 bytes).

        Args:
            frame_content: The byte string of the HDLC frame, excluding the flags.
                           It must contain at least Address, Control, Length, and CRC fields.

        Returns:
            A tuple containing:
            - A list of dictionaries representing decoded parts of the frame.
            - A context dictionary, including 'hdlc_payload' and 'hdlc_crc_error' if CRC fails.
        """
        items: List[Dict[str, Any]] = []
        offset = 0
        context: Dict[str, Any] = {} # Initialize context for this frame

        # Address field (1 byte)
        addr = frame_content[offset]
        items.append({
            'name': 'HDLC Address',
            'value': f'0x{addr:02X}',
            'type': 'Unsigned8',
            'offset': hex(offset), # Offset within frame_content
            'length': '1'
        })
        offset += 1
        
        # Control field (1 byte)
        control = frame_content[offset]
        control_type_str = self.get_control_type(control)
        items.append({
            'name': 'HDLC Control',
            'value': f'0x{control:02X} ({control_type_str})',
            'type': 'Unsigned8',
            'offset': hex(offset),
            'length': '1'
        })
        offset += 1
        
        # Length field (2 bytes, big-endian)
        # This length field in HDLC frames used by DLMS typically includes:
        # Address (1) + Control (1) + Payload (...) + CRC (2)
        hdlc_length_field_val = int_from_bytes(frame_content[offset : offset + 2])
        items.append({
            'name': 'HDLC Length Field', # Value from the actual Length field in the frame
            'value': str(hdlc_length_field_val),
            'type': 'Unsigned16',
            'offset': hex(offset),
            'length': '2'
        })
        offset += 2
        
        # Calculate expected payload length based on the HDLC length field.
        # Payload_Length = HDLC_Length_Field - (Addr_len + Ctrl_len + CRC_len)
        # Addr_len=1, Ctrl_len=1, CRC_len=2. Total non-payload = 4 bytes.
        if hdlc_length_field_val < 4:
            # This indicates a malformed frame as length cannot cover mandatory fields.
            items.append({'name': 'Error',
                          'value': f'HDLC Length field value ({hdlc_length_field_val}) is too small. It must be at least 4 to cover Address, Control, and CRC.',
                          'type': 'Error'})
            payload = b'' # Assume no valid payload
            crc_valid = False # Cannot validate CRC
            context['hdlc_crc_error'] = True
            context['hdlc_payload'] = payload
            # Add a placeholder for payload with error indication in CRC
            items.append({
                'name': 'HDLC Payload', 'value': '', 'type': 'OctetString',
                'offset': hex(offset), 'length': '0',
                'children': [{'name': 'CRC Check', 'value': 'Error: Invalid frame length for payload/CRC calculation', 'type': 'Error'}]
            })
            return items, context # Early exit due to malformed length

        payload_length = hdlc_length_field_val - 4

        # Ensure calculated payload_length matches the remaining frame_content length minus CRC (2 bytes).
        expected_remaining_for_payload_and_crc = len(frame_content) - offset
        if payload_length + 2 != expected_remaining_for_payload_and_crc:
            error_msg = (f"Inconsistent frame length. HDLC Length field implies payload of {payload_length} bytes, "
                         f"but {expected_remaining_for_payload_and_crc} bytes remain for payload and CRC.")
            items.append({'name': 'Error', 'value': error_msg, 'type': 'Error'})
            # Attempt to extract what might be the payload, but flag CRC as error.
            payload = frame_content[offset : len(frame_content) - 2] if expected_remaining_for_payload_and_crc > 2 else b''
            crc_valid = False
            context['hdlc_crc_error'] = True
            context['hdlc_payload'] = payload
            items.append({
                'name': 'HDLC Payload', 'value': bytes_to_hex(payload), 'type': 'OctetString',
                'offset': hex(offset), 'length': str(len(payload)),
                'children': [{'name': 'CRC Check', 'value': 'Error: Inconsistent frame length for payload/CRC calculation', 'type': 'Error'}]
            })
            return items, context # Early exit

        payload = frame_content[offset : offset + payload_length]
        
        # CRC field (last 2 bytes of frame_content)
        # The data over which CRC is calculated is frame_content *excluding* the CRC itself.
        # This is: Address + Control + LengthField + Payload.
        data_for_crc_calc = frame_content[:-2]
        crc_from_frame = int_from_bytes(frame_content[-2:])
        calculated_crc = crc_check(data_for_crc_calc) # Assumes crc_check uses CRC-16 CCITT (common for DLMS)
        crc_valid = (crc_from_frame == calculated_crc)
        
        items.append({
            'name': 'HDLC Payload',
            'value': bytes_to_hex(payload), # Display payload as hex
            'type': 'OctetString',
            'offset': hex(offset),
            'length': str(payload_length),
            'children': [{ # Child item for CRC information
                'name': 'CRC Check',
                'value': f'0x{crc_from_frame:04X} ({"Valid" if crc_valid else f"Invalid, expected 0x{calculated_crc:04X}"})',
                'type': 'Unsigned16'
            }]
        })
        # offset += payload_length # Offset is now at the start of CRC, which is end of frame_content for practical purposes here.
        
        context['hdlc_payload'] = payload # Store the raw payload bytes
        if not crc_valid:
            context['hdlc_crc_error'] = True # Signal CRC error in context

        return items, context
    
    def get_control_type(self, control: int) -> str:
        """
        Determines the HDLC control field type (I-Frame, S-Frame, U-Frame)
        based on the control byte value.

        Args:
            control: The HDLC control byte.

        Returns:
            A string indicating the frame type ("I-Frame", "S-Frame", "U-Frame",
            or "Unknown" if the pattern doesn't match standard HDLC types).
        """
        # Check for I-Frame (Information frame): Bit 0 is 0
        if control & 0x01 == 0:
            return "I-Frame"
        # Check for S-Frame (Supervisory frame): Bits 1-0 are 01 (binary)
        elif control & 0x03 == 0x01: # Check bits 1 and 0 together
            return "S-Frame"
        # Check for U-Frame (Unnumbered frame): Bits 1-0 are 11 (binary)
        elif control & 0x03 == 0x03: # Check bits 1 and 0 together
            return "U-Frame"
        # If none of the above, it's an unknown or reserved type
        return "Unknown"