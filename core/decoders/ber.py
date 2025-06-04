"""
core/decoders/ber.py

Provides the BERDecoder class for decoding ASN.1 BER (Basic Encoding Rules)
encoded data. This decoder is particularly focused on parsing DLMS/COSEM APDUs
like AARQ (Association Request) and AARE (Association Response), as well as
common universal ASN.1 types.
"""
from typing import Tuple, List, Dict, Any # Added typing imports
import binascii # For OID parsing or other conversions if needed. bytes_to_hex is from helpers.

from .base import BaseDecoder
# DLMS_TAGS maps tag values to human-readable names for better output.
from dlms_parser.utils.dlms_types import DLMS_TAGS
from ..utils.helpers import bytes_to_hex, int_from_bytes
# Import AxdrDecoder for compact-array content decoding
from .axdr import AxdrDecoder
import io # For io.BytesIO when using AxdrDecoder

# Universal Tag Numbers constants for ASN.1 types
UNIVERSAL_BOOLEAN = 1
UNIVERSAL_INTEGER = 2
UNIVERSAL_BIT_STRING = 3
UNIVERSAL_OCTET_STRING = 4
UNIVERSAL_NULL = 5
UNIVERSAL_OBJECT_IDENTIFIER = 6
UNIVERSAL_ENUMERATED = 10
UNIVERSAL_UTF8_STRING = 12
UNIVERSAL_SEQUENCE = 16
UNIVERSAL_PRINTABLE_STRING = 19
UNIVERSAL_VISIBLE_STRING = 26
# Other universal tags can be added here if needed.

class BERDecoder(BaseDecoder):
    """
    ASN.1 BER (Basic Encoding Rules) Decoder.

    This class decodes byte data encoded according to BER rules. It can parse
    common universal ASN.1 types (Integer, Boolean, Octet String, OID, etc.)
    and is specialized to understand the structure of DLMS/COSEM APDUs like
    AARQ (Association Request) and AARE (Association Response).
    It also handles DLMS Data CHOICE types like array, structure, and compact-array.

    The main method is `decode()`, which takes a byte string and returns a list
    of decoded items, each represented as a dictionary. For constructed types
    (like SEQUENCEs or APDUs), the dictionary will contain a 'children' key
    with a list of nested decoded items.
    """
    def __init__(self, axdr_decoder: AxdrDecoder = None):
        """
        Initializes the BERDecoder.
        Args:
            axdr_decoder: Optional. An instance of AxdrDecoder. If not provided,
                          a default one will be created for compact-array decoding.
        """
        self.axdr_decoder = axdr_decoder if axdr_decoder is not None else AxdrDecoder()

    def _parse_oid(self, value: bytes) -> str:
        """
        Helper method to parse OBJECT IDENTIFIER value bytes into a dot-notation string.

        Args:
            value: The byte string representing the OID's content octets.

        Returns:
            A string representation of the OID in dot notation (e.g., "1.3.6.1.4.1").
            Returns an empty string if the input value is empty.
        """
        oid_parts: List[str] = []
        if not value:
            return ""

        # First OID component from the first byte
        first_byte = value[0]
        oid_parts.append(str(first_byte // 40))
        oid_parts.append(str(first_byte % 40))

        # Subsequent OID components from remaining bytes (if any)
        current_component_value = 0
        for i in range(1, len(value)):
            byte_val = value[i]
            current_component_value = (current_component_value << 7) | (byte_val & 0x7F)
            if not (byte_val & 0x80):  # Check if the most significant bit is 0 (end of this component)
                oid_parts.append(str(current_component_value))
                current_component_value = 0 # Reset for the next component
        return ".".join(oid_parts)

    def decode(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes a complete BER PDU (Protocol Data Unit).

        This method iterates through the provided byte data, decoding each top-level
        BER TLV (Tag-Length-Value) structure it finds.

        Args:
            data: The byte string containing the BER-encoded PDU.

        Returns:
            A tuple containing:
            - A list of dictionaries, where each dictionary represents a decoded
              BER item. For constructed types, items will have a 'children' key.
            - A dictionary for any context collected or updated during decoding
              (currently, this is always an empty dictionary).
        """
        root_items: List[Dict[str, Any]] = []
        offset = 0
        new_context: Dict[str, Any] = {} # For potential future use, e.g. context from an APDU
        
        while offset < len(data):
            try:
                item, next_offset, item_context = self.decode_tag(data, offset)
                root_items.append(item)
                # new_context.update(item_context) # Currently item_context is always {}

                if next_offset <= offset :
                    # This safety break should ideally not be hit if TLV parsing is correct.
                    # It indicates an issue like zero-length TLV not advancing offset,
                    # or an error in offset calculation within decode_tag.
                    error_detail = "BERDecoder.decode: Offset did not advance properly."
                    if offset == next_offset and item.get('value_length', -1) == 0 and item.get('total_TLV_length', 0) > 0:
                        # This specific case might occur with a correctly parsed zero-length value (e.g. NULL tag)
                        # but indicates decode_tag might not have returned the offset *after* the item.
                        print(f"Warning: Offset stuck at {offset} after parsing zero-length item: {item.get('name')}. Check decode_tag offset logic.")
                        # Attempt a minimal advance to try to prevent an infinite loop, though parsing state might be compromised.
                        offset += item.get('total_TLV_length', 1)
                        if offset >= len(data): break # Exit if advanced past end of data
                        continue

                    print(f"Error: {error_detail} Current: {offset}, Next: {next_offset}. Item: {item.get('name')}. Halting.")
                    root_items.append({'name': "PARSING_ERROR", 'error': error_detail, 'offset': hex(offset)})
                    break
                offset = next_offset
            except Exception as e:
                import traceback
                traceback.print_exc() # Print full stack trace for better debugging
                error_item = {
                    'name': "PARSING_ERROR", 'error': str(e), 'offset': hex(offset),
                    'remaining_data_hex': bytes_to_hex(data[offset:])
                }
                root_items.append(error_item)
                print(f"BER Decoding Error: {e} at offset {offset}. Halting.")
                break
        
        return root_items, new_context

    def decode_tag(self, data: bytes, offset: int,
                   parent_expected_tags_for_child: Dict[int, str] = None) -> Tuple[Dict[str, Any], int, Dict[str, Any]]:
        """
        Decodes a single BER TLV (Tag-Length-Value) structure.

        Args:
            data: The byte string containing BER data.
            offset: The current starting offset in `data` to begin decoding this TLV.
            parent_expected_tags_for_child: Optional. A dictionary mapping context-specific
                                            tag numbers to names, provided by a parent
                                            constructed type (like AARQ/AARE) to help name
                                            its children.

        Returns:
            A tuple containing:
            - A dictionary representing the decoded BER item.
            - The new offset in `data` after this TLV has been parsed.
            - A context dictionary (currently always empty).

        Raises:
            IndexError: If data is insufficient for parsing TLV components.
            ValueError: If an invalid BER length encoding is encountered.
            NotImplementedError: If long-form tag numbers (tag_number=31) are encountered.
        """
        context_update: Dict[str, Any] = {}
        start_offset = offset
        
        # 1. Decode Tag
        if offset >= len(data): raise IndexError("Not enough data for tag byte.")
        tag_byte = data[offset]; offset += 1
        
        tag_class = (tag_byte >> 6) & 0x03      # Bits 8-7: Class (Universal, App, Context, Private)
        constructed = (tag_byte >> 5) & 0x01    # Bit 6: Constructed (1) or Primitive (0)
        tag_number = tag_byte & 0x1f            # Bits 5-1: Tag number
        
        if tag_number == 0x1f: # Indicates tag number is > 30 and uses subsequent bytes
            # This is a simplified decoder; multi-byte tag numbers are not supported.
            raise NotImplementedError("Long-form tag numbers (tag_number=31) are not supported.")

        # 2. Decode Length
        if offset >= len(data): raise IndexError("Not enough data for length byte.")
        length_byte = data[offset]; offset += 1

        length: int
        num_length_bytes_val = 0 # Number of bytes used for the length field itself (after the first length byte)
        if length_byte & 0x80:  # Long form: MSB of first length octet is 1
            num_length_bytes_val = length_byte & 0x7f # Lower 7 bits indicate number of subsequent length octets
            if not (0 < num_length_bytes_val <= 4): # 0 means indefinite form (not handled); >4 is usually too large / impractical
                raise ValueError(f"Invalid number of BER length bytes: {num_length_bytes_val}. (0 indicates indefinite form, >4 often unsupported).")
            if offset + num_length_bytes_val > len(data):
                raise IndexError("Insufficient data for long-form length bytes.")
            length = int_from_bytes(data[offset : offset + num_length_bytes_val])
            offset += num_length_bytes_val
        else:  # Short form: MSB is 0, length is in lower 7 bits
            length = length_byte
        
        # 3. Decode Value
        # Check if the decoded length would cause an overrun on the input data for the value part
        if offset + length > len(data):
            raise IndexError(f"Decoded length {length} exceeds available data {len(data) - offset} at offset {offset}.")
        
        value_bytes = data[offset : offset + length]
        
        # Decode the value bytes into a Python type and a type string
        decoded_value, value_type_str = self.decode_dlms_value(tag_class, tag_number, value_bytes, bool(constructed))
        
        # Determine a human-readable name for the item
        item_name = self.get_dlms_tag_name(tag_class, tag_number, value_type_str, parent_expected_tags_for_child)

        item: Dict[str, Any] = {
            'name': item_name,
            'tag_raw': hex(tag_byte),
            'offset': hex(start_offset),
            'length_of_length_field': (1 + num_length_bytes_val), # Includes the first length byte plus any subsequent ones
            'value_length': length,                               # Length of the Value part
            'total_TLV_length': (offset + length - start_offset), # Total length of this Tag-Length-Value structure
            'value': decoded_value,                               # Python representation of the value
            'raw_value_hex': bytes_to_hex(value_bytes),           # Hex string of the raw value bytes
            'type': value_type_str,                               # String describing the ASN.1 type
            'constructed': bool(constructed),
            'children': []                                        # For constructed types
        }
        
        # 4. Handle Children for Constructed Types
        if constructed:
            item.pop('children_note', None) # Remove any prior placeholder notes

            if tag_class == 1 and tag_number == 0:  # AARQ APDU (Application Class, Tag 0)
                item['name'] = "AARQ-apdu" # Override name for clarity
                item['children'], ctx_aarq = self.decode_aarq(value_bytes)
                context_update.update(ctx_aarq) # context_update is currently not used significantly
            elif tag_class == 1 and tag_number == 1:  # AARE APDU (Application Class, Tag 1)
                item['name'] = "AARE-apdu" # Override name
                item['children'], ctx_aare = self.decode_aare(value_bytes)
                context_update.update(ctx_aare)
            elif tag_class == 1 and tag_number == 2:  # RLRQ APDU (Application Class, Tag 2)
                item['name'] = "RLRQ-apdu"
                item['children'], ctx_rlrq = self.decode_rlrq(value_bytes)
                context_update.update(ctx_rlrq)
            elif tag_class == 1 and tag_number == 3:  # RLRE APDU (Application Class, Tag 3)
                item['name'] = "RLRE-apdu"
                item['children'], ctx_rlre = self.decode_rlre(value_bytes)
                context_update.update(ctx_rlre)
            # DLMS Data CHOICE: array [1] and structure [2] are context-specific, constructed.
            # These tags are used within the `Data ::= CHOICE { ... }` structure in DLMS.
            elif tag_class == 2 and tag_number == 1 and constructed: # Data array: [CONTEXT 1] IMPLICIT SEQUENCE OF Data
                # The name "Data-array" or similar could be set here if DLMS_TAGS has an entry for (2,1)
                # Otherwise, get_dlms_tag_name will use the value_type_str or fallback.
                # We explicitly set type to "array" for clarity in output.
                item['type'] = "array"
                # The 'value' for a constructed array itself isn't the elements, but a placeholder. Children hold elements.
                item['value'] = f"[Array of {len(value_bytes)} bytes content]"
                # Children are a sequence of 'Data' elements. No specific parent_expected_tags for the elements themselves here,
                # as each 'Data' element is self-describing via its own tag.
                child_items, child_ctx, _ = self._decode_tags_from_data(value_bytes, parent_expected_tags_for_child=None)
                item['children'].extend(child_items)
                context_update.update(child_ctx)
            elif tag_class == 2 and tag_number == 2 and constructed: # Data structure: [CONTEXT 2] IMPLICIT SEQUENCE OF Data
                item['type'] = "structure"
                item['value'] = f"[Structure of {len(value_bytes)} bytes content]"
                child_items, child_ctx, _ = self._decode_tags_from_data(value_bytes, parent_expected_tags_for_child=None)
                item['children'].extend(child_items)
                context_update.update(child_ctx)
            elif tag_class == 2 and tag_number == 19 and constructed: # Compact Array: [CONTEXT 19] IMPLICIT SEQUENCE
                item['type'] = "compact-array"
                item['value'] = "[Compact Array Contents]" # Placeholder, actual decoded elements go into 'decoded_elements'

                # The value_bytes of a compact-array is a BER-encoded SEQUENCE of two elements:
                # 1. contents-description ::= [0] IMPLICIT TypeDescription (CHOICE of NULL tagged types)
                # 2. array-contents       ::= [1] IMPLICIT OCTET STRING (A-XDR encoded)

                # We parse these two elements from value_bytes.
                # Expected tags for children of compact-array:
                compact_array_children_def = {0: "contents-description [0]", 1: "array-contents [1]"}
                parsed_children, _, _ = self._decode_tags_from_data(value_bytes, parent_expected_tags_for_child=compact_array_children_def)
                item['children'] = parsed_children # Store the BER structure of contents-description and array-contents

                element_type_str = "unknown"
                raw_axdr_contents_bytes = b""

                if len(parsed_children) == 2:
                    desc_item = parsed_children[0]
                    contents_item = parsed_children[1]

                    # Ensure the children are what we expect for compact-array structure
                    if desc_item['name'] == "contents-description [0]" and desc_item['tag_raw'].startswith("a0"): # Context [0], Constructed
                        # The value of contents-description is another TLV (the TypeDescription CHOICE)
                        # _decode_type_description expects the raw bytes of this inner TLV.
                        type_desc_tlv_bytes = binascii.unhexlify(desc_item['raw_value_hex'])
                        try:
                            element_type_str = self._decode_type_description(type_desc_tlv_bytes)
                            # Add resolved type to the description item for clarity in output
                            desc_item['resolved_element_type'] = element_type_str
                        except Exception as e:
                            desc_item['decoding_error'] = f"Failed to decode TypeDescription: {str(e)}"
                            item['decoding_error'] = "Compact-array TypeDescription decoding failed."
                    else:
                        item['decoding_error'] = "Missing or incorrect 'contents-description' in compact-array."

                    if contents_item['name'] == "array-contents [1]" and contents_item['tag_raw'].startswith("81"): # Context [1], Primitive
                        # The value of array-contents is an OCTET STRING, whose *value* is the A-XDR bytes.
                        # contents_item['value'] should be the bytes from the OCTET STRING.
                        if isinstance(contents_item['value'], bytes):
                            raw_axdr_contents_bytes = contents_item['value']
                        else:
                             item['decoding_error'] = f"array-contents expected bytes, got {type(contents_item['value'])}."
                             print(f"Warning: array-contents value was not bytes: {type(contents_item['value'])} for item: {contents_item}")
                    else:
                        # If error not already set, set it.
                        item.setdefault('decoding_error', "Missing or incorrect 'array-contents' in compact-array.")
                else:
                     item['decoding_error'] = f"Compact-array expected 2 children (description, contents), got {len(parsed_children)}."

                item['element_type'] = element_type_str # Store the determined A-XDR element type string
                item['raw_array_contents_hex'] = bytes_to_hex(raw_axdr_contents_bytes) # Store hex of A-XDR data

                # If element type was successfully determined and there are contents, decode them
                if element_type_str != "unknown" and raw_axdr_contents_bytes and 'decoding_error' not in item:
                    try:
                        item['decoded_elements'] = self._decode_compact_array_elements_axdr(raw_axdr_contents_bytes, element_type_str)
                    except Exception as e:
                        item['decoding_error'] = f"Failed to A-XDR decode compact array elements: {str(e)}"
                        item['decoded_elements'] = [f"Error: {str(e)}"] # Put error in elements list
                else:
                    item['decoded_elements'] = [] # No elements if type unknown or no content or previous error

            elif value_bytes: # Other generic constructed types (e.g., Universal SEQUENCE, SET)
                try:
                    # Parse children using _decode_tags_from_data.
                    # For universal SEQUENCE/SET, children are standard tags, so no parent_expected_tags needed here.
                    child_items, child_ctx, _ = self._decode_tags_from_data(value_bytes, parent_expected_tags_for_child=None)
                    item['children'].extend(child_items)
                    context_update.update(child_ctx)
                except Exception as e:
                    item['children_error'] = f"Failed to decode children of constructed type: {str(e)}"
            else:
                # Constructed type with empty value (e.g., an empty SEQUENCE)
                item['children_note'] = "Constructed type with empty value."
        
        offset += length # Advance offset past the current item's value
        return item, offset, context_update

    def _decode_tags_from_data(self, data: bytes, parent_expected_tags_for_child: Dict[int, str] = None) -> Tuple[List[Dict[str,Any]], Dict[str,Any], int]:
        """
        Helper to decode a sequence of BER TLV items from 'data' bytes.
        This is typically used to parse the content of a constructed type (like a SEQUENCE).

        Args:
            data: The byte string which is the content of a constructed type.
            parent_expected_tags_for_child: Optional. A map from context-specific tag numbers
                                            to names, used if 'data' represents a structure
                                            with context-specifically tagged children (e.g., AARQ fields).

        Returns:
            A tuple containing:
            - A list of decoded child items (each a dictionary).
            - A context dictionary (currently unused).
            - The total number of bytes read from 'data'.
        """
        children: List[Dict[str, Any]] = []
        current_offset_in_data = 0
        context_from_children: Dict[str, Any] = {}

        while current_offset_in_data < len(data):
            try:
                # Pass parent_expected_tags for naming context-specific children correctly
                item, next_offset_in_data, item_ctx = self.decode_tag(data, current_offset_in_data, parent_expected_tags_for_child=parent_expected_tags_for_child)
                children.append(item)
                # context_from_children.update(item_ctx) # item_ctx is currently always {}

                if next_offset_in_data <= current_offset_in_data:
                    # Safety break if offset within the child data doesn't advance
                    print(f"Error in _decode_tags_from_data: Offset did not advance. Current: {current_offset_in_data}, Next: {next_offset_in_data}. Child item: {item.get('name')}")
                    children.append({
                        'name': "CHILD_PARSING_ERROR", 'error': "Offset stuck in child parsing loop",
                        'offset_in_parent_value': hex(current_offset_in_data)
                    })
                    break
                current_offset_in_data = next_offset_in_data
            except Exception as e:
                error_msg = f"Error decoding child elements within _decode_tags_from_data: {str(e)}"
                print(error_msg)
                children.append({
                    'name': "CHILD_PARSING_ERROR", 'error': error_msg,
                    'offset_in_parent_value': hex(current_offset_in_data),
                    'remaining_child_data_hex': bytes_to_hex(data[current_offset_in_data:])
                })
                break # Stop parsing further children on error

        return children, context_from_children, current_offset_in_data

    def decode_dlms_value(self, tag_class: int, tag_number: int, 
                         value: bytes, constructed: bool) -> Tuple[Any, str]:
        """
        Decodes the raw value bytes of a BER TLV into a Python object and a type string.

        Args:
            tag_class: The class of the BER tag (Universal, Application, etc.).
            tag_number: The number of the BER tag.
            value: The raw byte string representing the value part of the TLV.
            constructed: Boolean indicating if the tag is marked as constructed.

        Returns:
            A tuple containing:
            - The decoded Python object (e.g., int, bool, str, bytes, or a descriptive string for complex types).
            - A string representing the ASN.1 type (e.g., "INTEGER", "OCTET STRING", "APPLICATION_0").
        """
        value_hex = bytes_to_hex(value) # For fallback or error display

        if tag_class == 0: # Universal Class
            if tag_number == UNIVERSAL_BOOLEAN:
                # BER: False is 0x00, True is any non-zero (typically 0xFF for DLMS)
                return value[0] != 0x00 if value else False, "BOOLEAN"
            elif tag_number == UNIVERSAL_INTEGER:
                return int_from_bytes(value, signed=True), "INTEGER"
            elif tag_number == UNIVERSAL_BIT_STRING:
                # The first byte of the value indicates the number of unused bits in the last content octet.
                if value:
                    unused_bits = value[0]
                    # Return the actual bit data (value[1:]) as hex, prefixed with unused bit info.
                    return f"UnusedBits:{unused_bits} Data:{bytes_to_hex(value[1:])}", "BIT STRING"
                return "", "BIT STRING" # Empty bit string
            elif tag_number == UNIVERSAL_OCTET_STRING:
                return value, "OCTET STRING" # Return as raw bytes
            elif tag_number == UNIVERSAL_NULL:
                return None, "NULL" # Value part should be empty for NULL.
            elif tag_number == UNIVERSAL_OBJECT_IDENTIFIER:
                return self._parse_oid(value), "OBJECT IDENTIFIER"
            elif tag_number == UNIVERSAL_ENUMERATED:
                return int_from_bytes(value, signed=True), "ENUMERATED" # Decoded as an integer.
            elif tag_number in [UNIVERSAL_UTF8_STRING, UNIVERSAL_PRINTABLE_STRING, UNIVERSAL_VISIBLE_STRING]:
                try:
                    # Note: PrintableString and VisibleString (ISO646String) have restricted charsets.
                    # For simplicity, all are decoded as UTF-8. Strict parsing might validate charsets.
                    return value.decode('utf-8'), "STRING"
                except UnicodeDecodeError:
                    return value_hex + " (UTF-8 Decode Error)", "STRING"
            elif tag_number == UNIVERSAL_SEQUENCE:
                # For a SEQUENCE tag, the 'value' field in the output item will be descriptive.
                # The actual content is parsed as children if constructed.
                return f"SEQUENCE (content_length {len(value)})", "SEQUENCE"
            else: # Fallback for other unhandled universal tags
                return value_hex, f"UNIVERSAL_{tag_number}"
        elif tag_class == 1: # Application Class
            # Specific APDU handling (e.g., AARQ, AARE) is based on tag_number in `decode_tag`'s constructed logic.
            # If this method is called for an APPLICATION tag, it implies it's either primitive
            # or its constructed nature is handled by `decode_tag` by parsing children.
            return value_hex, f"APPLICATION_{tag_number}"
        elif tag_class == 2: # Context-Specific Class
            # Context-specific tags are interpreted based on the schema of their containing structure.
            # The 'value' here is the raw content. If constructed, children will be parsed.
            return value_hex, f"CONTEXT_SPECIFIC_{tag_number}"
        elif tag_class == 3: # Private Class
            return value_hex, f"PRIVATE_{tag_number}"

        return value_hex, f"UNKNOWN_TAG_CLASS_{tag_class}" # Should ideally not be reached

    def get_dlms_tag_name(self, tag_class: int, tag_number: int, value_type_str: str,
                          parent_expected_tags_for_child: Dict[int, str] = None) -> str:
        """
        Determines a human-readable name for a BER tag.

        Priority for name resolution:
        1. Context-specific name from parent definition (if available).
        2. Specific name from `DLMS_TAGS` map (for known DLMS/ASN.1 tags).
        3. Descriptive type string from `decode_dlms_value` (e.g., "INTEGER", "OCTET STRING")
           if it's more specific than a generic "UNIVERSAL_X".
        4. Generic type string from `decode_dlms_value` (e.g., "UNIVERSAL_2").
        5. Absolute fallback like "ClassX_TagY".

        Args:
            tag_class: The class of the tag.
            tag_number: The number of the tag.
            value_type_str: The type string returned by `decode_dlms_value`.
            parent_expected_tags_for_child: Optional. Map from tag numbers to names,
                                            for context-specific tags defined by a parent.
        Returns:
            A string name for the tag.
        """
        # 1. Check if parent provides a name for a context-specific tag
        if tag_class == 2 and parent_expected_tags_for_child and tag_number in parent_expected_tags_for_child:
            return parent_expected_tags_for_child[tag_number]

        # 2. Check DLMS_TAGS map (covers common universal and application specific tags)
        specific_name_from_map = DLMS_TAGS.get((tag_class, tag_number))
        if not specific_name_from_map and tag_class == 0: # For Universal tags, DLMS_TAGS might map by number only
            specific_name_from_map = DLMS_TAGS.get(tag_number)

        if specific_name_from_map:
            return specific_name_from_map

        # 3. Use descriptive type string from decode_dlms_value if not generic
        is_generic_type_str = value_type_str.startswith("UNIVERSAL_") or \
                              value_type_str.startswith("APPLICATION_") or \
                              value_type_str.startswith("CONTEXT_SPECIFIC_") or \
                              value_type_str.startswith("PRIVATE_") or \
                              value_type_str.startswith("UNKNOWN_TAG_CLASS_")
        if value_type_str and not is_generic_type_str:
            return value_type_str # e.g., "INTEGER", "BOOLEAN", "OCTET STRING"

        # 4. Fallback to the (potentially generic) type string from decode_dlms_value
        if value_type_str:
            return value_type_str # e.g., "UNIVERSAL_2", "APPLICATION_0"

        # 5. Absolute fallback if all else fails (should be rare)
        return f"Class{tag_class}_Tag{tag_number}"


    def decode_aarq(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an AARQ (Association Request) APDU.
        The AARQ APDU itself is [APPLICATION 0] IMPLICIT SEQUENCE {...}.
        This method receives the content of that SEQUENCE.

        Args:
            data: The byte string representing the content of the AARQ SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the AARQ).
            - A context dictionary (currently empty).
        """
        # Defines the expected context-specific tags and their names within an AARQ PDU
        aarq_field_definitions = {
            0: "protocol-version [0]", 1: "application-context-name [1]", 2: "called-ap-title [2]",
            3: "called-ae-qualifier [3]", 4: "called-ap-invocation-id [4]", 5: "called-ae-invocation-id [5]",
            6: "calling-ap-title [6]", 7: "calling-ae-qualifier [7]", 8: "calling-ap-invocation-id [8]",
            9: "calling-ae-invocation-id [9]", 10: "sender-acse-requirements [10]", 11: "mechanism-name [11]",
            12: "calling-authentication-value [12]", 29: "implementation-information [29]", 30: "user-information [30]"
        }
        # The fields within AARQ are context-specific and IMPLICITLY tagged.
        # _decode_tags_from_data will parse these fields.
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=aarq_field_definitions)
        return children, context_update

    def decode_aare(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an AARE (Association Response) APDU.
        The AARE APDU itself is [APPLICATION 1] IMPLICIT SEQUENCE {...}.
        This method receives the content of that SEQUENCE.

        Args:
            data: The byte string representing the content of the AARE SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the AARE).
            - A context dictionary (currently empty).
        """
        # Defines the expected context-specific tags and their names within an AARE PDU
        aare_field_definitions = {
            0: "protocol-version [0]", 1: "application-context-name [1]", 2: "result [2]",
            3: "result-source-diagnostic [3]", 4: "responding-ap-title [4]", 5: "responding-ae-qualifier [5]",
            6: "responding-ap-invocation-id [6]", 7: "responding-ae-invocation-id [7]",
            8: "responder-acse-requirements [8]", 9: "mechanism-name [9]", 10: "responding-authentication-value [10]",
            29: "implementation-information [29]", 30: "user-information [30]"
        }
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=aare_field_definitions)
        return children, context_update

    # RLRQ APDU: [APPLICATION 2] IMPLICIT ReleaseRequestReason OPTIONAL
    rlrq_field_definitions = {
        0: "reason [0]" # ReleaseRequestReason OPTIONAL
        # user-information [30] is also possible as per ACSE, but typically not used in basic RLRQ for DLMS
        # If user-information were present, it would be:
        # 30: "user-information [30]"
    }

    def decode_rlrq(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an RLRQ (Release Request) APDU.
        The RLRQ APDU itself is [APPLICATION 2] IMPLICIT SEQUENCE {...fields...}.
        This method receives the content of that SEQUENCE.
        The main field is an optional 'reason'.

        Args:
            data: The byte string representing the content of the RLRQ SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the RLRQ).
            - A context dictionary (currently empty).
        """
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=self.rlrq_field_definitions)
        return children, context_update

    # RLRE APDU: [APPLICATION 3] IMPLICIT ReleaseResponseReason OPTIONAL
    rlre_field_definitions = {
        0: "reason [0]", # ReleaseResponseReason OPTIONAL
        30: "user-information [30]" # User-information OPTIONAL
    }

    def decode_rlre(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an RLRE (Release Response) APDU.
        The RLRE APDU itself is [APPLICATION 3] IMPLICIT SEQUENCE {...fields...}.
        This method receives the content of that SEQUENCE.
        Fields are optional 'reason' and 'user-information'.

        Args:
            data: The byte string representing the content of the RLRE SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the RLRE).
            - A context dictionary (currently empty).
        """
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=self.rlre_field_definitions)
        return children, context_update

    # RLRQ APDU: [APPLICATION 2] IMPLICIT ReleaseRequestReason OPTIONAL
    rlrq_field_definitions = {
        0: "reason [0]", # ReleaseRequestReason OPTIONAL
        # user-information [30] is also possible as per ACSE, but typically not used in basic RLRQ for DLMS
        30: "user-information [30]" # User-information OPTIONAL (ACSE standard)
    }

    def decode_rlrq(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an RLRQ (Release Request) APDU.
        The RLRQ APDU itself is [APPLICATION 2] IMPLICIT SEQUENCE {...fields...}.
        This method receives the content of that SEQUENCE.
        Fields are optional 'reason' and 'user-information'.

        Args:
            data: The byte string representing the content of the RLRQ SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the RLRQ).
            - A context dictionary (currently empty).
        """
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=self.rlrq_field_definitions)
        return children, context_update

    # RLRE APDU: [APPLICATION 3] IMPLICIT ReleaseResponseReason OPTIONAL
    rlre_field_definitions = {
        0: "reason [0]", # ReleaseResponseReason OPTIONAL
        30: "user-information [30]" # User-information OPTIONAL
    }

    def decode_rlre(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Decodes the content of an RLRE (Release Response) APDU.
        The RLRE APDU itself is [APPLICATION 3] IMPLICIT SEQUENCE {...fields...}.
        This method receives the content of that SEQUENCE.
        Fields are optional 'reason' and 'user-information'.

        Args:
            data: The byte string representing the content of the RLRE SEQUENCE.

        Returns:
            A tuple containing:
            - A list of decoded child items (fields of the RLRE).
            - A context dictionary (currently empty).
        """
        children, context_update, _ = self._decode_tags_from_data(data, parent_expected_tags_for_child=self.rlre_field_definitions)
        return children, context_update

# Add the __main__ block for testing
if __name__ == '__main__':
    decoder = BERDecoder()
    import json

    print("--- BER Decoder Test Suite ---")

    def run_test(name, data_hex):
        print(f"\n--- Test: {name} ---")
        data_bytes = binascii.unhexlify(data_hex)
        print(f"Input Hex: {data_hex}")
        decoded_items, _ = decoder.decode(data_bytes)

        # Custom JSON default handler for bytes if any 'value' is still raw bytes for display
        def json_default_bytes(obj):
            if isinstance(obj, bytes):
                return f"bytes:{bytes_to_hex(obj)}" # Or obj.decode('latin-1') if it's simple text
            raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

        print("Decoded Output:")
        print(json.dumps(decoded_items, indent=2, default=json_default_bytes))

    # Test 1: Simple INTEGER
    run_test("Simple INTEGER", "02012A") # INTEGER 42

    # Test 2: Simple OCTET STRING
    run_test("Simple OCTET STRING", "040548656C6C6F") # OCTET STRING "Hello"

    # Test 3: Basic SEQUENCE with two INTEGERS
    # SEQUENCE { INTEGER 10, INTEGER 20 }
    run_test("SEQUENCE of INTEGERS", "300602010A020114")

    # Test 4: AARQ APDU (Simplified Example)
    # This AARQ example aims to test the structure and context-specific tag handling.
    # AARQ-apdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {
    #   application-context-name [1] IMPLICIT Application-context-name (OBJECT IDENTIFIER),
    #   user-information         [30] IMPLICIT Association-information (OCTET STRING)
    # }
    # Application-context-name: OID 2.16.756.5.8.1.1 (LN no cipher) -> raw OID value: 60857405080101
    # User-information: OCTET STRING "TestData" -> raw OCTET STRING value: 5465737444617461

    # Field 1: application-context-name [1] (OBJECT IDENTIFIER 2.16.756.5.8.1.1)
    #   Tag: [CONTEXT 1] (A1 for constructed, assuming OID is wrapped or it's primitive 81)
    #   Value: OBJECT IDENTIFIER (06) L=7 V=60857405080101
    #   For IMPLICIT, the context tag [1] replaces the universal tag of OID.
    #   If [1] is constructed (A1), its value is the full TLV of OID.
    oid_tlv = "060760857405080101" # Universal OBJECT IDENTIFIER TLV
    app_context_field = "A1" + ("%02X" % (len(oid_tlv)//2)) + oid_tlv # [CONTEXT 1] IMPLICIT AppCtxName (Constructed)

    # Field 2: user-information [30] (OCTET STRING "TestData")
    #   Tag: [CONTEXT 30] (BE for constructed, 9E for primitive)
    #   Value: OCTET STRING (04) L=8 V=5465737444617461
    user_info_content = "5465737444617461" # "TestData"
    user_info_tlv = "04" + ("%02X" % (len(user_info_content)//2)) + user_info_content # Universal OCTET STRING TLV
    user_info_field = "BE" + ("%02X" % (len(user_info_tlv)//2)) + user_info_tlv # [CONTEXT 30] IMPLICIT UserInfo (Constructed)

    aarq_content_hex = app_context_field + user_info_field
    aarq_apdu_hex = "60" + ("%02X" % (len(aarq_content_hex)//2)) + aarq_content_hex # AARQ APDU [APPLICATION 0]
    run_test("Simplified AARQ APDU", aarq_apdu_hex)

    # Test 5: Empty SEQUENCE
    run_test("Empty SEQUENCE", "3000")

    # Test 6: SEQUENCE with NULL
    run_test("SEQUENCE with NULL", "30020500") # SEQUENCE { NULL }

    # Test 7: Malformed - tag indicates constructed, but no children / zero length value for children parsing
    run_test("Constructed Tag, Empty Value", "A100") # Context 1, Constructed, Length 0

    # Test 8: Malformed - length exceeds data
    run_test("Length Exceeds Data", "020501020304") # INTEGER, Len 5, but only 4 value bytes

    # Test 9: Malformed - long form length, but not enough length bytes
    run_test("Incomplete Long Form Length", "028201") # INTEGER, Len is 2 bytes, but only 1 provided

    # Test 10: DLMS Data array [CONTEXT 1] IMPLICIT SEQUENCE OF Data
    # Example: array { INTEGER 5, BOOLEAN true }
    # BER: A1 (Tag [1], Context-specific, Constructed) L (length of content)
    #      02 01 05 (INTEGER 5)
    #      01 01 FF (BOOLEAN true)
    array_content_hex = "020105" + "0101FF"
    array_tlv_hex = "A1" + ("%02X" % (len(array_content_hex)//2)) + array_content_hex
    run_test("DLMS Data array {5, true}", array_tlv_hex)

    # Test 11: DLMS Data structure [CONTEXT 2] IMPLICIT SEQUENCE OF Data
    # Example: structure { OCTET STRING "AB", NULL }
    # BER: A2 (Tag [2], Context-specific, Constructed) L (length of content)
    #      04 02 4142 (OCTET STRING "AB")
    #      05 00      (NULL)
    structure_content_hex = "04024142" + "0500"
    structure_tlv_hex = "A2" + ("%02X" % (len(structure_content_hex)//2)) + structure_content_hex
    run_test("DLMS Data structure {\"AB\", null}", structure_tlv_hex)

    # Test 12: Empty DLMS Data array
    empty_array_hex = "A100" # Tag [1], Context-specific, Constructed, Length 0
    run_test("Empty DLMS Data array", empty_array_hex)

    # Test 13: Empty DLMS Data structure
    empty_structure_hex = "A200" # Tag [2], Context-specific, Constructed, Length 0
    run_test("Empty DLMS Data structure", empty_structure_hex)

    # Test 14: DLMS Compact Array of Booleans {true, false, true}
    # Tag [19] (B3 = 80|20|13 = Context-specific, Constructed, Tag 19)
    # Content SEQUENCE:
    #   contents-description [0]: A0 L=2 V=(TypeDescription for boolean: 8300) -> A0028300
    #   array-contents [1]: 81 L=5 V=(OCTET STRING for A-XDR FF00FF: 0403FF00FF) -> 81050403FF00FF
    compact_array_content_bool_hex = "A0028300" + "81050403FF00FF"
    compact_array_tlv_bool_hex = "B3" + ("%02X" % (len(compact_array_content_bool_hex)//2)) + compact_array_content_bool_hex
    run_test("DLMS Compact Array of Booleans", compact_array_tlv_bool_hex)

    # Test 15: Compact array of unsigned8 {10, 20, 30}
    # TypeDescription: unsigned (uint8) -> [CONTEXT 17] IMPLICIT NULL -> BER: 9100 (Tag 17 = 0x11)
    type_desc_uint8_tlv_hex = "9100"
    contents_desc_field_hex = "A0" + ("%02X" % (len(type_desc_uint8_tlv_hex)//2)) + type_desc_uint8_tlv_hex
    # ArrayContents: A-XDR unsigned8: 0A141E (10, 20, 30)
    axdr_uint8_contents_hex = "0A141E"
    array_contents_octet_string_tlv_hex = "04" + ("%02X" % (len(axdr_uint8_contents_hex)//2)) + axdr_uint8_contents_hex
    array_contents_field_hex = "81" + ("%02X" % (len(array_contents_octet_string_tlv_hex)//2)) + array_contents_octet_string_tlv_hex
    compact_array_content_uint8_hex = contents_desc_field_hex + array_contents_field_hex
    compact_array_tlv_uint8_hex = "B3" + ("%02X" % (len(compact_array_content_uint8_hex)//2)) + compact_array_content_uint8_hex
    run_test("DLMS Compact Array of Unsigned8", compact_array_tlv_uint8_hex)

    # Test 16: Empty Compact Array (e.g. of integers)
    # TypeDescription: integer -> [CONTEXT 15] IMPLICIT NULL -> BER: 8F00 (Tag 15 = 0x0F)
    type_desc_int_tlv_hex = "8F00"
    contents_desc_field_empty_arr_hex = "A0" + ("%02X" % (len(type_desc_int_tlv_hex)//2)) + type_desc_int_tlv_hex
    # ArrayContents: Empty A-XDR sequence -> OCTET STRING (empty) -> 0400
    array_contents_os_empty_tlv_hex = "0400"
    array_contents_field_empty_hex = "81" + ("%02X" % (len(array_contents_os_empty_tlv_hex)//2)) + array_contents_os_empty_tlv_hex
    compact_array_content_empty_hex = contents_desc_field_empty_arr_hex + array_contents_field_empty_hex
    compact_array_tlv_empty_hex = "B3" + ("%02X" % (len(compact_array_content_empty_hex)//2)) + compact_array_content_empty_hex
    run_test("Empty DLMS Compact Array of Integers", compact_array_tlv_empty_hex)

    # Test 17: RLRQ APDU with reason normal (0)
    # RLRQ-apdu ::= [APPLICATION 2] IMPLICIT SEQUENCE { reason [0] IMPLICIT ReleaseRequestReason OPTIONAL }
    # ReleaseRequestReason ::= ENUMERATED { normal(0), urgent(1), user-defined(2) }
    # Reason [0] (ENUMERATED 0) -> BER for ENUM 0: 0A0100. Field: 80030A0100 (Context 0, Prim, Len 3, Val is TLV of ENUM)
    # According to ASN.1 for IMPLICIT, the context tag replaces the universal tag.
    # So, reason [0] IMPLICIT ENUMERATED(0) is: 80 01 00
    rlrq_content_normal_hex = "800100"
    rlrq_apdu_normal_hex = "62" + ("%02X" % (len(rlrq_content_normal_hex)//2)) + rlrq_content_normal_hex # App 2, Constructed
    run_test("RLRQ APDU (Normal)", rlrq_apdu_normal_hex)

    # Test 18: RLRE APDU with reason normal (0)
    # RLRE-apdu ::= [APPLICATION 3] IMPLICIT SEQUENCE { reason [0] IMPLICIT ReleaseResponseReason OPTIONAL, ...}
    # ReleaseResponseReason ::= ENUMERATED { normal(0), not-finished(1), user-defined(2) }
    # Reason [0] (ENUMERATED 0) -> 800100
    rlre_content_normal_hex = "800100"
    rlre_apdu_normal_hex = "63" + ("%02X" % (len(rlre_content_normal_hex)//2)) + rlre_content_normal_hex # App 3, Constructed
    run_test("RLRE APDU (Normal)", rlre_apdu_normal_hex)

    # Test 19: RLRQ APDU - no reason (empty sequence for RLRQ content)
    rlrq_apdu_no_reason_hex = "6200" # App 2, Constructed, Length 0
    run_test("RLRQ APDU (No Reason)", rlrq_apdu_no_reason_hex)

    # Test 20: RLRE APDU - no reason, no user-info (empty sequence for RLRE content)
    rlre_apdu_empty_hex = "6300" # App 3, Constructed, Length 0
    run_test("RLRE APDU (Empty)", rlre_apdu_empty_hex)

    print("\n--- BER Decoder Test Suite Complete ---")