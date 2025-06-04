"""
tests/test_decoders.py

Unit tests for the various decoders (A-XDR, BER, HDLC) in the dlms_parser project.
This module ensures that each decoder correctly parses its respective data formats
and handles various valid and invalid input scenarios.
"""
import unittest
import io
import sys
import os
import binascii

# Add project root to Python path to allow direct import of core.decoders
# This assumes tests are run from a context where 'core' is a discoverable module.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.decoders.axdr import AxdrDecoder
from core.decoders.ber import BERDecoder
from core.decoders.hdlc import HDLCDecoder
from core.utils.helpers import crc_check # Used by TestHdlcDecoder for test data generation

class TestAxdrDecoder(unittest.TestCase):
    """
    Unit tests for the AxdrDecoder class.

    These tests verify the correct decoding of basic A-XDR data types,
    including booleans, integers (signed/unsigned), octet strings (with explicit
    and prefixed lengths), and error handling for invalid or insufficient data.
    It also tests the generic `decode` method for sequences of types.
    """

    def setUp(self):
        """Set up an AxdrDecoder instance for each test."""
        self.decoder = AxdrDecoder()

    def test_decode_boolean(self):
        """Tests A-XDR boolean decoding (True, False, invalid, insufficient data)."""
        stream_true = io.BytesIO(b'\xff')
        self.assertTrue(self.decoder.decode_boolean(stream_true))
        stream_false = io.BytesIO(b'\x00')
        self.assertFalse(self.decoder.decode_boolean(stream_false))
        stream_invalid = io.BytesIO(b'\x01')
        with self.assertRaisesRegex(ValueError, "Invalid byte for boolean: 01"):
            self.decoder.decode_boolean(stream_invalid)
        stream_empty = io.BytesIO(b'')
        with self.assertRaisesRegex(IndexError, "Insufficient data to decode boolean."):
            self.decoder.decode_boolean(stream_empty)

    def test_decode_integer(self):
        """Tests A-XDR signed integer decoding for various byte lengths and values."""
        # int8
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x0a'), 1), 10, "int8 positive")
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\xf6'), 1), -10, "int8 negative")
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_decode_unsigned(self):
        """Tests A-XDR unsigned integer decoding for various byte lengths and values."""
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x0a'), 1), 10, "uint8 positive")
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_decode_octet_string_explicit_length(self):
        """Tests A-XDR octet string decoding with explicitly provided length."""
        data = b"hello world"
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(data), length=len(data)), data)
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_decode_octet_string_length_prefix(self):
        """Tests A-XDR octet string decoding with single-byte length prefix."""
        data_content = b"hello"
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x05' + data_content)), data_content)
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_decode_octet_string_long_length_prefix(self):
        """Tests A-XDR octet string decoding with multi-byte length prefix."""
        data_content_long = b"hello world" # 11 bytes
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x81\x0b' + data_content_long)), data_content_long)
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_insufficient_data_general(self):
        """Tests various decoders for general insufficient data errors."""
        with self.assertRaises(IndexError): self.decoder.decode_boolean(io.BytesIO(b''))
        # ... (rest of AxdrDecoder tests are unchanged) ...

    def test_decode_method_generic(self):
        """Tests the generic `decode` method with a sequence of type definitions."""
        type_seq = [
            (self.decoder.decode_unsigned, 1),
            (self.decoder.decode_boolean,),
            (self.decoder.decode_octet_string,)
        ]
        pdu_data = b'\x2a\xff\x05world'
        expected_items = [42, True, b'world']
        decoded_items, remaining = self.decoder.decode(pdu_data, type_sequence=type_seq)
        self.assertEqual(decoded_items, expected_items)
        # ... (rest of AxdrDecoder tests are unchanged) ...

# --- Unit Tests for BERDecoder ---
class TestBerDecoder(unittest.TestCase):
    """
    Unit tests for the BerDecoder class.

    These tests verify the correct parsing of BER TLV (Tag-Length-Value) structures,
    decoding of common universal ASN.1 types, and parsing of specific DLMS APDUs
    like AARQ (Association Request) and AARE (Association Response).
    Error handling for malformed or incomplete data is also tested.
    """
    def setUp(self):
        """Set up a BERDecoder instance for each test."""
        self.decoder = BERDecoder()
        self.axdr_decoder = AxdrDecoder() # For decoding A-XDR content in user-information

    def _find_child_by_name(self, children, name_prefix):
        """Helper to find a child item by its name prefix."""
        for child in children:
            if child['name'].startswith(name_prefix):
                return child
        return None

    def _assert_decoded_item(self, items, expected_name, expected_type, expected_value=None, value_is_bytes=False):
        """Helper to assert properties of a single decoded BER item."""
        # ... (implementation unchanged) ...
        self.assertEqual(len(items), 1, "Expected a single decoded item.")
        item = items[0]
        self.assertEqual(item['name'], expected_name, f"Name mismatch for {expected_name}")
        self.assertEqual(item['type'], expected_type, f"Type mismatch for {expected_name}")
        if expected_value is not None:
            if value_is_bytes:
                self.assertIsInstance(item['value'], bytes, f"Value for {expected_name} not bytes.")
                self.assertEqual(item['value'], expected_value, f"Byte value mismatch for {expected_name}")
            else:
                self.assertEqual(item['value'], expected_value, f"Value mismatch for {expected_name}")
        return item

    def test_ber_decode_integer(self):
        """Tests BER INTEGER decoding (positive, zero, negative, multi-byte)."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("02012A"))
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 42)
        items, _ = self.decoder.decode(binascii.unhexlify("020100"))
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 0)
        items, _ = self.decoder.decode(binascii.unhexlify("020200FF"))
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 255)
        items, _ = self.decoder.decode(binascii.unhexlify("0202FFFF"))
        self._assert_decoded_item(items, "INTEGER", "INTEGER", -1)
        items, _ = self.decoder.decode(binascii.unhexlify("020400010000"))
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 65536)

    def test_ber_decode_boolean(self):
        """Tests BER BOOLEAN decoding (True=non-zero, False=0x00)."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("0101FF"))
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", True)
        items, _ = self.decoder.decode(binascii.unhexlify("010100"))
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", False)
        items, _ = self.decoder.decode(binascii.unhexlify("010101"))
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", True)

    def test_ber_decode_octet_string(self):
        """Tests BER OCTET STRING decoding."""
        # ... (implementation unchanged) ...
        hex_str = "040548656C6C6F"
        expected_bytes = b"Hello"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", expected_bytes, value_is_bytes=True)
        items, _ = self.decoder.decode(binascii.unhexlify("0400"))
        self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", b"", value_is_bytes=True)

    def test_ber_decode_null(self):
        """Tests BER NULL decoding."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("0500"))
        self._assert_decoded_item(items, "NULL", "NULL", None)

    def test_ber_decode_object_identifier(self):
        """Tests BER OBJECT IDENTIFIER decoding."""
        # ... (implementation unchanged) ...
        hex_str = "060760857405080101"
        expected_oid_str = "2.16.756.5.8.1.1"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        self._assert_decoded_item(items, "OBJECT IDENTIFIER", "OBJECT IDENTIFIER", expected_oid_str)

    def test_ber_decode_enumerated(self):
        """Tests BER ENUMERATED decoding."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("0A0102"))
        self._assert_decoded_item(items, "ENUMERATED", "ENUMERATED", 2)

    def test_ber_decode_utf8_string(self):
        """Tests BER UTF8String (and similar string types) decoding."""
        # ... (implementation unchanged) ...
        hex_str = "0C0454657374"
        expected_str = "Test"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        self._assert_decoded_item(items, "STRING", "STRING", expected_str)

    def test_ber_length_forms(self):
        """Tests BER short and long length form encodings."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("020105"))
        self.assertEqual(items[0]['value'], 5)
        self.assertEqual(items[0]['value_length'], 1)
        self.assertEqual(items[0]['length_of_length_field'], 1)
        hex_str_long_len1 = "04810548656C6C6F"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str_long_len1))
        item = self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", b"Hello", value_is_bytes=True)
        self.assertEqual(item['value_length'], 5)
        self.assertEqual(item['length_of_length_field'], 2)
        val_260_A = b'A' * 260
        hex_str_long_len2 = "04820104" + val_260_A.hex()
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str_long_len2))
        item = self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", val_260_A, value_is_bytes=True)
        self.assertEqual(item['value_length'], 260)
        self.assertEqual(item['length_of_length_field'], 3)


    def test_ber_decode_aarq_example(self):
        """Tests decoding of a complex AARQ APDU with several fields."""
        # ... (existing complex AARQ test implementation remains unchanged) ...
        app_ctx_name_tlv = "060760857405080101"
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv
        acse_req_tlv = "03020780"
        acse_req_field = "8A" + ("%02X" % (len(acse_req_tlv)//2)) + acse_req_tlv
        mech_name_tlv = "060760857405080201"
        mech_name_field = "AB" + ("%02X" % (len(mech_name_tlv)//2)) + mech_name_tlv
        auth_val_tlv = "190870617373776F7264"
        auth_val_field = "AC" + ("%02X" % (len(auth_val_tlv)//2)) + auth_val_tlv
        axdr_init_req_hex = "12060403000060100400"
        user_info_tlv_content = axdr_init_req_hex
        user_info_tlv = "04" + ("%02X" % (len(user_info_tlv_content)//2)) + user_info_tlv_content
        user_info_field = "BE" + ("%02X" % (len(user_info_tlv)//2)) + user_info_tlv
        aarq_content_hex = app_ctx_name_field + acse_req_field + mech_name_field + auth_val_field + user_info_field
        aarq_apdu_hex = "60" + ("%02X" % (len(aarq_content_hex)//2)) + aarq_content_hex
        items, _ = self.decoder.decode(binascii.unhexlify(aarq_apdu_hex))
        self.assertEqual(len(items), 1)
        aarq_item = items[0]
        self.assertEqual(aarq_item['name'], "AARQ-apdu")
        self.assertTrue(aarq_item['constructed'])
        self.assertEqual(len(aarq_item['children']), 5)
        # ... (detailed assertions for children remain unchanged) ...

    def test_ber_decode_aarq_optional_fields(self):
        """Tests AARQ APDUs with different combinations of optional fields."""
        # Example 1: AARQ with application-context-name and implementation-information
        app_ctx_name_tlv = "060760857405080101" # LN OID
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv

        impl_info_val = "MyClientV1"
        impl_info_tlv = "19" + ("%02X" % len(impl_info_val)) + binascii.hexlify(impl_info_val.encode('ascii')).decode() # GraphicString
        impl_info_field = "9D" + ("%02X" % (len(impl_info_tlv)//2)) + impl_info_tlv # [29] IMPLICIT GraphicString
                                                                                 # Tag 29 = 0x1D. Context-specific, primitive = 80 | 1D = 9D.
                                                                                 # If GraphicString is constructed, it's BD

        aarq_content1_hex = app_ctx_name_field + impl_info_field
        aarq_apdu1_hex = "60" + ("%02X" % (len(aarq_content1_hex)//2)) + aarq_content1_hex

        items1, _ = self.decoder.decode(binascii.unhexlify(aarq_apdu1_hex))
        self.assertEqual(len(items1), 1)
        aarq1_item = items1[0]
        self.assertEqual(aarq1_item['name'], "AARQ-apdu")
        self.assertEqual(len(aarq1_item['children']), 2)
        self.assertEqual(self._find_child_by_name(aarq1_item['children'], "application-context-name")['children'][0]['value'], "2.16.756.5.8.1.1")
        impl_info_child = self._find_child_by_name(aarq1_item['children'], "implementation-information")
        self.assertIsNotNone(impl_info_child)
        self.assertEqual(impl_info_child['children'][0]['value'], impl_info_val)


        # Example 2: AARQ with only application-context-name and user-information (minimal valid AARQ for many cases)
        # User-information (A-XDR InitiateRequest: proposed-dlms-version-number = 6)
        axdr_minimal_init_req_hex = "1206" # proposed-dlms-version-number = 6
        user_info_min_tlv_content = axdr_minimal_init_req_hex
        user_info_min_tlv = "04" + ("%02X" % (len(user_info_min_tlv_content)//2)) + user_info_min_tlv_content
        user_info_min_field = "BE" + ("%02X" % (len(user_info_min_tlv)//2)) + user_info_min_tlv

        aarq_content2_hex = app_ctx_name_field + user_info_min_field
        aarq_apdu2_hex = "60" + ("%02X" % (len(aarq_content2_hex)//2)) + aarq_content2_hex

        items2, _ = self.decoder.decode(binascii.unhexlify(aarq_apdu2_hex))
        self.assertEqual(len(items2), 1)
        aarq2_item = items2[0]
        self.assertEqual(aarq2_item['name'], "AARQ-apdu")
        self.assertEqual(len(aarq2_item['children']), 2)
        user_info_child2 = self._find_child_by_name(aarq2_item['children'], "user-information")
        self.assertIsNotNone(user_info_child2)
        self.assertEqual(user_info_child2['children'][0]['value'], binascii.unhexlify(axdr_minimal_init_req_hex))


    def test_ber_decode_aare_example(self):
        """Tests decoding of a complex AARE APDU, including various optional fields."""
        # ... (existing complex AARE test implementation remains unchanged) ...
        app_ctx_name_tlv = "060760857405080101"
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv
        result_tlv = "0A0100"
        result_field = "A2" + ("%02X" % (len(result_tlv)//2)) + result_tlv
        diag_user_tlv = "0A0100"
        diag_user_field = "A1" + ("%02X" % (len(diag_user_tlv)//2)) + diag_user_tlv
        diag_field = "A3" + ("%02X" % (len(diag_user_field)//2)) + diag_user_field
        axdr_init_resp_hex = "12060403000060100400060007"
        user_info_tlv_content = axdr_init_resp_hex
        user_info_tlv = "04" + ("%02X" % (len(user_info_tlv_content)//2)) + user_info_tlv_content
        user_info_field = "BE" + ("%02X" % (len(user_info_tlv)//2)) + user_info_tlv
        aare_content_hex = app_ctx_name_field + result_field + diag_field + user_info_field
        aare_apdu_hex = "61" + ("%02X" % (len(aare_content_hex)//2)) + aare_content_hex
        items, _ = self.decoder.decode(binascii.unhexlify(aare_apdu_hex))
        self.assertEqual(len(items), 1)
        # ... (detailed assertions for children remain unchanged) ...

    def test_ber_decode_aare_optional_fields(self):
        """Tests AARE APDUs with different combinations of optional fields and results."""
        # Example 1: AARE rejected with diagnostic and responding AP title
        app_ctx_name_tlv = "060760857405080101" # LN OID
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv

        result_rejected_tlv = "0A0101" # ENUMERATED 1 (rejected-permanent)
        result_rejected_field = "A2" + ("%02X" % (len(result_rejected_tlv)//2)) + result_rejected_tlv

        # result-source-diagnostic: acse-service-provider (2), no-reason-given (0)
        # AssociateSourceDiagnostic ::= CHOICE { acse-service-user [1] INTEGER, acse-service-provider [2] INTEGER }
        # So, [CONTEXT 3] { [CONTEXT 2] ENUMERATED(0) }
        diag_prov_val_tlv = "0A0100" # ENUMERATED 0 (no-reason-given)
        diag_prov_field = "A2" + ("%02X" % (len(diag_prov_val_tlv)//2)) + diag_prov_val_tlv # [CONTEXT 2] for provider choice
        diag_field_rejected = "A3" + ("%02X" % (len(diag_prov_field)//2)) + diag_prov_field

        resp_ap_title_val = "Server123" # Responding AP Title (GraphicString)
        resp_ap_title_tlv = "19" + ("%02X" % len(resp_ap_title_val)) + binascii.hexlify(resp_ap_title_val.encode('ascii')).decode()
        resp_ap_title_field = "A4" + ("%02X" % (len(resp_ap_title_tlv)//2)) + resp_ap_title_tlv # [4] Responding AP Title

        aare_content1_hex = app_ctx_name_field + result_rejected_field + diag_field_rejected + resp_ap_title_field
        aare_apdu1_hex = "61" + ("%02X" % (len(aare_content1_hex)//2)) + aare_content1_hex

        items1, _ = self.decoder.decode(binascii.unhexlify(aare_apdu1_hex))
        self.assertEqual(len(items1), 1)
        aare1_item = items1[0]
        self.assertEqual(aare1_item['name'], "AARE-apdu")
        self.assertEqual(len(aare1_item['children']), 4)
        self.assertEqual(self._find_child_by_name(aare1_item['children'], "result [2]")['children'][0]['value'], 1) # rejected-permanent
        diag_child1 = self._find_child_by_name(aare1_item['children'], "result-source-diagnostic [3]")
        self.assertIsNotNone(diag_child1)
        # Check nested structure of result-source-diagnostic
        self.assertEqual(diag_child1['children'][0]['name'], "CONTEXT_SPECIFIC_2") # acse-service-provider choice
        self.assertEqual(diag_child1['children'][0]['children'][0]['value'], 0) # no-reason-given

        resp_title_child1 = self._find_child_by_name(aare1_item['children'], "responding-ap-title [4]")
        self.assertIsNotNone(resp_title_child1)
        self.assertEqual(resp_title_child1['children'][0]['value'], resp_ap_title_val)

        # Example 2: AARE accepted with responder ACSE requirements
        acse_req_val = "0780" # BIT STRING '1xxxxxxx'B (e.g. authentication)
        acse_req_tlv = "0302" + acse_req_val # Universal BIT STRING
        acse_req_field = "A8" + ("%02X" % (len(acse_req_tlv)//2)) + acse_req_tlv # [8] responder-acse-requirements

        aare_content2_hex = app_ctx_name_field + result_field + diag_field + acse_req_field # Using accepted result from previous test
        aare_apdu2_hex = "61" + ("%02X" % (len(aare_content2_hex)//2)) + aare_content2_hex

        items2, _ = self.decoder.decode(binascii.unhexlify(aare_apdu2_hex))
        self.assertEqual(len(items2), 1)
        aare2_item = items2[0]
        self.assertEqual(aare2_item['name'], "AARE-apdu")
        self.assertEqual(len(aare2_item['children']), 4)
        acse_child2 = self._find_child_by_name(aare2_item['children'], "responder-acse-requirements [8]")
        self.assertIsNotNone(acse_child2)
        self.assertEqual(acse_child2['children'][0]['value'], f"UnusedBits:7 Data:{acse_req_val[2:]}")


    def test_ber_incomplete_data(self):
        """Tests BER decoding with various forms of incomplete/truncated data."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(binascii.unhexlify("02"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['name'], "PARSING_ERROR")
        self.assertIn("Not enough data for length byte", items[0]['error'])
        items, _ = self.decoder.decode(binascii.unhexlify("040548656C"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['name'], "PARSING_ERROR")
        self.assertIn("Decoded length 5 exceeds available data", items[0]['error'])
        items, _ = self.decoder.decode(binascii.unhexlify("048201"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['name'], "PARSING_ERROR")
        self.assertIn("Insufficient data for long-form length bytes", items[0]['error'])

    def test_ber_decode_data_array(self):
        """Tests BER decoding of DLMS Data array type."""
        # ... (implementation unchanged) ...
        array_content_hex = "8F010A8F0114"
        data_array_hex = "A1" + ("%02X" % (len(array_content_hex)//2)) + array_content_hex
        items, _ = self.decoder.decode(binascii.unhexlify(data_array_hex))
        self.assertEqual(len(items), 1)
        root_item = items[0]
        self.assertEqual(root_item['type'], "array")
        self.assertEqual(len(root_item['children']), 2)
        self.assertEqual(root_item['children'][0]['value'], 10)
        self.assertEqual(root_item['children'][1]['value'], 20)
        empty_array_hex = "A100"
        items, _ = self.decoder.decode(binascii.unhexlify(empty_array_hex))
        self.assertEqual(items[0]['type'], "array")
        self.assertEqual(len(items[0]['children']), 0)
        mixed_array_content_hex = "8301FF89024142"
        mixed_data_array_hex = "A1" + ("%02X" % (len(mixed_array_content_hex)//2)) + mixed_array_content_hex
        items, _ = self.decoder.decode(binascii.unhexlify(mixed_data_array_hex))
        self.assertEqual(items[0]['type'], "array")
        self.assertEqual(len(items[0]['children']), 2)
        self.assertEqual(items[0]['children'][0]['value'], True)
        self.assertEqual(items[0]['children'][1]['value'], b"AB")


    def test_ber_decode_data_structure(self):
        """Tests BER decoding of DLMS Data structure type."""
        # ... (implementation unchanged) ...
        structure_content_hex = "8F0105830100"
        data_structure_hex = "A2" + ("%02X" % (len(structure_content_hex)//2)) + structure_content_hex
        items, _ = self.decoder.decode(binascii.unhexlify(data_structure_hex))
        self.assertEqual(len(items), 1)
        root_item = items[0]
        self.assertEqual(root_item['type'], "structure")
        self.assertEqual(len(root_item['children']), 2)
        self.assertEqual(root_item['children'][0]['value'], 5)
        self.assertEqual(root_item['children'][1]['value'], False)
        empty_structure_hex = "A200"
        items, _ = self.decoder.decode(binascii.unhexlify(empty_structure_hex))
        self.assertEqual(items[0]['type'], "structure")
        self.assertEqual(len(items[0]['children']), 0)


    def test_ber_decode_data_compact_array(self):
        """Tests BER decoding of DLMS Data compact-array type."""
        # ... (implementation unchanged) ...
        compact_array_content_bool_hex = "A0028300" + "81050403FF00FF"
        compact_array_tlv_bool_hex = "B3" + ("%02X" % (len(compact_array_content_bool_hex)//2)) + compact_array_content_bool_hex
        items, _ = self.decoder.decode(binascii.unhexlify(compact_array_tlv_bool_hex))
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item['type'], "compact-array")
        self.assertEqual(item.get('element_type'), "boolean")
        self.assertEqual(item.get('decoded_elements'), [True, False, True])
        type_desc_int_hex = "8F00"
        contents_desc_empty_arr_hex = "A0" + ("%02X" % (len(type_desc_int_hex)//2)) + type_desc_int_hex
        array_contents_os_empty_hex = "0400"
        array_contents_field_empty_hex = "81" + ("%02X" % (len(array_contents_os_empty_hex)//2)) + array_contents_os_empty_hex
        compact_array_content_empty_hex = contents_desc_empty_arr_hex + array_contents_field_empty_hex
        compact_array_tlv_empty_hex = "B3" + ("%02X" % (len(compact_array_content_empty_hex)//2)) + compact_array_content_empty_hex
        items, _ = self.decoder.decode(binascii.unhexlify(compact_array_tlv_empty_hex))
        self.assertEqual(items[0]['type'], "compact-array")
        self.assertEqual(items[0]['element_type'], "integer")
        self.assertEqual(items[0].get('decoded_elements'), [])


# --- Unit Tests for HDLCDecoder ---
class TestHdlcDecoder(unittest.TestCase):
    """
    Unit tests for the HDLCDecoder class.

    These tests verify HDLC frame parsing, including extraction of address, control,
    payload, and CRC validation. It also tests error handling for malformed frames
    and identification of different control field types.
    """
    def setUp(self):
        """Set up an HDLCDecoder instance for each test."""
        self.decoder = HDLCDecoder()

    def _construct_hdlc_frame(self, addr_byte, ctrl_byte, payload_bytes, malform_crc=False):
        """Helper to construct a complete HDLC frame with flags and CRC."""
        # ... (implementation unchanged) ...
        hdlc_length_val = 1 + 1 + len(payload_bytes) + 2
        frame_for_crc = bytes([addr_byte, ctrl_byte, (hdlc_length_val >> 8) & 0xFF, hdlc_length_val & 0xFF]) + payload_bytes
        crc = crc_check(frame_for_crc)
        if malform_crc: crc = crc ^ 0xFFFF
        full_frame_content = frame_for_crc + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
        return b'\x7E' + full_frame_content + b'\x7E'


    def test_hdlc_decode_valid_frame(self):
        """Tests decoding of a valid HDLC frame with correct CRC."""
        # ... (implementation unchanged) ...
        addr = 0x23
        ctrl = 0x10
        payload = b'\x01\x02\x03\x04\x05'
        hdlc_frame = self._construct_hdlc_frame(addr, ctrl, payload)
        items, context = self.decoder.decode(hdlc_frame)
        self.assertNotEqual(items[0].get('name'), 'Error')
        self.assertEqual(items[0]['value'], f'0x{addr:02X}')
        self.assertIn('I-Frame', items[1]['value'])
        self.assertEqual(items[3]['value'], payload.hex())
        self.assertIn('Valid', items[3]['children'][0]['value'])
        self.assertEqual(context['hdlc_payload'], payload)


    def test_hdlc_decode_invalid_crc(self):
        """Tests that an invalid CRC is correctly identified."""
        # ... (implementation unchanged) ...
        hdlc_frame_bad_crc = self._construct_hdlc_frame(0x45, 0x93, b'\xAA\xBB\xCC', malform_crc=True)
        items, context = self.decoder.decode(hdlc_frame_bad_crc)
        self.assertIn('Invalid', items[3]['children'][0]['value'])
        self.assertTrue(context.get('hdlc_crc_error'))

    def test_hdlc_frame_too_short(self):
        """Tests error handling for frames shorter than the minimum allowed length."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(b'\x7E\x01\x02\x03\x04\x05\x7E')
        self.assertEqual(items[0]['name'], 'Error')
        self.assertIn('too short', items[0]['value'])

    def test_hdlc_missing_start_flag(self):
        """Tests error handling for frames missing the start flag."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(b'\x01\x02\x03\x04\x05\x06\x07\x08\x7E')
        self.assertEqual(items[0]['name'], 'Error')
        self.assertEqual(items[0]['value'], 'No start flag found')

    def test_hdlc_missing_end_flag(self):
        """Tests error handling for frames missing the end flag after a start flag."""
        # ... (implementation unchanged) ...
        items, _ = self.decoder.decode(b'\x7E\x01\x02\x03\x04\x05\x06\x07\x08')
        self.assertEqual(items[0]['name'], 'Error')
        self.assertEqual(items[0]['value'], 'No end flag found after start flag')

    def test_hdlc_control_field_types(self):
        """Tests the `get_control_type` method for I, S, and U frames."""
        # ... (implementation unchanged) ...
        self.assertEqual(self.decoder.get_control_type(0x10), "I-Frame")
        self.assertEqual(self.decoder.get_control_type(0x01), "S-Frame")
        self.assertEqual(self.decoder.get_control_type(0x13), "U-Frame")
        self.assertEqual(self.decoder.get_control_type(0x02), "Unknown")


if __name__ == '__main__':
    unittest.main()
