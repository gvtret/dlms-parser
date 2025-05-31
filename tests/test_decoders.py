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
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x00'), 1), 0, "int8 zero")
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x7f'), 1), 127, "int8 max")
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x80'), 1), -128, "int8 min")

        # int16
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x01\x00'), 2), 256, "int16 positive")
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\xff\x00'), 2), -256, "int16 negative")

        # int32
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x00\x01\x00\x00'), 4), 65536, "int32 positive")

        # int64
        self.assertEqual(self.decoder.decode_integer(io.BytesIO(b'\x00\x00\x00\x00\x00\x01\x00\x00'), 8), 65536, "int64 positive")

        # Invalid length argument
        with self.assertRaisesRegex(ValueError, "Unsupported integer byte_length: 3"):
            self.decoder.decode_integer(io.BytesIO(b'\x00'), 3)

        # Insufficient data
        with self.assertRaisesRegex(IndexError, "Insufficient data to decode 2-byte integer."):
            self.decoder.decode_integer(io.BytesIO(b'\x01'), 2)
        with self.assertRaisesRegex(IndexError, "Insufficient data to decode 1-byte integer."):
            self.decoder.decode_integer(io.BytesIO(b''), 1)


    def test_decode_unsigned(self):
        """Tests A-XDR unsigned integer decoding for various byte lengths and values."""
        # uint8
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x0a'), 1), 10, "uint8 positive")
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x00'), 1), 0, "uint8 zero")
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\xff'), 1), 255, "uint8 max")

        # uint16
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x01\x00'), 2), 256, "uint16 positive")
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\xff\xff'), 2), 65535, "uint16 max")

        # uint32
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x00\x01\x00\x00'), 4), 65536, "uint32 positive")

        # uint64
        self.assertEqual(self.decoder.decode_unsigned(io.BytesIO(b'\x00\x00\x00\x00\x00\x01\x00\x00'), 8), 65536, "uint64 positive")

        # Invalid length argument
        with self.assertRaisesRegex(ValueError, "Unsupported unsigned integer byte_length: 3"):
            self.decoder.decode_unsigned(io.BytesIO(b'\x00'), 3)

        # Insufficient data
        with self.assertRaisesRegex(IndexError, "Insufficient data to decode 2-byte unsigned integer."):
            self.decoder.decode_unsigned(io.BytesIO(b'\x01'), 2)
        with self.assertRaisesRegex(IndexError, "Insufficient data to decode 1-byte unsigned integer."):
            self.decoder.decode_unsigned(io.BytesIO(b''), 1)

    def test_decode_octet_string_explicit_length(self):
        """Tests A-XDR octet string decoding with explicitly provided length."""
        data = b"hello world"
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(data), length=len(data)), data)

        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b""), length=0), b"")

        with self.assertRaisesRegex(IndexError, "Insufficient data for octet string of length 10. Expected 10, got 5."):
            self.decoder.decode_octet_string(io.BytesIO(b"short"), length=10)

        with self.assertRaisesRegex(ValueError, "Explicit length for octet string cannot be negative."):
            self.decoder.decode_octet_string(io.BytesIO(b"data"), length=-1)

    def test_decode_octet_string_length_prefix(self):
        """Tests A-XDR octet string decoding with single-byte length prefix."""
        data_content = b"hello"
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x05' + data_content)), data_content)

        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x00')), b"") # Empty string

        data_127 = b'A' * 127
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x7f' + data_127)), data_127) # Max single-byte length

        with self.assertRaisesRegex(IndexError, "Insufficient data for octet string of length 5. Expected 5, got 3."):
            self.decoder.decode_octet_string(io.BytesIO(b'\x05hel'))

        with self.assertRaisesRegex(IndexError, "Insufficient data to decode length prefix."):
            self.decoder.decode_octet_string(io.BytesIO(b''))

    def test_decode_octet_string_long_length_prefix(self):
        """Tests A-XDR octet string decoding with multi-byte length prefix."""
        data_content_long = b"hello world" # 11 bytes
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x81\x0b' + data_content_long)), data_content_long)

        data_256 = b'B' * 256
        self.assertEqual(self.decoder.decode_octet_string(io.BytesIO(b'\x82\x01\x00' + data_256)), data_256)

        with self.assertRaisesRegex(IndexError, "Insufficient data for multi-byte length \(2 bytes expected\)."):
            self.decoder.decode_octet_string(io.BytesIO(b'\x82\x01'))

        with self.assertRaisesRegex(IndexError, "Insufficient data for octet string of length 11. Expected 11, got 5."):
            self.decoder.decode_octet_string(io.BytesIO(b'\x81\x0bhello'))

        with self.assertRaisesRegex(ValueError, "Invalid length prefix: 0x80."): # As per axdr.py _decode_length logic
            self.decoder.decode_octet_string(io.BytesIO(b'\x80'))

        with self.assertRaisesRegex(ValueError, "Length prefix indicates too many length bytes: 5"):
            self.decoder.decode_octet_string(io.BytesIO(b'\x85\x01\x02\x03\x04\x05'))


    def test_insufficient_data_general(self):
        """Tests various decoders for general insufficient data errors."""
        with self.assertRaises(IndexError): self.decoder.decode_boolean(io.BytesIO(b''))
        with self.assertRaises(IndexError): self.decoder.decode_integer(io.BytesIO(b'\x01'), 2)
        with self.assertRaises(IndexError): self.decoder.decode_unsigned(io.BytesIO(b'\x01'), 2)
        with self.assertRaises(IndexError): self.decoder.decode_octet_string(io.BytesIO(b'abc'), length=5)
        with self.assertRaises(IndexError): self.decoder.decode_octet_string(io.BytesIO(b'')) # For length prefix
        with self.assertRaises(IndexError): self.decoder.decode_octet_string(io.BytesIO(b'\x05ab')) # For content
        with self.assertRaises(IndexError): self.decoder.decode_octet_string(io.BytesIO(b'\x82\x01')) # For multi-byte length bytes

    def test_decode_method_generic(self):
        """Tests the generic `decode` method with a sequence of type definitions."""
        type_seq = [
            (self.decoder.decode_unsigned, 1),    # uint8
            (self.decoder.decode_boolean,),       # boolean
            (self.decoder.decode_octet_string,)   # octet_string with length prefix
        ]
        pdu_data = b'\x2a\xff\x05world' # 42, True, "world"
        expected_items = [42, True, b'world']
        decoded_items, remaining = self.decoder.decode(pdu_data, type_sequence=type_seq)

        self.assertEqual(decoded_items, expected_items, "Generic decode sequence mismatch")
        self.assertEqual(remaining, b'', "Generic decode remaining data not empty")

        # Test with remaining data after sequence
        pdu_data_with_rem = b'\x2a\xff\x05world\x01\x02\x03'
        decoded_items_rem, remaining_rem = self.decoder.decode(pdu_data_with_rem, type_sequence=type_seq)
        self.assertEqual(decoded_items_rem, expected_items, "Generic decode with remainder: items mismatch")
        self.assertEqual(remaining_rem, b'\x01\x02\x03', "Generic decode with remainder: remaining data mismatch")

        # Test insufficient data for one of the sequence elements
        pdu_data_fail_bool = b'\x2a'
        with self.assertRaises(IndexError, msg="Generic decode: Insufficient data for boolean in sequence"):
             self.decoder.decode(pdu_data_fail_bool, type_sequence=type_seq)

        pdu_data_fail_octet_content = b'\x2a\xff\x05wor' # Missing 'ld' for octet string
        with self.assertRaises(IndexError, msg="Generic decode: Insufficient data for octet string content"):
             self.decoder.decode(pdu_data_fail_octet_content, type_sequence=type_seq)

        # Test default decode (no type_sequence) - should try to decode as single octet string
        default_pdu_data = b'\x03cat' # Represents octet string "cat"
        decoded_default, remaining_default = self.decoder.decode(default_pdu_data)
        self.assertEqual(decoded_default, [b'cat'], "Default generic decode failed")
        self.assertEqual(remaining_default, b'', "Default generic decode remaining data not empty")


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

    def _assert_decoded_item(self, items, expected_name, expected_type, expected_value=None, value_is_bytes=False):
        """Helper to assert properties of a single decoded BER item."""
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
        items, _ = self.decoder.decode(binascii.unhexlify("02012A")) # INTEGER 42
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 42)
        items, _ = self.decoder.decode(binascii.unhexlify("020100")) # INTEGER 0
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 0)
        items, _ = self.decoder.decode(binascii.unhexlify("020200FF")) # INTEGER 255
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 255)
        items, _ = self.decoder.decode(binascii.unhexlify("0202FFFF")) # INTEGER -1 (signed 16-bit)
        self._assert_decoded_item(items, "INTEGER", "INTEGER", -1)
        items, _ = self.decoder.decode(binascii.unhexlify("020400010000")) # INTEGER 65536
        self._assert_decoded_item(items, "INTEGER", "INTEGER", 65536)

    def test_ber_decode_boolean(self):
        """Tests BER BOOLEAN decoding (True=non-zero, False=0x00)."""
        items, _ = self.decoder.decode(binascii.unhexlify("0101FF")) # BOOLEAN TRUE
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", True)
        items, _ = self.decoder.decode(binascii.unhexlify("010100")) # BOOLEAN FALSE
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", False)
        items, _ = self.decoder.decode(binascii.unhexlify("010101")) # Also TRUE
        self._assert_decoded_item(items, "BOOLEAN", "BOOLEAN", True)

    def test_ber_decode_octet_string(self):
        """Tests BER OCTET STRING decoding."""
        hex_str = "040548656C6C6F" # OCTET STRING "Hello"
        expected_bytes = b"Hello"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", expected_bytes, value_is_bytes=True)
        items, _ = self.decoder.decode(binascii.unhexlify("0400")) # Empty OCTET STRING
        self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", b"", value_is_bytes=True)

    def test_ber_decode_null(self):
        """Tests BER NULL decoding."""
        items, _ = self.decoder.decode(binascii.unhexlify("0500")) # NULL
        self._assert_decoded_item(items, "NULL", "NULL", None)

    def test_ber_decode_object_identifier(self):
        """Tests BER OBJECT IDENTIFIER decoding."""
        hex_str = "060760857405080101" # OID 2.16.756.5.8.1.1 (DLMS UA)
        expected_oid_str = "2.16.756.5.8.1.1"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        self._assert_decoded_item(items, "OBJECT IDENTIFIER", "OBJECT IDENTIFIER", expected_oid_str)

    def test_ber_decode_enumerated(self):
        """Tests BER ENUMERATED decoding."""
        items, _ = self.decoder.decode(binascii.unhexlify("0A0102")) # ENUMERATED 2
        self._assert_decoded_item(items, "ENUMERATED", "ENUMERATED", 2)

    def test_ber_decode_utf8_string(self):
        """Tests BER UTF8String (and similar string types) decoding."""
        hex_str = "0C0454657374" # UTF8String "Test"
        expected_str = "Test"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str))
        # Note: decode_dlms_value groups various string types into "STRING"
        self._assert_decoded_item(items, "STRING", "STRING", expected_str)

    def test_ber_length_forms(self):
        """Tests BER short and long length form encodings."""
        # Short form
        items, _ = self.decoder.decode(binascii.unhexlify("020105")) # INTEGER 5
        self.assertEqual(items[0]['value'], 5)
        self.assertEqual(items[0]['value_length'], 1, "Short form value length")
        self.assertEqual(items[0]['length_of_length_field'], 1, "Short form L-field length")

        # Long form, 1 byte for length value (total L part is 2 bytes: 0x81 + length_byte)
        hex_str_long_len1 = "04810548656C6C6F" # OCTET STRING "Hello"
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str_long_len1))
        item = self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", b"Hello", value_is_bytes=True)
        self.assertEqual(item['value_length'], 5, "Long form (1 byte L) value length")
        self.assertEqual(item['length_of_length_field'], 2, "Long form (1 byte L) L-field length")

        # Long form, 2 bytes for length value (total L part is 3 bytes: 0x82 + len_byte1 + len_byte2)
        val_260_A = b'A' * 260 # Length 260 = 0x0104
        hex_str_long_len2 = "04820104" + val_260_A.hex()
        items, _ = self.decoder.decode(binascii.unhexlify(hex_str_long_len2))
        item = self._assert_decoded_item(items, "OCTET STRING", "OCTET STRING", val_260_A, value_is_bytes=True)
        self.assertEqual(item['value_length'], 260, "Long form (2 byte L) value length")
        self.assertEqual(item['length_of_length_field'], 3, "Long form (2 byte L) L-field length")

    def test_ber_decode_aarq_example(self):
        """Tests decoding of a more complex AARQ APDU with several fields."""
        # AARQ APDU: [APPLICATION 0] IMPLICIT SEQUENCE { ... }
        #   application-context-name        [1] IMPLICIT OBJECT IDENTIFIER (2.16.756.5.8.1.1 - LN no cipher)
        #   sender-acse-requirements        [10] IMPLICIT BIT STRING { authentication (0) } -> '1'B
        #   mechanism-name                  [11] IMPLICIT OBJECT IDENTIFIER (2.16.756.5.8.2.1 - LLS)
        #   calling-authentication-value    [12] IMPLICIT GraphicString "password"
        #   user-information                [30] IMPLICIT OCTET STRING (A-XDR InitiateRequest)
        #     A-XDR InitiateRequest: {
        #       proposed-dlms-version-number = 6 (Unsigned8)
        #       proposed-conformance = { get, set } (BIT STRING Size 24, bits 5 and 6 are 1: ...01100000 -> 000060)
        #       client-max-receive-pdu-size = 1024 (Unsigned16)
        #     }

        # Field 1: application-context-name (OID 2.16.756.5.8.1.1)
        # BER TLV: 060760857405080101
        app_ctx_name_tlv = "060760857405080101"
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv

        # Field 2: sender-acse-requirements (BIT STRING { authentication(0) } -> '1'B)
        # Value is 1 bit, '1'. BER BIT STRING: 03 L=2 (1 byte for unused bits, 1 for value) V=0780 (7 unused, value 10000000)
        acse_req_tlv = "03020780"
        acse_req_field = "8A" + ("%02X" % (len(acse_req_tlv)//2)) + acse_req_tlv # Context tag 10 primitive

        # Field 3: mechanism-name (OID 2.16.756.5.8.2.1 - LLS)
        # BER TLV: 060760857405080201
        mech_name_tlv = "060760857405080201"
        mech_name_field = "8B" + ("%02X" % (len(mech_name_tlv)//2)) + mech_name_tlv # Context tag 11 primitive (ASN says constructed A1, but OID is primitive)
                                                                                # Let's assume it's context primitive containing OID TLV
                                                                                # Or context constructed A1 containing OID TLV. The spec implies IMPLICIT.
                                                                                # If IMPLICIT, then 8B L V where V is OID value bytes.
                                                                                # For now, assume context constructed for simplicity of test data.
        mech_name_field = "AB" + ("%02X" % (len(mech_name_tlv)//2)) + mech_name_tlv


        # Field 4: calling-authentication-value (GraphicString "password")
        # BER TLV: 190870617373776F7264
        auth_val_tlv = "190870617373776F7264" # GraphicString "password"
        auth_val_field = "AC" + ("%02X" % (len(auth_val_tlv)//2)) + auth_val_tlv # Context tag 12 constructed

        # Field 5: user-information (A-XDR InitiateRequest)
        # A-XDR: 1206 0403000060 100400 (version 6, conformance get&set, pdu 1024)
        axdr_init_req_hex = "12060403000060100400"
        user_info_tlv_content = axdr_init_req_hex # This is the content of the OCTET STRING
        user_info_tlv = "04" + ("%02X" % (len(user_info_tlv_content)//2)) + user_info_tlv_content
        user_info_field = "BE" + ("%02X" % (len(user_info_tlv)//2)) + user_info_tlv # Context tag 30 constructed

        aarq_content_hex = app_ctx_name_field + acse_req_field + mech_name_field + auth_val_field + user_info_field
        aarq_apdu_hex = "60" + ("%02X" % (len(aarq_content_hex)//2)) + aarq_content_hex

        items, _ = self.decoder.decode(binascii.unhexlify(aarq_apdu_hex))

        self.assertEqual(len(items), 1, "AARQ: Expected one root item.")
        aarq_item = items[0]
        self.assertEqual(aarq_item['name'], "AARQ-apdu", "AARQ: Name mismatch.")
        self.assertTrue(aarq_item['constructed'], "AARQ: Should be constructed.")
        self.assertEqual(len(aarq_item['children']), 5, "AARQ: Expected 5 children.")

        # Child 1: application-context-name
        app_ctx_item = aarq_item['children'][0]
        self.assertEqual(app_ctx_item['name'], "application-context-name [1]")
        self.assertEqual(app_ctx_item['children'][0]['value'], "2.16.756.5.8.1.1")

        # Child 2: sender-acse-requirements
        acse_req_item = aarq_item['children'][1]
        self.assertEqual(acse_req_item['name'], "sender-acse-requirements [10]")
        self.assertEqual(acse_req_item['children'][0]['value'], "UnusedBits:7 Data:80") # '1'B

        # Child 3: mechanism-name
        mech_name_item = aarq_item['children'][2]
        self.assertEqual(mech_name_item['name'], "mechanism-name [11]")
        self.assertEqual(mech_name_item['children'][0]['value'], "2.16.756.5.8.2.1")

        # Child 4: calling-authentication-value
        auth_val_item = aarq_item['children'][3]
        self.assertEqual(auth_val_item['name'], "calling-authentication-value [12]")
        self.assertEqual(auth_val_item['children'][0]['value'], "password")

        # Child 5: user-information (check raw OCTET STRING content at BER level)
        user_info_item = aarq_item['children'][4]
        self.assertEqual(user_info_item['name'], "user-information [30]")
        self.assertEqual(user_info_item['children'][0]['type'], "OCTET STRING")
        user_info_axdr_bytes = user_info_item['children'][0]['value']
        self.assertEqual(user_info_axdr_bytes, binascii.unhexlify(axdr_init_req_hex))

        # Optionally decode A-XDR if desired for more detailed test (requires AxdrDecoder)
        # axdr_items, _ = self.axdr_decoder.decode(user_info_axdr_bytes, type_sequence=[
        #     (self.axdr_decoder.decode_unsigned, 1), # dlms-version
        #     (self.axdr_decoder.decode_octet_string, 3), # conformance bits (assuming fixed length for test)
        #     (self.axdr_decoder.decode_unsigned, 2)  # pdu-size
        # ])
        # self.assertEqual(axdr_items[0], 6) # dlms-version
        # self.assertEqual(axdr_items[1], binascii.unhexlify("000060")) # conformance
        # self.assertEqual(axdr_items[2], 1024) # pdu-size


    def test_ber_decode_aare_example(self):
        """Tests decoding of a more complex AARE APDU."""
        # AARE APDU: [APPLICATION 1] IMPLICIT SEQUENCE { ... }
        #   application-context-name    [1] IMPLICIT OBJECT IDENTIFIER (2.16.756.5.8.1.1)
        #   result                      [2] IMPLICIT Association-result (accepted(0))
        #   result-source-diagnostic    [3] IMPLICIT Associate-source-diagnostic (acse-service-user, null(0))
        #   user-information            [30] IMPLICIT OCTET STRING (A-XDR InitiateResponse)
        #     A-XDR InitiateResponse: {
        #       negotiated-dlms-version-number = 6 (Unsigned8)
        #       negotiated-conformance = { get, set } (BIT STRING, e.g. 000060)
        #       server-max-receive-pdu-size = 1024 (Unsigned16)
        #       vaa-name = 0x0007 (Integer16) -> A-XDR for Integer16: 06 (tag) 0007 (value)
        #     }

        # Field 1: application-context-name (OID 2.16.756.5.8.1.1)
        app_ctx_name_tlv = "060760857405080101"
        app_ctx_name_field = "A1" + ("%02X" % (len(app_ctx_name_tlv)//2)) + app_ctx_name_tlv

        # Field 2: result (ENUMERATED accepted(0))
        result_tlv = "0A0100" # ENUMERATED 0
        result_field = "A2" + ("%02X" % (len(result_tlv)//2)) + result_tlv

        # Field 3: result-source-diagnostic (acse-service-user CHOICE {null(0)})
        # This is SEQUENCE { INTEGER, INTEGER }. Here, acse-service-user (1), null (0)
        # BER: A3 LOuter (Context Tag 3, Constructed)
        #        A1 LInner (Context Tag 1, Constructed - for acse-service-user)
        #           02 01 00 (INTEGER 0 for null diagnostic)
        # This structure needs careful checking with ASN.1 spec for Associate-source-diagnostic
        # For simplicity, let's assume it's just an ENUMERATED value for the test for now.
        # Example: acse-service-user (1), null (0) -> ENUMERATED 0 inside User diagnostic
        diag_user_tlv = "0A0100" # ENUMERATED 0 for "null" choice within user diagnostic
        diag_user_field = "A1" + ("%02X" % (len(diag_user_tlv)//2)) + diag_user_tlv # [1] IMPLICIT Associate-source-diagnostic.user
        diag_field = "A3" + ("%02X" % (len(diag_user_field)//2)) + diag_user_field # [3] result-source-diagnostic

        # Field 4: user-information (A-XDR InitiateResponse)
        # A-XDR: 1206 0403000060 100400 060007
        axdr_init_resp_hex = "12060403000060100400060007"
        user_info_tlv_content = axdr_init_resp_hex
        user_info_tlv = "04" + ("%02X" % (len(user_info_tlv_content)//2)) + user_info_tlv_content
        user_info_field = "BE" + ("%02X" % (len(user_info_tlv)//2)) + user_info_tlv

        aare_content_hex = app_ctx_name_field + result_field + diag_field + user_info_field
        aare_apdu_hex = "61" + ("%02X" % (len(aare_content_hex)//2)) + aare_content_hex

        items, _ = self.decoder.decode(binascii.unhexlify(aare_apdu_hex))
        self.assertEqual(len(items), 1, "AARE: Expected one root item.")
        aare_item = items[0]
        self.assertEqual(aare_item['name'], "AARE-apdu")
        self.assertTrue(aare_item['constructed'])
        self.assertEqual(len(aare_item['children']), 4) # Expect 4 children

        # Child 1: application-context-name
        self.assertEqual(aare_item['children'][0]['name'], "application-context-name [1]")
        self.assertEqual(aare_item['children'][0]['children'][0]['value'], "2.16.756.5.8.1.1")

        # Child 2: result
        self.assertEqual(aare_item['children'][1]['name'], "result [2]")
        self.assertEqual(aare_item['children'][1]['children'][0]['value'], 0) # accepted(0)

        # Child 3: result-source-diagnostic
        # Based on simplified structure for test
        self.assertEqual(aare_item['children'][2]['name'], "result-source-diagnostic [3]")
        # This child is constructed, its child is context tag 1, its child is ENUM 0
        self.assertEqual(aare_item['children'][2]['children'][0]['name'], "CONTEXT_SPECIFIC_1") # This name depends on how DLMS_TAGS is set up or if parent_expected_tags is passed down for nested context tags
        self.assertEqual(aare_item['children'][2]['children'][0]['children'][0]['value'], 0)


        # Child 4: user-information
        user_info_item = aare_item['children'][3]
        self.assertEqual(user_info_item['name'], "user-information [30]")
        user_info_axdr_bytes = user_info_item['children'][0]['value']
        self.assertEqual(user_info_axdr_bytes, binascii.unhexlify(axdr_init_resp_hex))
        # Optional: A-XDR decode user_info_axdr_bytes here to verify content
        # axdr_resp_items, _ = self.axdr_decoder.decode(user_info_axdr_bytes, type_sequence=[
        #     (self.axdr_decoder.decode_unsigned, 1), # negotiated_dlms_version_number
        #     (self.axdr_decoder.decode_octet_string, 3), # negotiated_conformance
        #     (self.axdr_decoder.decode_unsigned, 2), # server_max_receive_pdu_size
        #     (self.axdr_decoder.decode_integer, 2)   # vaa_name (Integer16)
        # ])
        # self.assertEqual(axdr_resp_items[0], 6)
        # self.assertEqual(axdr_resp_items[1], binascii.unhexlify("000060"))
        # self.assertEqual(axdr_resp_items[2], 1024)
        # self.assertEqual(axdr_resp_items[3], 7)


    def test_ber_incomplete_data(self):
        """Tests BER decoding with various forms of incomplete/truncated data."""
        # Tag only, no length/value
        items, _ = self.decoder.decode(binascii.unhexlify("02"))
        self.assertEqual(len(items), 1, "Incomplete (Tag only): Expected 1 error item.")
        self.assertEqual(items[0]['name'], "PARSING_ERROR", "Incomplete (Tag only): Error name.")
        self.assertIn("Not enough data for length byte", items[0]['error'], "Incomplete (Tag only): Error message.")

        # Valid T, L, but truncated V
        items, _ = self.decoder.decode(binascii.unhexlify("040548656C")) # OCTET STRING len 5, value "Hel" (3 bytes)
        self.assertEqual(len(items), 1, "Incomplete (Truncated V): Expected 1 error item.")
        self.assertEqual(items[0]['name'], "PARSING_ERROR", "Incomplete (Truncated V): Error name.")
        self.assertIn("Decoded length 5 exceeds available data", items[0]['error'], "Incomplete (Truncated V): Error message.")

        # Incomplete long form length bytes
        items, _ = self.decoder.decode(binascii.unhexlify("048201")) # Expect 2 length bytes for L, only 1 provided (0x01)
        self.assertEqual(len(items), 1, "Incomplete (Long L): Expected 1 error item.")
        self.assertEqual(items[0]['name'], "PARSING_ERROR", "Incomplete (Long L): Error name.")
        self.assertIn("Insufficient data for long-form length bytes", items[0]['error'], "Incomplete (Long L): Error message.")

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
        # Frame content for CRC calculation: Addr(1) + Ctrl(1) + Length_Field(2) + Payload(...)
        # HDLC Length field value = Addr_len(1) + Ctrl_len(1) + Payload_len + CRC_len(2)
        hdlc_length_val = 1 + 1 + len(payload_bytes) + 2

        frame_for_crc = bytes([
            addr_byte, ctrl_byte,
            (hdlc_length_val >> 8) & 0xFF, hdlc_length_val & 0xFF
        ]) + payload_bytes

        crc = crc_check(frame_for_crc)
        if malform_crc:
            crc = crc ^ 0xFFFF # Invert CRC to make it invalid

        full_frame_content = frame_for_crc + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
        return b'\x7E' + full_frame_content + b'\x7E'

    def test_hdlc_decode_valid_frame(self):
        """Tests decoding of a valid HDLC frame with correct CRC."""
        addr = 0x23 # Example client address
        ctrl = 0x10 # Example I-Frame control byte
        payload = b'\x01\x02\x03\x04\x05' # Example payload

        hdlc_frame = self._construct_hdlc_frame(addr, ctrl, payload)
        items, context = self.decoder.decode(hdlc_frame)

        self.assertIsNotNone(items, "Decoder returned None for items.")
        self.assertGreater(len(items), 0, "Decoder returned no items.")
        self.assertNotEqual(items[0].get('name'), 'Error', f"Decoding error: {items[0].get('value')}")

        self.assertEqual(items[0]['name'], 'HDLC Address', "Address field name.")
        self.assertEqual(items[0]['value'], f'0x{addr:02X}', "Address field value.")

        self.assertEqual(items[1]['name'], 'HDLC Control', "Control field name.")
        self.assertIn(f'0x{ctrl:02X}', items[1]['value'], "Control field value (hex).")
        self.assertIn('I-Frame', items[1]['value'], "Control field type string.")

        expected_hdlc_len_field_val = 1 + 1 + len(payload) + 2 # Addr+Ctrl+Payload+CRC
        self.assertEqual(items[2]['name'], 'HDLC Length Field', "Length field name.")
        self.assertEqual(items[2]['value'], str(expected_hdlc_len_field_val), "Length field value.")

        payload_item = items[3]
        self.assertEqual(payload_item['name'], 'HDLC Payload', "Payload field name.")
        self.assertEqual(payload_item['value'], payload.hex(), "Payload content (hex).")
        self.assertIn('Valid', payload_item['children'][0]['value'], "CRC check validity.")

        self.assertIn('hdlc_payload', context, "hdlc_payload in context.")
        self.assertEqual(context['hdlc_payload'], payload, "hdlc_payload content in context.")
        self.assertNotIn('hdlc_crc_error', context, "CRC error flag should not be in context for valid CRC.")


    def test_hdlc_decode_invalid_crc(self):
        """Tests that an invalid CRC is correctly identified."""
        addr = 0x45
        ctrl = 0x93 # Example U-Frame (SNRM)
        payload = b'\xAA\xBB\xCC'

        hdlc_frame_bad_crc = self._construct_hdlc_frame(addr, ctrl, payload, malform_crc=True)
        items, context = self.decoder.decode(hdlc_frame_bad_crc)

        self.assertIsNotNone(items)
        self.assertGreater(len(items), 3, "Expected at least 4 items for a parsed frame (Addr, Ctrl, Len, Payload+CRC).")
        payload_item = items[3]
        self.assertEqual(payload_item['name'], 'HDLC Payload', "Payload field name for invalid CRC case.")
        self.assertIn('Invalid', payload_item['children'][0]['value'], "CRC check should indicate invalid.")
        self.assertTrue(context.get('hdlc_crc_error'), "hdlc_crc_error flag should be True in context.")


    def test_hdlc_frame_too_short(self):
        """Tests error handling for frames shorter than the minimum allowed length."""
        short_frame = b'\x7E\x01\x02\x03\x04\x05\x7E' # 7 bytes total, content is 5 bytes (min content is 6)
        items, _ = self.decoder.decode(short_frame)
        self.assertEqual(items[0]['name'], 'Error', "Error name for too short frame.")
        self.assertIn('too short', items[0]['value'], "Error message for too short frame.")


    def test_hdlc_missing_start_flag(self):
        """Tests error handling for frames missing the start flag."""
        no_start_frame = b'\x01\x02\x03\x04\x05\x06\x07\x08\x7E' # No leading 0x7E
        items, _ = self.decoder.decode(no_start_frame)
        self.assertEqual(items[0]['name'], 'Error', "Error name for missing start flag.")
        self.assertEqual(items[0]['value'], 'No start flag found', "Error message for missing start flag.")

    def test_hdlc_missing_end_flag(self):
        """Tests error handling for frames missing the end flag after a start flag."""
        no_end_frame = b'\x7E\x01\x02\x03\x04\x05\x06\x07\x08' # No trailing 0x7E after content
        items, _ = self.decoder.decode(no_end_frame)
        self.assertEqual(items[0]['name'], 'Error', "Error name for missing end flag.")
        self.assertEqual(items[0]['value'], 'No end flag found after start flag', "Error message for missing end flag.")

    def test_hdlc_control_field_types(self):
        """Tests the `get_control_type` method for I, S, and U frames."""
        # I-Frames (LSB is 0)
        self.assertEqual(self.decoder.get_control_type(0x00), "I-Frame", "Control byte 0x00 (I-Frame)")
        self.assertEqual(self.decoder.get_control_type(0x10), "I-Frame", "Control byte 0x10 (I-Frame)")
        self.assertEqual(self.decoder.get_control_type(0x52), "I-Frame", "Control byte 0x52 (I-Frame)")
        # S-Frames (LSBs are 01)
        self.assertEqual(self.decoder.get_control_type(0x01), "S-Frame", "Control byte 0x01 (S-Frame RR)")
        self.assertEqual(self.decoder.get_control_type(0x05), "S-Frame", "Control byte 0x05 (S-Frame RNR)")
        # U-Frames (LSBs are 11)
        self.assertEqual(self.decoder.get_control_type(0x13), "U-Frame", "Control byte 0x13 (U-Frame SNRM)")
        self.assertEqual(self.decoder.get_control_type(0x6F), "U-Frame", "Control byte 0x6F (U-Frame UA)")
        self.assertEqual(self.decoder.get_control_type(0xFF), "U-Frame", "Control byte 0xFF (U-Frame)")
        # Unknown (if LSBs are 10 - reserved/invalid pattern)
        self.assertEqual(self.decoder.get_control_type(0x02), "Unknown", "Control byte 0x02 (Unknown)")
        self.assertEqual(self.decoder.get_control_type(0x0A), "Unknown", "Control byte 0x0A (Unknown)")


if __name__ == '__main__':
    unittest.main()

[end of tests/test_decoders.py]
