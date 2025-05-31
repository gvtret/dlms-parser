"""
core/decoders/axdr.py

Provides the AxdrDecoder class for decoding A-XDR (Abstract Syntax Description Rules)
encoded data types. A-XDR is commonly used in DLMS/COSEM for encoding data values.
This decoder handles basic A-XDR types and provides placeholders for more complex ones.
"""
import io
from typing import List, Tuple, Any, Callable # Added Callable for type_sequence

class AxdrDecoder:
    """
    A-XDR (Abstract Syntax Description Rules) Decoder.

    Decodes various A-XDR encoded data types from a byte stream.
    This includes integers, booleans, octet strings, and provides a mechanism
    for decoding sequences of types. It also includes placeholders for more
    complex A-XDR types like structures and arrays which are not fully implemented yet.

    The main entry point for decoding a known sequence of types is the `decode` method.
    Individual type decoding methods (e.g., `decode_boolean`, `decode_integer`)
    operate on a provided byte stream.
    """

    def decode_boolean(self, data_stream: io.BytesIO) -> bool:
        """
        Decodes a boolean value from the stream.

        A single byte is read from the stream:
        - 0x00 represents False.
        - 0xFF represents True.

        Args:
            data_stream: An io.BytesIO stream from which to read the boolean byte.

        Returns:
            The decoded boolean value (True or False).

        Raises:
            IndexError: If the stream has insufficient data to read a byte.
            ValueError: If the byte read is not 0x00 or 0xFF.
        """
        byte = data_stream.read(1)
        if not byte:
            raise IndexError("Insufficient data to decode boolean.")
        if byte == b'\x00':
            return False
        elif byte == b'\xff':
            return True
        else:
            raise ValueError(f"Invalid byte for boolean: {byte.hex()}")

    def decode_integer(self, data_stream: io.BytesIO, byte_length: int) -> int:
        """
        Decodes a signed integer of 'byte_length' from the stream.

        The integer is assumed to be in big-endian byte order.
        Supported byte lengths are 1 (int8), 2 (int16), 4 (int32), and 8 (int64).

        Args:
            data_stream: An io.BytesIO stream to read from.
            byte_length: The number of bytes representing the integer.

        Returns:
            The decoded signed integer.

        Raises:
            ValueError: If an unsupported `byte_length` is provided.
            IndexError: If the stream has insufficient data for the specified `byte_length`.
        """
        if byte_length not in (1, 2, 4, 8):
            raise ValueError(f"Unsupported integer byte_length: {byte_length}")

        data = data_stream.read(byte_length)
        if len(data) < byte_length:
            raise IndexError(f"Insufficient data to decode {byte_length}-byte integer.")

        return int.from_bytes(data, byteorder='big', signed=True)

    def decode_unsigned(self, data_stream: io.BytesIO, byte_length: int) -> int:
        """
        Decodes an unsigned integer of 'byte_length' from the stream.

        The integer is assumed to be in big-endian byte order.
        Supported byte lengths are 1 (uint8), 2 (uint16), 4 (uint32), and 8 (uint64).

        Args:
            data_stream: An io.BytesIO stream to read from.
            byte_length: The number of bytes representing the unsigned integer.

        Returns:
            The decoded unsigned integer.

        Raises:
            ValueError: If an unsupported `byte_length` is provided.
            IndexError: If the stream has insufficient data for the specified `byte_length`.
        """
        if byte_length not in (1, 2, 4, 8):
            raise ValueError(f"Unsupported unsigned integer byte_length: {byte_length}")

        data = data_stream.read(byte_length)
        if len(data) < byte_length:
            raise IndexError(f"Insufficient data to decode {byte_length}-byte unsigned integer.")

        return int.from_bytes(data, byteorder='big', signed=False)

    def _decode_length(self, data_stream: io.BytesIO) -> int:
        """
        Decodes an A-XDR length prefix from the stream.

        The A-XDR length prefix is determined as follows:
        - If the first byte is < 0x80, its value is the length.
        - If the first byte is >= 0x80, the lower 7 bits (first_byte & 0x7F)
          indicate the number of subsequent bytes that represent the length.
          The value 0x80 itself is invalid as a length prefix start if it implies
          zero subsequent length bytes in this context.

        Args:
            data_stream: An io.BytesIO stream to read the length prefix from.

        Returns:
            The decoded length.

        Raises:
            IndexError: If insufficient data to read the length prefix.
            ValueError: If the length prefix format is invalid (e.g., 0x80, or too many length bytes).
        """
        first_byte_val = data_stream.read(1)
        if not first_byte_val:
            raise IndexError("Insufficient data to decode length prefix.")

        first_byte = first_byte_val[0]

        if first_byte < 0x80:
            # Single byte length
            return first_byte
        else:
            # Multi-byte length
            num_length_bytes = first_byte & 0x7F # Number of subsequent bytes for length
            if num_length_bytes == 0:
                 raise ValueError("Invalid length prefix: 0x80. If BER indefinite, not supported by this simple decoder. If A-XDR, number of length bytes cannot be zero.")
            if num_length_bytes > 4: # Practical limit for length (e.g., for an octet string)
                raise ValueError(f"Length prefix indicates too many length bytes: {num_length_bytes}")

            length_bytes = data_stream.read(num_length_bytes)
            if len(length_bytes) < num_length_bytes:
                raise IndexError(f"Insufficient data for multi-byte length ({num_length_bytes} bytes expected).")

            return int.from_bytes(length_bytes, byteorder='big', signed=False)


    def decode_octet_string(self, data_stream: io.BytesIO, length: int = None) -> bytes:
        """
        Decodes an octet string (byte string) from the stream.

        If 'length' is provided explicitly, it reads exactly that many bytes.
        Otherwise, it decodes an A-XDR length prefix from the stream to determine
        the number of bytes to read for the octet string.

        Args:
            data_stream: An io.BytesIO stream to read from.
            length: Optional. If provided, this many bytes are read.
                    Otherwise, length is decoded from the stream.

        Returns:
            The decoded octet string as bytes.

        Raises:
            ValueError: If an explicit `length` is negative.
            IndexError: If insufficient data for reading the length or the string itself.
        """
        if length is None:
            # Decode length prefix from stream
            actual_length = self._decode_length(data_stream)
        else:
            # Use provided explicit length
            if length < 0:
                raise ValueError("Explicit length for octet string cannot be negative.")
            actual_length = length

        if actual_length == 0:
            return b"" # Empty octet string

        data = data_stream.read(actual_length)
        if len(data) < actual_length:
            raise IndexError(f"Insufficient data for octet string of length {actual_length}. Expected {actual_length}, got {len(data)}.")
        return data

    # --- Placeholder methods for complex types (Not fully implemented) ---

    def decode_structure(self, data_stream: io.BytesIO, type_definitions: list) -> list:
        """
        Placeholder for decoding a structure (sequence of diverse types).

        A-XDR structures are sequences of components, each with its own type.
        This method would require a schema or list of type definitions to correctly
        decode each component of the structure.

        Args:
            data_stream: The byte stream.
            type_definitions: A list or structure defining the types of the components.

        Returns:
            A list of decoded components.

        Raises:
            NotImplementedError: This method is not yet implemented.
        """
        # Example of how it might work:
        # results = []
        # for type_def in type_definitions:
        #     # This is highly schematic and depends on how type_def is structured
        #     # (e.g., a callable, a tag, a descriptive string)
        #     if type_def == 'integer':
        #         # Need to know byte_length for integer, etc. This highlights complexity.
        #         # results.append(self.decode_integer(data_stream, appropriate_byte_length))
        #         pass
        #     elif type_def == 'boolean':
        #         results.append(self.decode_boolean(data_stream))
        #     # ... and so on for other types
        raise NotImplementedError("decode_structure is not yet implemented.")
        # return results

    def decode_array(self, data_stream: io.BytesIO, type_definition: Any) -> list:
        """
        Placeholder for decoding an array of elements, all of the same type.

        A-XDR arrays are typically prefixed by their length (number of elements),
        followed by the sequence of elements.

        Args:
            data_stream: The byte stream.
            type_definition: Definition of the type of elements in the array.
                             This could be a callable decoding function or type metadata.

        Returns:
            A list of decoded elements.

        Raises:
            NotImplementedError: This method is not yet implemented.
        """
        # Example of how it might work:
        # num_elements = self._decode_length(data_stream) # Standard A-XDR array encoding
        # results = []
        # for _ in range(num_elements):
        #     # type_definition needs to be processed to call the correct decoder
        #     # e.g., if type_definition is a callable function:
        #     #   results.append(type_definition(data_stream))
        #     # or if it's a tag/metadata to dispatch to another method:
        #     #   results.append(self.decode_by_tag(type_definition, data_stream))
        #     pass
        raise NotImplementedError("decode_array is not yet implemented.")
        # return results

    def decode(self, data: bytes, type_sequence: List[Tuple[Callable, ...]] = None) -> Tuple[List[Any], bytes]:
        """
        Decodes a sequence of A-XDR types from a byte string.

        This method acts as a dispatcher. If `type_sequence` is provided, it iterates
        through it, calling the specified decoding methods with their arguments.
        If `type_sequence` is None, it attempts a default decoding strategy:
        tries to decode the entire `data` as a single length-prefixed octet string.

        Args:
            data: The byte string containing A-XDR encoded data.
            type_sequence: Optional. A list of tuples. Each tuple should contain:
                           - The decoding method to call (e.g., self.decode_unsigned).
                           - Any arguments required by that method (e.g., byte_length for integers).
                           Example: `[(self.decode_unsigned, 1), (self.decode_boolean)]`

        Returns:
            A tuple containing:
            - A list of the decoded items.
            - Any remaining bytes from the data stream after decoding.

        Raises:
            NotImplementedError: If called with `type_sequence=None` and the default
                                 strategy is not what's intended for complex data.
            Various (from called methods): IndexError, ValueError if data is malformed or insufficient.
        """
        stream = io.BytesIO(data)
        results: List[Any] = []

        if not type_sequence:
            # Default behavior: attempt to decode as a single length-prefixed octet string.
            # This is a basic fallback, suitable for simple cases or when the data is known
            # to be a single octet string. For complex DLMS messages, a type_sequence or a
            # more sophisticated parsing strategy (like schema-driven parsing) is required.
            try:
                if not data: # Handle empty input data
                    return ["No data to decode"], b""
                item = self.decode_octet_string(stream)
                results.append(item)
            except IndexError as e:
                results.append(f"Default A-XDR decode attempt as octet string failed: {e}")
            except ValueError as e: # Catch errors like invalid length prefix
                results.append(f"Default A-XDR decode attempt as octet string failed with value error: {e}")

            remaining_data = stream.read()
            return results, remaining_data

        # Process according to the provided type_sequence
        for item_type_info in type_sequence:
            method_to_call: Callable = item_type_info[0]
            args = item_type_info[1:] # Subsequent elements in tuple are args for the method
            results.append(method_to_call(stream, *args))

        remaining_data = stream.read()
        return results, remaining_data

    def decode_value_by_type_string(self, data_stream: io.BytesIO, type_str: str) -> Any:
        """
        Decodes a single A-XDR value from the stream based on a type string.

        This method maps a type string (e.g., "boolean", "integer", "octet-string")
        to the appropriate specific decoding method and its required parameters (like byte_length).

        Args:
            data_stream: An io.BytesIO stream to read from.
            type_str: A string identifying the A-XDR type to decode.
                      Supported types: "boolean", "integer" (assumes int8 for now),
                                       "long-integer" (int16), "double-long-integer" (int32),
                                       "long64-integer" (int64),
                                       "unsigned" (uint8), "long-unsigned" (uint16),
                                       "double-long-unsigned" (uint32), "long64-unsigned" (uint64),
                                       "octet-string".

        Returns:
            The decoded value.

        Raises:
            NotImplementedError: If the `type_str` is not supported.
            ValueError: If underlying decode methods raise it (e.g. invalid boolean byte).
            IndexError: If underlying decode methods raise it (e.g. insufficient data).
        """
        # Map type string to decoder method and any fixed arguments (like byte_length)
        # Note: This mapping implies fixed byte lengths for certain types.
        # A more flexible approach might involve passing length info if variable.
        if type_str == "boolean":
            return self.decode_boolean(data_stream)
        elif type_str == "integer": # Defaulting 'integer' to int8 for compact array context
            return self.decode_integer(data_stream, 1)
        elif type_str == "long-integer": # DLMS Blue book: long-integer is int16
            return self.decode_integer(data_stream, 2)
        elif type_str == "double-long-integer": # DLMS Blue book: double-long-integer is int32
            return self.decode_integer(data_stream, 4)
        elif type_str == "long64-integer": # DLMS Blue book: long64-integer is int64
            return self.decode_integer(data_stream, 8)
        elif type_str == "unsigned": # Defaulting 'unsigned' to uint8
            return self.decode_unsigned(data_stream, 1)
        elif type_str == "long-unsigned": # DLMS Blue book: long-unsigned is uint16
            return self.decode_unsigned(data_stream, 2)
        elif type_str == "double-long-unsigned": # DLMS Blue book: double-long-unsigned is uint32
            return self.decode_unsigned(data_stream, 4)
        elif type_str == "long64-unsigned": # DLMS Blue book: long64-unsigned is uint64
            return self.decode_unsigned(data_stream, 8)
        elif type_str == "octet-string":
            # Assumes length prefix is part of the A-XDR encoding for octet-string elements
            return self.decode_octet_string(data_stream)
        # Add other A-XDR types as needed for compact array elements
        # e.g., "float32", "float64", "date", "time", "datetime", "visible-string"
        else:
            raise NotImplementedError(f"A-XDR decoding for type string '{type_str}' is not implemented.")


if __name__ == '__main__':
    # This block provides example usage and basic tests for the AxdrDecoder.
    # It's useful for quick verification during development.
    # To run these examples: `python -m core.decoders.axdr` from the project root,
    # or `python core/decoders/axdr.py` if PYTHONPATH is set appropriately.

    decoder = AxdrDecoder()

    print("--- A-XDR Decoder Example Usage ---")

    # Boolean Examples
    print("\nBoolean Decoding:")
    stream_true = io.BytesIO(b'\xff')
    print(f"Input: ff -> Decoded: {decoder.decode_boolean(stream_true)}")
    stream_false = io.BytesIO(b'\x00')
    print(f"Input: 00 -> Decoded: {decoder.decode_boolean(stream_false)}")
    try:
        stream_invalid_bool = io.BytesIO(b'\x01')
        decoder.decode_boolean(stream_invalid_bool)
    except ValueError as e:
        print(f"Input: 01 -> Error (expected for boolean): {e}")

    # Integer Examples
    print("\nInteger Decoding:")
    stream_int8_neg = io.BytesIO(b'\xfc') # -4 in int8
    print(f"Input: fc (int8) -> Decoded: {decoder.decode_integer(stream_int8_neg, 1)}")
    stream_int16_neg = io.BytesIO(b'\xff\xfc') # -4 in int16
    print(f"Input: fffc (int16) -> Decoded: {decoder.decode_integer(stream_int16_neg, 2)}")
    stream_int32_pos = io.BytesIO(b'\x00\x00\x00\x05') # 5 in int32
    print(f"Input: 00000005 (int32) -> Decoded: {decoder.decode_integer(stream_int32_pos, 4)}")

    # Unsigned Integer Examples
    print("\nUnsigned Integer Decoding:")
    stream_uint8 = io.BytesIO(b'\x05') # 5 in uint8
    print(f"Input: 05 (uint8) -> Decoded: {decoder.decode_unsigned(stream_uint8, 1)}")
    stream_uint16 = io.BytesIO(b'\x01\x00') # 256 in uint16
    print(f"Input: 0100 (uint16) -> Decoded: {decoder.decode_unsigned(stream_uint16, 2)}")

    # Octet String Examples
    print("\nOctet String Decoding:")
    # Explicit length
    stream_os_explicit = io.BytesIO(b'hello')
    print(f"Input: 'hello' (explicit length 5) -> Decoded: {decoder.decode_octet_string(stream_os_explicit, length=5)}")
    # Length prefix (single byte)
    stream_os_len_prefix_short = io.BytesIO(b'\x05hello')
    print(f"Input: 05'hello' (short len prefix) -> Decoded: {decoder.decode_octet_string(stream_os_len_prefix_short)}")
    # Length prefix (zero length)
    stream_os_zero_len = io.BytesIO(b'\x00')
    print(f"Input: 00 (zero length) -> Decoded: {decoder.decode_octet_string(stream_os_zero_len)}")
    # Length prefix (multi-byte)
    stream_os_len_prefix_multi = io.BytesIO(b'\x81\x0bhello world') # length 11 (0x0B)
    print(f"Input: 810B'hello world' (multi-byte len prefix) -> Decoded: {decoder.decode_octet_string(stream_os_len_prefix_multi)}")

    # Example with a longer multi-byte length octet string
    long_os_data = b'A' * 256 # 256 'A' characters
    long_os_encoded = b'\x82\x01\x00' + long_os_data # length 256 (0x0100)
    stream_long_os = io.BytesIO(long_os_encoded)
    decoded_long_os = decoder.decode_octet_string(stream_long_os)
    print(f"Input: 820100... (256 'A's) -> Decoded Length: {len(decoded_long_os)}")


    # Error Case Examples
    print("\nError Case Examples:")
    try:
        stream_err_int = io.BytesIO(b'\x01') # Only 1 byte available
        decoder.decode_integer(stream_err_int, 4) # Expecting 4 bytes
    except IndexError as e:
        print(f"Integer decoding error (expected IndexError): {e}")

    try:
        stream_err_os_len = io.BytesIO(b'\x81') # Multi-byte length prefix, but no length bytes
        decoder.decode_octet_string(stream_err_os_len)
    except IndexError as e:
        print(f"Octet String length decoding error (expected IndexError): {e}")

    try:
        stream_err_os_invalid_len = io.BytesIO(b'\x80') # Invalid length prefix 0x80
        decoder.decode_octet_string(stream_err_os_invalid_len)
    except ValueError as e:
        print(f"Octet String invalid length prefix (expected ValueError): {e}")

    # Generic decode() method Example
    print("\nGeneric decode() Method Example:")
    # Defines a sequence: uint8, boolean, octet_string (length prefixed)
    type_seq_example = [
        (decoder.decode_unsigned, 1),    # decode_unsigned with byte_length=1
        (decoder.decode_boolean,),       # decode_boolean (no extra args)
        (decoder.decode_octet_string,)   # decode_octet_string (length from prefix)
    ]
    # Data: 42 (uint8), True (boolean), "world" (octet_string with length prefix 0x05)
    pdu_data_example = b'\x2a\xff\x05world'
    decoded_items_list, remaining_bytes = decoder.decode(pdu_data_example, type_sequence=type_seq_example)
    print(f"Input PDU: {pdu_data_example.hex()}")
    print(f"Decoded items list: {decoded_items_list}")
    print(f"Remaining bytes: {remaining_bytes.hex()}")

    # Example of default decode (as single octet string)
    print("\nGeneric decode() Method (Default - single Octet String):")
    default_pdu_data = b'\x03cat' # Represents an octet string "cat" with length 3
    decoded_default, remaining_default = decoder.decode(default_pdu_data) # type_sequence is None
    print(f"Input PDU: {default_pdu_data.hex()}")
    print(f"Decoded (default strategy): {decoded_default}") # Should be [b'cat']
    print(f"Remaining (default strategy): {remaining_default.hex()}")


    print("\n--- A-XDR Decoder Example Usage Complete ---")
