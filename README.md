# dlms-parser
================{}

A DLMS/COSEM parser written in Python 🚀
-----------------------------------------

### Project Purpose and Background

The dlms-parser project is designed to parse DLMS and COSEM messages. DLMS (Device Language Message Specification) is a protocol used for communication between devices in various industries. COSEM (Common Object Security Environment) is a specification for secure communication over a network. This project aims to provide a convenient and efficient way to process and analyze DLMS and COSEM messages, enabling developers to create applications that integrate with DLMS/COSEM devices.

### Features and Functionality

* Parse DLMS and COSEM messages
* Support for multiple message types
* Built-in support for common DLMS and COSEM objects
* Highly configurable and customizable

Note: This project is currently under active development, and some features or components might be incomplete or subject to change.

### Technology Stack

* Language: Python 3.x
* Dependencies:
    * `PyQt5>=5.15` (for the GUI application)
    * Python 3.8+ required

### Installation and Setup

Before getting started, make sure you have Python 3.8+ installed on your system. Then, simply clone the repository and run the following commands:

1. `python setup.py install` 🛠️
2. `python app.py` 🔧 (To run the example GUI application)

### Usage Examples

Here's an example of how to use a decoder (assuming you have raw byte data):

```python
# Example: Using the BER decoder. Adjust import and usage as per actual class names and methods.
from core.decoders.ber import BERDecoder # Example, adjust as per actual class names

# Create a new decoder instance
# Ensure BERDecoder is the correct class name and it's available at this path.
# You might also import directly from the package if installed, e.g., from dlms_parser.core.decoders.ber import BERDecoder
decoder = BERDecoder() # Example instantiation

# Example byte data (replace with your actual data)
hex_data = "0102030405" # Example hex string
byte_data = bytes.fromhex(hex_data)

# Decode the byte data
# The actual method name might be different (e.g., decode_frame, parse)
try:
    decoded_data, _ = decoder.decode(byte_data) # Assuming decode returns a tuple
    # Print the decoded data (structure will depend on the decoder's output)
    print(decoded_data)
except Exception as e:
    print(f"An error occurred during decoding: {e}")

```

### Project Structure

The project consists of the following directories and files:

* `core`: Contains the core parsing and decoding logic.
* `app.py`: A sample GUI application that illustrates how to use the decoders.
* `setup.py`: The setup script for installing the parser.
* `dlms_parser/__init__.py`: Initializes the `dlms_parser` package.
* `tests`: Contains tests for the parsers and decoders.

### Contributing Guidelines

If you'd like to contribute to the project, please follow these guidelines:

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Implement the changes and add tests if necessary
4. Submit a pull request for review

### License Information

This project is licensed under the MIT License. This means you're free to use, modify, and distribute the code as you see fit, but please keep the original authors in mind and give credit where credit is due. ⭐

### Contribution to Development

Development workflow:

* Create a new pull request for a feature or bug fix
* Review and discuss the changes with the community
* Once approved, the changes are merged into the main branch

Code style and standards:

* Python PEP 8 style guide
* Follow the existing code structure and naming conventions

We appreciate any contributions to the project, including bug reports, feature requests, and pull requests. If you have any questions or need help, feel free to reach out to the maintainers. 🛠️