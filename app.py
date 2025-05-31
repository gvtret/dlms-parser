import sys
import binascii
from PyQt5.QtWidgets import (QApplication, QMainWindow, QSplitter, QTextEdit, 
                            QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, 
                            QLabel, QHBoxLayout, QPushButton, QFileDialog, 
                            QMessageBox, QComboBox, QMenu, QAction, QLineEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QTextCursor

# Attempt to import from package structure first, then fallback for local script execution
try:
    from dlms_parser.core.decoders.ber import BERDecoder
    from dlms_parser.core.decoders.hdlc import HDLCDecoder
    from dlms_parser.core.decoders.wrapper import WrapperDecoder
    from dlms_parser.core.decoders.axdr import AxdrDecoder # Corrected Class Name
except ModuleNotFoundError:
    # Fallback for running app.py directly from its directory, if core is a subdir
    print("Failed to import decoders from dlms_parser.core, trying local core.decoders...")
    from core.decoders.ber import BERDecoder
    from core.decoders.hdlc import HDLCDecoder
    from core.decoders.wrapper import WrapperDecoder
    from core.decoders.axdr import AxdrDecoder # Corrected Class Name


# Mock QTextEdit for testing if GUI is not fully set up
class MockQTextEdit:
    def __init__(self, text=""):
        self._text = text
    def toPlainText(self):
        return self.text_for_decode_data # Use a class variable to easily set test data
    def clear(self): # Add clear method
        pass

MockQTextEdit.text_for_decode_data = "0548656c6c6f" # Default: "Hello" as A-XDR octet string (0x05 "Hello")

# Mock QTreeWidget
class MockQTreeWidget:
    def clear(self):
        print("MockQTreeWidget: Cleared")

# Mock QStatusBar
class MockQStatusBar:
    def showMessage(self, message, timeout=0):
        print(f"MockStatusBar: {message} (timeout: {timeout})")


class DLMSDecoderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLMS/COSEM Decoder")
        self.setGeometry(100, 100, 1000, 800)
        
        # Initialize decoders
        self.decoders = {
            'HDLC': HDLCDecoder(), # Assuming these are correctly implemented elsewhere
            'Wrapper': WrapperDecoder(), # Assuming these are correctly implemented elsewhere
            'BER': BERDecoder(), # Assuming these are correctly implemented elsewhere
            'A-XDR': AxdrDecoder() # Corrected Class Name and instantiation
        }
        self.current_decoder = None
        
        self.init_ui() # Call to initialize UI elements
        self.show()
    
    def init_ui(self):
        # --- Mock UI Elements for testing integration ---
        self.hex_edit = MockQTextEdit()
        self.tree_widget = MockQTreeWidget() # Used in decode_data if hex_text is empty
        self.status_bar = MockQStatusBar()
        # --- End Mock UI Elements ---

        # Add a real button to trigger decoding for manual testing
        # This part is for making the app runnable and manually testable via GUI
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.real_hex_edit = QTextEdit()
        self.real_hex_edit.setPlaceholderText("Enter hex data (e.g., 0548656c6c6f for A-XDR 'Hello')")
        layout.addWidget(self.real_hex_edit)

        self.decode_button = QPushButton("Decode")
        self.decode_button.clicked.connect(self.trigger_decode_from_real_input)
        layout.addWidget(self.decode_button)

        self.result_text = QTextEdit() # To display results
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)
        print("init_ui completed with mock and basic real elements.")

    def trigger_decode_from_real_input(self):
        # Update the mock hex_edit's text from the real one for decode_data to use
        MockQTextEdit.text_for_decode_data = self.real_hex_edit.toPlainText()
        self.decode_data()

    # Placeholder for display_decoded_data and display_error
    # These would normally update the GUI (e.g., QTreeWidget)
    def display_decoded_data(self, decoded_items: list):
        print(f"--- display_decoded_data ---")
        result_str_list = []
        for item in decoded_items:
            if isinstance(item, bytes):
                line = f"  Item (bytes): {item.hex()} ({item.decode('utf-8', 'replace')})"
            else:
                line = f"  Item: {item}"
            print(line)
            result_str_list.append(line)
        self.result_text.setText("\n".join(result_str_list))
        self.status_bar.showMessage("Decoding complete.", 5000)

    def display_error(self, error_message: str):
        print(f"--- display_error ---")
        print(f"  Error: {error_message}")
        self.result_text.setText(f"Error: {error_message}")
        self.status_bar.showMessage(f"Error: {error_message}", 5000)

    def decode_data(self):
        # self.hex_edit is now the MockQTextEdit set up in init_ui
        hex_text = self.hex_edit.toPlainText().strip()
        print(f"\n--- decode_data called ---")
        print(f"Hex input from self.hex_edit (MockQTextEdit): '{hex_text}'")

        if not hex_text:
            self.tree_widget.clear() # MockQTreeWidget.clear()
            self.status_bar.showMessage("No hex data provided.")
            self.result_text.setText("No hex data provided.")
            return
        
        try:
            data = binascii.unhexlify(hex_text.replace(' ', ''))
            print(f"Converted to bytes: {data.hex()}")
        except binascii.Error as e:
            self.status_bar.showMessage(f"Invalid hex data: {str(e)}")
            self.result_text.setText(f"Invalid hex data: {str(e)}")
            return
        
        # --- Integration Test: Force A-XDR decoding ---
        decoder_name = 'A-XDR'
        # Alternatively, use self.detect_protocol(data) if you want to test that logic
        # decoder_name = self.detect_protocol(data)
        print(f"Decoder explicitly set to: {decoder_name}")
        # --- End Integration Test ---

        self.current_decoder = self.decoders.get(decoder_name)

        if not self.current_decoder:
            msg = f"Decoder '{decoder_name}' not found."
            self.status_bar.showMessage(msg)
            self.result_text.setText(msg)
            print(msg)
            return

        self.status_bar.showMessage(f"Decoding using {decoder_name}...")
        
        # Start decoding thread
        self.decoder_thread = DecoderThread(data, self.current_decoder)
        # Connect signals to the placeholder methods
        self.decoder_thread.decoding_complete.connect(self.display_decoded_data)
        self.decoder_thread.error_occurred.connect(self.display_error)
        self.decoder_thread.start()
        print(f"DecoderThread started for {decoder_name}.")
    
    def detect_protocol(self, data: bytes) -> str:
        """Auto-detect protocol based on data content"""
        print(f"detect_protocol called with data (first 10 bytes): {data[:10].hex()}")
        if len(data) == 0:
            print("detect_protocol: No data, defaulting to BER for now.")
            return 'BER' # Original behavior for empty data
        
        if data[0] == 0x7E: # Check for HDLC frame
            print("detect_protocol: Detected HDLC.")
            return 'HDLC'
        
        if data[0] in (0x01, 0x02):  # Common wrapper versions
            print("detect_protocol: Detected Wrapper.")
            return 'Wrapper'
        
        # Default for this test if others don't match, can be A-XDR or BER
        # For focused A-XDR testing via this path, change to 'A-XDR'
        print("detect_protocol: No specific protocol detected, defaulting to BER.")
        return 'BER'

class DecoderThread(QThread):
    decoding_complete = pyqtSignal(list) # Expects a list of decoded items
    error_occurred = pyqtSignal(str)
    
    def __init__(self, data: bytes, decoder):
        super().__init__()
        self.data = data
        self.decoder = decoder
    
    def run(self):
        print(f"DecoderThread ({self.decoder.__class__.__name__}) run method started with data: {self.data.hex()}")
        try:
            # AxdrDecoder.decode now has a default behavior if type_sequence is None
            # It returns (results_list, remaining_bytes)
            decoded_items, remaining_bytes = self.decoder.decode(self.data)
            print(f"DecoderThread: Decoded items: {decoded_items}, Remaining bytes: {remaining_bytes.hex()}")
            self.decoding_complete.emit(decoded_items) # Emit the list of items
        except Exception as e:
            import traceback
            print(f"!!! Error in DecoderThread.run() for {self.decoder.__class__.__name__} !!!")
            traceback.print_exc() # Print full traceback to console for debugging
            self.error_occurred.emit(f"Decoding failed in thread: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    decoder_app = DLMSDecoderApp()

    # --- For quick non-GUI test of A-XDR decoding flow ---
    # Set hex string for A-XDR (e.g., 0548656c6c6f for "Hello")
    # MockQTextEdit.text_for_decode_data = "0548656c6c6f"
    # To test empty data for A-XDR:
    # MockQTextEdit.text_for_decode_data = ""
    # To test insufficient data for A-XDR octet string:
    # MockQTextEdit.text_for_decode_data = "054865" # Length 5, data "He"

    # print("\n>>> Running initial decode_data for testing A-XDR integration (non-GUI check)...")
    # decoder_app.decode_data() # Trigger decode directly with the default A-XDR hex in MockQTextEdit
    # print("<<< Initial decode_data finished.\n")
    # --- End quick non-GUI test ---

    sys.exit(app.exec_())