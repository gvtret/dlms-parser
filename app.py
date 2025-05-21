import sys
import binascii
from PyQt5.QtWidgets import (QApplication, QMainWindow, QSplitter, QTextEdit, 
                            QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, 
                            QLabel, QHBoxLayout, QPushButton, QFileDialog, 
                            QMessageBox, QComboBox, QMenu, QAction, QLineEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QTextCursor

from dlms_parser.decoders.ber import BERDecoder
from dlms_parser.decoders.hdlc import HDLCDecoder
from dlms_parser.decoders.wrapper import WrapperDecoder
from dlms_parser.decoders.axdr import AXRDecoder


class DLMSDecoderApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLMS/COSEM Decoder")
        self.setGeometry(100, 100, 1000, 800)
        
        # Initialize decoders
        self.decoders = {
            'HDLC': HDLCDecoder(),
            'Wrapper': WrapperDecoder(),
            'BER': BERDecoder(),
            'A-XDR': AXRDecoder()
        }
        self.current_decoder = None
        
        self.init_ui()
        self.show()
    
    def init_ui(self):
        # Реализация UI (аналогично предыдущему коду)
        pass
    
    def decode_data(self):
        hex_text = self.hex_edit.toPlainText().strip()
        if not hex_text:
            self.tree_widget.clear()
            return
        
        try:
            data = binascii.unhexlify(hex_text.replace(' ', ''))
        except binascii.Error as e:
            self.status_bar.showMessage(f"Invalid hex data: {str(e)}")
            return
        
        # Auto-detect protocol or use selected decoder
        decoder_name = self.detect_protocol(data)
        self.current_decoder = self.decoders.get(decoder_name, self.decoders['BER'])
        
        # Start decoding thread
        self.decoder_thread = DecoderThread(data, self.current_decoder)
        self.decoder_thread.decoding_complete.connect(self.display_decoded_data)
        self.decoder_thread.error_occurred.connect(self.display_error)
        self.decoder_thread.start()
        self.status_bar.showMessage(f"Decoding using {decoder_name}...")
    
    def detect_protocol(self, data: bytes) -> str:
        """Auto-detect protocol based on data content"""
        if len(data) == 0:
            return 'BER'
        
        # Check for HDLC frame (start with 0x7E)
        if data[0] == 0x7E:
            return 'HDLC'
        
        # Check for Wrapper (first byte is version)
        if data[0] in (0x01, 0x02):  # Common wrapper versions
            return 'Wrapper'
        
        # Default to BER
        return 'BER'

class DecoderThread(QThread):
    decoding_complete = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, data: bytes, decoder):
        super().__init__()
        self.data = data
        self.decoder = decoder
    
    def run(self):
        try:
            decoded_items, _ = self.decoder.decode(self.data)
            self.decoding_complete.emit(decoded_items)
        except Exception as e:
            self.error_occurred.emit(f"Decoding failed: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    decoder_app = DLMSDecoderApp()
    sys.exit(app.exec_())