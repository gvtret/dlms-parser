import binascii
from PyQt5.QtWidgets import (QMainWindow, QSplitter, QTextEdit, 
                            QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, 
                            QLabel, QHBoxLayout, QPushButton, QMessageBox, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from core.decoders.ber import BERDecoder
from core.decoders.hdlc import HDLCDecoder
from core.decoders.wrapper import WrapperDecoder
from core.decoders.axdr import AXRDecoder


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
        # Create widgets
        self.hex_edit = QTextEdit()
        self.hex_edit.setPlaceholderText("Enter hex data here...")
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Tag", "Type", "Value", "Description"])

        self.decode_button = QPushButton("Decode")
        self.decoder_combo = QComboBox()
        self.decoder_combo.addItems(self.decoders.keys())

        # Connect signals
        self.decode_button.clicked.connect(self.decode_data)

        # Layout for decoder selection and button
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Decoder:"))
        controls_layout.addWidget(self.decoder_combo)
        controls_layout.addWidget(self.decode_button)
        controls_layout.addStretch()

        # Main layout with splitter
        main_layout = QVBoxLayout()
        
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.hex_edit)
        splitter.addWidget(self.tree_widget)
        splitter.setSizes([200, 600]) # Initial sizes for hex_edit and tree_widget

        main_layout.addLayout(controls_layout)
        main_layout.addWidget(splitter)

        # Central widget
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Status bar
        self.status_bar = self.statusBar() # QMainWindow's built-in status bar
        self.status_bar.showMessage("Ready")

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

        # Get selected decoder
        selected_decoder_name = self.decoder_combo.currentText()
        self.current_decoder = self.decoders.get(selected_decoder_name, self.decoders['BER'])

        # Start decoding thread
        self.decoder_thread = DecoderThread(data, self.current_decoder)
        self.decoder_thread.decoding_complete.connect(self.display_decoded_data)
        self.decoder_thread.error_occurred.connect(self.display_error)
        self.decoder_thread.start()
        self.status_bar.showMessage(f"Decoding using {selected_decoder_name}...")

    def display_decoded_data(self, items):
        self.tree_widget.clear()
        self.populate_tree(None, items)
        self.status_bar.showMessage("Decoding complete.")

    def populate_tree(self, parent_item, items):
        for item_data in items:
            if isinstance(item_data, dict): # Assuming item_data is a dict
                tree_item = QTreeWidgetItem(parent_item or self.tree_widget)
                tree_item.setText(0, item_data.get("tag", ""))
                tree_item.setText(1, item_data.get("type", ""))
                tree_item.setText(2, str(item_data.get("value", "")))
                tree_item.setText(3, item_data.get("description", ""))
                if "children" in item_data and item_data["children"]:
                    self.populate_tree(tree_item, item_data["children"])
            elif isinstance(item_data, list): # If it's a list, iterate through its elements
                 self.populate_tree(parent_item, item_data)
            # Add more conditions here if items can be other types, e.g. simple strings

    def display_error(self, error_message):
        self.status_bar.showMessage(error_message)
        QMessageBox.critical(self, "Decoding Error", error_message)
    
    def detect_protocol(self, data: bytes) -> str:
        """Auto-detect protocol based on data content"""
        # This method might not be strictly necessary if manual selection is preferred
        # For now, let's keep it simple and rely on manual selection or a default
        if not data: # Handle empty data
            return self.decoder_combo.currentText() # or a default like 'BER'

        # Check for HDLC frame (start with 0x7E)
        if data.startswith(b'\x7E'):
            return 'HDLC'
        
        # Check for Wrapper (first byte is version)
        # This is a simplistic check, might need more robust logic
        if data[0] in (0x01, 0x02) and len(data) > 6 : # Wrapper has header and data
             # A more specific check could be if data[1]*256 + data[2] == len(data) - 3 (for version 1)
            return 'Wrapper'
        
        # Default to selected or BER
        return self.decoder_combo.currentText()


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