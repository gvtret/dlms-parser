import sys
from PyQt5.QtWidgets import QApplication
from app import DLMSDecoderApp

def main():
    """Entry point for the application"""
    qt_app = QApplication(sys.argv)
    decoder_app = DLMSDecoderApp()
    sys.exit(qt_app.exec_())

if __name__ == "__main__":
    main()