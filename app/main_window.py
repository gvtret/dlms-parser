from PyQt5.QtWidgets import QMainWindow
from ..core.decoders import BERDecoder

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.decoder = BERDecoder()
        # Initialize UI here

def run_app():
    import sys
    from PyQt5.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())