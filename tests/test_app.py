import unittest
import sys

# Add the project root to the Python path to allow importing 'app'
import os
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from PyQt5.QtWidgets import QApplication
from app import DLMSDecoderApp

class TestApp(unittest.TestCase):
    """Test suite for the DLMSDecoderApp."""

    @classmethod
    def setUpClass(cls):
        """Set up the QApplication instance before any tests run."""
        # Ensure a QApplication instance exists.
        # Using instance() is safer in test environments.
        cls.q_app = QApplication.instance()
        if not cls.q_app:
            cls.q_app = QApplication(sys.argv)

    def test_app_instantiation(self):
        """Test if the DLMSDecoderApp can be instantiated."""
        # Attempt to create an instance of DLMSDecoderApp
        try:
            decoder_app = DLMSDecoderApp()
            self.assertIsNotNone(decoder_app, "DLMSDecoderApp instance should not be None.")
            # Optionally, close the window if it's shown during tests,
            # though for instantiation tests it might not be necessary
            # if the window isn't explicitly shown by __init__.
            # decoder_app.close() 
        except Exception as e:
            self.fail(f"DLMSDecoderApp instantiation failed with an exception: {e}")

if __name__ == '__main__':
    unittest.main()
