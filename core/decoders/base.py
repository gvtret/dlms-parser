from abc import ABC, abstractmethod
from typing import Dict, Tuple, List, Any

class BaseDecoder(ABC):
    def __init__(self):
        self.context = {}
    
    @abstractmethod
    def decode(self, data: bytes) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Decode the raw data and return decoded items and context"""
        pass
    
    def update_context(self, new_context: Dict[str, Any]):
        """Update the decoder context"""
        self.context.update(new_context)
    
    def reset_context(self):
        """Reset the decoder context"""
        self.context = {}