import json
import os
from typing import List, Dict, Optional

CONFIG_FILE = "config.json"

class ConfigManager:
    def __init__(self):
        self.config = self._load_config()
    
    def _load_config(self) -> dict:
        """Load configuration from JSON file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return self._default_config()
        return self._default_config()
    
    def _default_config(self) -> dict:
        """Return default configuration"""
        return {
            "owner_uids": [],
            "emotes": {},
            "group_responses_enabled": False
        }
    
    def _save_config(self):
        """Save configuration to JSON file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def set_owner_uids(self, uids: List[str]):
        """Save owner UIDs"""
        self.config["owner_uids"] = uids
        self._save_config()
    
    def get_owner_uids(self) -> List[str]:
        """Get all owner UIDs"""
        return self.config.get("owner_uids", [])
    
    def add_emote(self, name: str, code: str):
        """Save emote command"""
        if "emotes" not in self.config:
            self.config["emotes"] = {}
        self.config["emotes"][name] = code
        self._save_config()
    
    def get_emote(self, name: str) -> Optional[str]:
        """Get single emote code"""
        return self.config.get("emotes", {}).get(name)
    
    def get_all_emotes(self) -> Dict[str, str]:
        """Get all emotes"""
        return self.config.get("emotes", {})
    
    def remove_emote(self, name: str) -> bool:
        """Remove emote command, returns True if found and removed"""
        if "emotes" not in self.config:
            return False
        if name in self.config["emotes"]:
            del self.config["emotes"][name]
            self._save_config()
            return True
        return False
    
    def set_group_responses(self, enabled: bool):
        """Toggle group responses"""
        self.config["group_responses_enabled"] = enabled
        self._save_config()
    
    def get_group_responses(self) -> bool:
        """Get group responses status"""
        return self.config.get("group_responses_enabled", False)

# Global instance
config_manager = ConfigManager()
