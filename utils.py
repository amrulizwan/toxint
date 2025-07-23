import os
import json
from datetime import datetime

class ConfigManager:
    def __init__(self):
        self.load_config()
    
    def load_config(self):
        self.config = {}
        
        try:
            with open('config.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        self.config[key] = value
        except FileNotFoundError:
            print("Config file not found, using defaults")
    
    def get(self, key, default=None):
        return self.config.get(key, default)

class ResultsSaver:
    def __init__(self):
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
    
    def save_results(self, module_name, target, results):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{module_name}_{target.replace('/', '_').replace(':', '_')}_{timestamp}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'module': module_name,
                    'target': target,
                    'timestamp': timestamp,
                    'results': results
                }, f, indent=2, ensure_ascii=False)
            
            return filepath
        except Exception as e:
            print(f"Error saving results: {e}")
            return None

class Logger:
    def __init__(self, level="INFO"):
        self.level = level
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def info(self, message):
        self.log(message, "INFO")
    
    def warning(self, message):
        self.log(message, "WARNING")
    
    def error(self, message):
        self.log(message, "ERROR")
