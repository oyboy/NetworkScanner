import json
import os
import sys

class ConfigManager:
    def __init__(self, config_path):
        if not os.path.exists(config_path):
            sys.exit(f"[!] Файл конфигурации {config_path} не найден.")
            
        try:
            with open(config_path, encoding="utf-8") as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            sys.exit(f"\n[!] Ошибка синтаксиса в файле {config_path}:\n"
                     f"    {e}\n"
                     f"    [Подсказка]: В стандартном JSON строго запрещены комментарии (//) и запятые после последнего элемента.\n")
        except Exception as e:
            sys.exit(f"\n[!] Неизвестная ошибка при чтении {config_path}:\n    {e}\n")
            
        self.wordlist_users = self.config.get("wordlists/wordlist_users", "/usr/share/wordlists/fasttrack.txt")
        self.wordlist_pass = self.config.get("wordlists/wordlist_pass", "/usr/share/wordlists/rockyou.txt")
            
    def get_mode(self, mode_name):
        mode = self.config.get("modes", {}).get(mode_name)
        if not mode:
            sys.exit(f"[!] Режим '{mode_name}' не найден в конфиге.")
        return mode

    def get_target(self):
        return self.config.get("target", "")

    def get_output_dir(self):
        out_dir = self.config.get("output_dir", "scan_results")
        os.makedirs(out_dir, exist_ok=True)
        return out_dir