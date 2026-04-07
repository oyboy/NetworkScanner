import shlex
import time
import subprocess
import os
import json

class ScannerEngine:
    def __init__(self, out_dir):
        self.out_dir = out_dir

    @staticmethod
    def run_nmap(target, flags, output_xml, stage_name, scripts="", verbose=True):
        cmd = ["nmap", "-oX", output_xml]
        if flags: cmd.extend(shlex.split(flags))
        if scripts: cmd.extend(["--script", scripts])
        cmd.extend(shlex.split(target))
        
        if verbose: print(f"  [{stage_name}]\n    $ {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=7200)
            elapsed = time.time() - start_time
            if res.returncode == 0:
                if verbose: print(f"    -> {output_xml}\n")
                return True, elapsed
            else:
                if verbose: print(f"    [ERR] Nmap code {res.returncode}. {res.stderr.decode()[:150]}\n")
                return False, elapsed
        except Exception as e:
            if verbose: print(f"    [ERR] {e}\n")
            return False, 0.0

    @staticmethod
    def run_rustscan(targets_list, nmap_flags, output_xml, stage_name):
        target_str = ",".join(targets_list)
        cmd = ["rustscan", "-a", target_str, "--", "-oX", output_xml]
        if nmap_flags:
            cmd.extend(shlex.split(nmap_flags))
            
        print(f"  [{stage_name} - RustScan]\n    $ {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=7200)
            elapsed = time.time() - start_time
            if os.path.exists(output_xml):
                print(f"    -> {output_xml} ({elapsed:.1f}s)\n")
                return True
            else:
                print(f"    [ERR] RustScan не создал XML. {res.stderr.decode()[:100]}\n")
                return False
        except FileNotFoundError:
            print("    [!] RustScan не установлен! Будет использован Nmap.\n")
            return False

    def prepare_targets(self, targets_with_ports):
        input_file = os.path.join(self.out_dir, "all_targets.txt")
        with open(input_file, "w") as f:
            for ip, data in targets_with_ports.items():
                for port_key in data["ports"].keys():
                    port = port_key.split("/")[0]
                    f.write(f"{ip}:{port}\n")
        return input_file

    def run_httpx(self, input_file, flags):
        if not flags:
            return None
            
        print("[*] Запуск Httpx...")
        urls_out = os.path.join(self.out_dir, "httpx_alive.txt")
        cmd = f"httpx-toolkit -l {input_file} {flags} -o {urls_out}"
        
        try:
            subprocess.run(shlex.split(cmd), capture_output=True, timeout=600)
            alive_urls = []
            if os.path.exists(urls_out):
                with open(urls_out, "r") as f:
                    alive_urls = [line.strip() for line in f if line.strip()]
            print(f"    [+] Httpx обработал {len(alive_urls)} живых Web-энгпоинтов.")
            return urls_out
        except FileNotFoundError:
            print("    [!] httpx-toolkit не установлен.")
            return None

    def run_nuclei(self, target_file, flags, results_dict):
        if not flags:
            return

        print("[*] Запуск Nuclei...")
        nuclei_out = os.path.join(self.out_dir, "nuclei_results.json")
        
        cmd = f"nuclei -l {target_file} {flags} -je {nuclei_out}"
        
        try:
            subprocess.run(shlex.split(cmd), capture_output=True)
            
            if os.path.exists(nuclei_out):
                vuln_count = 0
                with open(nuclei_out, "r") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            finding = json.loads(line)
                            
                            host_field = finding.get("host", "")
                            port = finding.get("port", "")
                            ip = finding.get("ip", "")
                            
                            if not port and ":" in host_field:
                                port = host_field.split(":")[-1]
                            if not ip:
                                ip = host_field.split(":")[0].replace("https://", "").replace("http://", "")

                            vuln_name = finding.get("info", {}).get("name", "Unknown Vuln")
                            severity = finding.get("info", {}).get("severity", "info").upper()
                            cve_list = finding.get("info", {}).get("classification", {}).get("cve-id", [])
                            
                            cve_str = f" ({', '.join(cve_list)})" if cve_list else ""
                            entry = f"[NUCLEI] [{severity}] {vuln_name}{cve_str}"
                            
                            port_key = f"{port}/tcp"
                            if ip in results_dict and port_key in results_dict[ip]["ports"]:
                                if entry not in results_dict[ip]["ports"][port_key]["vulns"]:
                                    results_dict[ip]["ports"][port_key]["vulns"].append(entry)
                                    vuln_count += 1
                        except json.JSONDecodeError:
                            continue
                print(f"    [+] Nuclei завершил работу. Найдено {vuln_count} уязвимостей/мисконфигураций.")
            else:
                print("    [-] Nuclei ничего не нашел.")
        except FileNotFoundError:
            print("    [!] Nuclei не установлен.")