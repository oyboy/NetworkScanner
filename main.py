from ConfigManager import ConfigManager
from ScannerEngine import ScannerEngine
from BruteEngine import BruteForceEngine
from Parser import Parser
from ReconEngine import ReconEngine
from ReportGenerator import ReportGenerator
import argparse
from datetime import datetime
import os
from utils import sanitize_name

class NetworkAudit:
    def __init__(self, args):
        self.config_mgr = ConfigManager(args.config)
        self.mode = self.config_mgr.get_mode(args.mode)
        self.target = self.config_mgr.get_target()
        self.out_dir = self.config_mgr.get_output_dir()
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}
        
        self.recon = ReconEngine(self.out_dir)
        self.scanner = ScannerEngine(self.out_dir)
        self.bruteforce = BruteForceEngine(self.config_mgr.wordlist_users, self.config_mgr.wordlist_pass)

        self.is_external = any(c.isalpha() for c in self.target) and "localhost" not in self.target
        
        self.scanner_type = self.mode.get("scanner", "nmap").lower()

    def execute(self):
        print(f"\n{'=' * 70}\n  Аудит:  {self.mode['name']}\n  Цель:   {self.target}\n  Вывод:  {self.out_dir}/\n  Выбран словарь пользователей: {self.config_mgr.wordlist_users}\n  Выбран словарь с паролями: {self.config_mgr.wordlist_pass}\n {'=' * 70}\n")
        scan_targets = [self.target]

        if self.is_external:
            print("[STAGE 0] Внешняя разведка (Amass)\n")
            subdomains = self.recon.run_amass(self.target)
            if subdomains:
                scan_targets = subdomains
            print()

        print("[STAGE 1] Обнаружение хостов\n")
        alive_hosts = []
        for tg in scan_targets:
            xml = os.path.join(self.out_dir, f"01_disc_{sanitize_name(tg)}_{self.ts}.xml")
            self.scanner.run_nmap(tg, self.mode.get("discovery_flags", "-sn"), xml, f"Discovery {tg}", verbose=False)
            Parser.parse_nmap_xml(xml, self.results)
            
        alive_hosts = list(self.results.keys())
        if not alive_hosts:
            return print("  [!] Живых хостов не найдено.\n")
        print(f"  Найдено {len(alive_hosts)} живых хостов.\n")


        print(f"[STAGE 2] Сканирование портов ({self.scanner_type.upper()})\n")
        scan_target_str = " ".join(alive_hosts) if len(alive_hosts) <= 30 else self.target
        passes = self.mode.get("port_scan_flags_multi", [{"label": "Main", "flags": self.mode.get("port_scan_flags", "")}])
        
        for i, p in enumerate(passes):
            xml = os.path.join(self.out_dir, f"02_portscan_p{i+1}_{self.ts}.xml")
            
            if self.scanner_type == "rustscan":
                success = self.scanner.run_rustscan(alive_hosts, p.get("flags", ""), xml, f"Pass {i+1}: {p.get('label', 'Main')}")
                if not success:
                    print("  [!] Переход на резервный сканер Nmap...\n")
                    self.scanner.run_nmap(scan_target_str, p.get("flags", ""), xml, f"Pass {i+1}: {p.get('label', 'Main')}")
            else:
                self.scanner.run_nmap(scan_target_str, p.get("flags", ""), xml, f"Pass {i+1}: {p.get('label', 'Main')}")
                
            Parser.parse_nmap_xml(xml, self.results)
        
        targets_with_ports = {ip: d for ip, d in self.results.items() if d["ports"]}
        if not targets_with_ports:
            return print("  [!] Открытых портов не найдено.\n")
        
        print("\n[STAGE 3] Определение сервисов\n")
        svc_flags = self.mode.get("service_detect_flags", "-sV -Pn")
        for ip, data in targets_with_ports.items():
            ports = [p["port"] for p in data["ports"].values() if p["proto"] == "tcp"]
            if ports:
                xml = os.path.join(self.out_dir, f"03_svc_{sanitize_name(ip)}_{self.ts}.xml")
                self.scanner.run_nmap(ip, f"{svc_flags} -p {','.join(ports)}", xml, f"SVC: {ip}", verbose=False)
                Parser.parse_nmap_xml(xml, self.results)
                print(f"    [OK] {ip}\n")

        ans = input("[?] Чем сканировать уязвимости? (nmap / nuclei / skip) [nmap]: ").strip().lower()
        if ans in ('nmap', 'n', ''):
            vuln_scripts = self.mode.get('vuln_scripts', "")
            if vuln_scripts:
                print("\n[STAGE 4] Проверка наличия уязвимостей (NMAP)\n")
                for ip, data in targets_with_ports.items():
                    ports = [p["port"] for p in data["ports"].values() if p["proto"] == "tcp"]
                    if ports:
                        xml = os.path.join(self.out_dir, f"04_vuln_nmap_{sanitize_name(ip)}_{self.ts}.xml")
                        base_flags = self.mode.get("service_detect_flags", "-Pn")
                        self.scanner.run_nmap(ip, f"{base_flags} -p {','.join(ports)}", xml, f"VULN: {ip}", scripts=vuln_scripts, verbose=False)
                        Parser.parse_nmap_xml(xml, self.results)
                        print(f"    [OK] {ip}")
            else:
                print("\n[STAGE 4] Пропущен (В конфиге нет параметра vuln_scripts)\n")

        elif ans in ('nuclei', 'nu'):
            httpx_flags = self.mode.get("httpx_flags", "")
            nuclei_flags = self.mode.get("nuclei_flags", "")
            if httpx_flags or nuclei_flags:
                print("\n[STAGE 4] Проверка наличия уязвимостей (NUCLEI + HTTPX)\n")
                target_file = self.scanner.prepare_targets(targets_with_ports)
                
                if httpx_flags:
                    self.scanner.run_httpx(target_file, httpx_flags)                
                if nuclei_flags:
                    self.scanner.run_nuclei(target_file, nuclei_flags, self.results)
            else:
                print("\n[STAGE 4] Пропущен (В конфиге нет параметров nuclei_flags)\n")
        else:
            print("\n[STAGE 4] Сканирование уязвимостей пропущено.\n")
        print()
    
        print("[STAGE 5] Брутфорс аутентификации\n")
        ask_brute = self.mode.get("ask_brute", False)
        if ask_brute:
            ans = input("  [?] Запустить брутфорс паролей (THC Hydra)? [y/N]: ")
            if ans.lower() in ('y', 'yes', 'д', 'да'):
                if os.path.exists(self.bruteforce.users) and os.path.exists(self.bruteforce.passwords):
                    for ip, data in targets_with_ports.items():
                        for port_key, p_data in data["ports"].items():
                            svc_name = p_data.get("service", "").split(" ")[0]
                            if svc_name:
                                self.bruteforce.run_hydra(ip, p_data["port"], svc_name, self.results)
                else:
                    print(f"  [!] Словари для брутфорса не найдены ({self.bruteforce.users}).")
            else:
                print("  [-] Брутфорс отменен пользователем.")
        else:
            print("  [-] Брутфорс пропущен (ask_brute = false).")
        print()


        print("[MERGE] Формирование отчета\n")
        for ip, data in sorted(self.results.items()):
            vulns = sum(len(p["vulns"]) for p in data["ports"].values())
            os_str = f"  OS: {data['os']}" if data.get('os') else ""
            v_str = f", {vulns} находок" if vulns else ""
            print(f"    {ip:20s} {len(data['ports']):3d} портов{v_str}{os_str}")

        rep_path = ReportGenerator.generate_html(self.results, self.mode["name"], self.out_dir)
        print(f"\n{'=' * 70}\n  Отчет готов: {rep_path}\n{'=' * 70}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="stealth")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    net = NetworkAudit(args)
    net.execute()