import argparse
import json
import os
import subprocess
import sys
import shlex
import time
from datetime import datetime
import xml.etree.ElementTree as ET

def load_config(path="config.json"):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def run_nmap(target, flags, output_xml, stage_name, scripts="", verbose=True):
    cmd = ["nmap", "-oX", output_xml]
    if flags:
        cmd.extend(shlex.split(flags))
    if scripts:
        cmd.extend(["--script", scripts])
    cmd.extend(shlex.split(target))
    
    if verbose:
        print(f"  [{stage_name}]")
        print(f"    $ {' '.join(cmd)}")
    
    start_time = time.time()
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=7200)
        elapsed = time.time() - start_time
        if res.returncode == 0:
            if verbose:
                print(f"    -> {output_xml}\n")
            return True, elapsed
        else:
            if verbose:
                print(f"    [ERR] Nmap code {res.returncode}. {res.stderr.decode()[:150]}\n")
            return False, elapsed
    except Exception as e:
        if verbose:
            print(f"    [ERR] {e}\n")
        return False, 0.0

def update_results_from_xml(xml_path, results):
    if not os.path.exists(xml_path):
        return
    try:
        root = ET.parse(xml_path).getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            
            addr = host.find("address")
            if addr is None:
                continue
            ip = addr.get("addr")
            
            if ip not in results:
                results[ip] = {"os": "", "ports": {}}
            
            osmatch = host.find(".//osmatch")
            if osmatch is not None and not results[ip]["os"]:
                results[ip]["os"] = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"

            for port in host.findall(".//port"):
                state = port.find("state").get("state")
                if state not in ("open", "open|filtered", "unfiltered"):
                    continue
                
                pid = port.get("portid")
                proto = port.get("protocol")
                key = f"{pid}/{proto}"
                
                if key not in results[ip]["ports"]:
                    results[ip]["ports"][key] = {"port": pid, "proto": proto, "state": state, "service": "", "vulns": []}
                
                p_data = results[ip]["ports"][key]
                svc = port.find("service")
                if svc is not None:
                    p_data["service"] = f"{svc.get('name', '')} {svc.get('product', '')} {svc.get('version', '')}".strip()
                
                for script in port.findall(".//script"):
                    script_id = script.get("id", "")
                    raw_out = script.get("output", "")
                    if not raw_out:
                        continue
                        
                    lines = [line.strip() for line in raw_out.split('\n') if line.strip()]
                    
                    if script_id == "vulners":
                        v_count = 0
                        for line in lines:
                            if "CVE-" in line or "*EXPLOIT*" in line:
                                clean_line = " ".join(line.split())
                                entry = f"vulners: {clean_line}"
                                # Берем топ-5 уязвимостей, чтобы не захламлять таблицу
                                if entry not in p_data["vulns"] and v_count < 5:
                                    p_data["vulns"].append(entry)
                                    v_count += 1
                    else:
                        is_vuln = False
                        vuln_title = ""
                        vuln_ids = ""
                        
                        for i, line in enumerate(lines):
                            if line.startswith("VULNERABLE:"):
                                is_vuln = True
                                if i + 1 < len(lines):
                                    vuln_title = lines[i+1]
                            elif "State: VULNERABLE" in line or "State: LIKELY VULNERABLE" in line:
                                is_vuln = True
                            elif line.startswith("IDs:"):
                                vuln_ids = line.replace("IDs:", "").strip()
                            elif "CVE-" in line and not line.startswith("IDs:"):
                                if line not in p_data["vulns"]:
                                    p_data["vulns"].append(line)
                                    
                        if is_vuln and vuln_title:
                            entry = f"{vuln_title} ({vuln_ids})" if vuln_ids else vuln_title
                            if entry not in p_data["vulns"]:
                                p_data["vulns"].append(entry)
    except Exception as e:
        print(f"[!] Ошибка парсинга XML: {e}")

def generate_html_report(results, mode_name, out_dir):
    html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
    <title>Отчет Nmap - {mode_name}</title>
    <style>
        body {{ font-family: Consolas, monospace; background: #1e1e1e; color: #ddd; padding: 20px; }}
        h1 {{ color: #4CAF50; }} 
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #444; padding: 10px; text-align: left; vertical-align: top; }}
        th {{ background: #333; color: #fff; }} 
        tr:nth-child(even) {{ background: #2a2a2a; }}
        .vuln {{ color: #ff5555; font-weight: bold; font-size: 0.9em; display: block; margin-top: 4px; }}
        .svc {{ color: #8be9fd; }} 
        .host {{ background: #282a36; font-size: 1.1em; font-weight: bold; color: #50fa7b; }}
    </style></head><body>
    <h1>Отчет о сканировании: {mode_name}</h1>
    <p>Сгенерировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <table><tr><th>Хост / ОС</th><th>Порт</th><th>Статус</th><th>Сервис и Уязвимости</th></tr>"""
    
    for ip, data in sorted(results.items()):
        ports = data.get("ports", {})
        os_info = data.get("os") or "Неизвестная ОС"
        html += f"<tr class='host'><td colspan='4'>{ip} ({os_info})</td></tr>"
        if not ports:
            html += f"<tr><td></td><td colspan='3'>Открытых портов не найдено</td></tr>"
        for key, p in sorted(ports.items(), key=lambda x: int(x[1]["port"])):
            vulns_html = "".join([f"<span class='vuln'>[!] {v}</span>" for v in p["vulns"]])
            html += f"<tr><td></td><td>{p['port']}/{p['proto']}</td><td>{p['state']}</td><td><span class='svc'>{p['service']}</span>{vulns_html}</td></tr>"

    html += "</table></body></html>"
    report_path = os.path.join(out_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="stealth")
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    config = load_config(args.config)
    mode = config["modes"].get(args.mode)
    if not mode:
        return sys.exit(f"[!] Режим '{args.mode}' не найден.")

    target = config["target"]
    out_dir = config["output_dir"]
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {}

    print(f"\n{'=' * 70}")
    print(f"  Mode:   {mode['name']}")
    print(f"  Target: {target}")
    print(f"  Output: {out_dir}/")
    print(f"{'=' * 70}\n")

    print("[STAGE 1] Host Discovery\n")
    disc_xml = os.path.join(out_dir, f"01_discovery_{ts}.xml")
    success, elapsed = run_nmap(target, mode.get("discovery_flags", "-sn"), disc_xml, "Discovery")
    update_results_from_xml(disc_xml, results)
    
    alive = list(results.keys())
    if not alive:
        return print("  [!] Живых хостов не найдено.\n")
    print(f"  Found {len(alive)} alive hosts ({elapsed:.1f}s)\n")
    for ip in alive:
        print(f"    {ip}")
    print()

    print("[STAGE 2] Port Scan\n")
    scan_target = " ".join(alive) if len(alive) <= 30 else target
    passes = mode.get("port_scan_flags_multi", [{"label": "Main", "flags": mode.get("port_scan_flags", "")}])
    
    for i, p in enumerate(passes):
        pxml = os.path.join(out_dir, f"02_portscan_p{i+1}_{ts}.xml")
        success, elapsed = run_nmap(scan_target, p.get("flags", ""), pxml, f"Pass {i+1}: {p.get('label', 'Main')}")
        update_results_from_xml(pxml, results)

    targets_with_ports = {ip: data for ip, data in results.items() if data["ports"]}
    
    if targets_with_ports:
        port_count = sum(len(d["ports"]) for d in targets_with_ports.values())
        print(f"    -> {port_count} open ports on {len(targets_with_ports)} hosts ({elapsed:.1f}s)\n")
        print(f"  Total: {len(targets_with_ports)} hosts with open ports\n")
        
        for ip, data in sorted(targets_with_ports.items()):
            tcp = [p["port"] for p in data["ports"].values() if p["proto"] == "tcp"]
            udp = [p["port"] for p in data["ports"].values() if p["proto"] == "udp"]
            parts = []
            if tcp: parts.append(f"TCP: {','.join(tcp[:20])}")
            if udp: parts.append(f"UDP: {','.join(udp[:10])}")
            print(f"    {ip:20s} {' | '.join(parts)}")
        print()
    else:
        print("  [!] Открытых портов не найдено.\n")

    svc_flags = mode.get("service_detect_flags", "")
    vuln_scripts = mode.get("vuln_scripts", "")

    if targets_with_ports and svc_flags:
        print("[STAGE 3] Service Detection\n")
        start_svc = time.time()
        for ip, data in targets_with_ports.items():
            ports = [p["port"] for p in data["ports"].values() if p["proto"] == "tcp"]
            if ports:
                xml = os.path.join(out_dir, f"03_svc_{ip.replace('.','_')}_{ts}.xml")
                run_nmap(ip, f"{svc_flags} -p {','.join(ports)}", xml, f"SVC {ip}", verbose=False)
                update_results_from_xml(xml, results)
                print(f"    [OK] {ip} TCP: {','.join(ports)}")
        print(f"\n  Service Detection done ({time.time() - start_svc:.1f}s)\n")

    if targets_with_ports and vuln_scripts:
        print("[STAGE 4] Vulnerability Scripts\n")
        print(f"  Scripts: {vuln_scripts}\n")
        start_vuln = time.time()
        for ip, data in targets_with_ports.items():
            ports = [p["port"] for p in data["ports"].values() if p["proto"] == "tcp"]
            if ports:
                xml = os.path.join(out_dir, f"04_vuln_{ip.replace('.','_')}_{ts}.xml")
                base_flags = svc_flags if svc_flags else "-Pn"
                run_nmap(ip, f"{base_flags} -p {','.join(ports)}", xml, f"VULN {ip}", scripts=vuln_scripts, verbose=False)
                update_results_from_xml(xml, results)
                print(f"    [OK] {ip}")
        print(f"\n  Vuln Scripts done ({time.time() - start_vuln:.1f}s)\n")

    print("[MERGE] Combining all results\n")
    print(f"  Total hosts: {len(results)}\n")
    for ip, data in sorted(results.items()):
        vulns = sum(len(p["vulns"]) for p in data["ports"].values())
        os_str = f"  OS: {data['os']}" if data.get('os') else ""
        v_str = f", {vulns} vuln" if vulns else ""
        print(f"    {ip:20s} {len(data['ports']):3d} ports{v_str}{os_str}")

    rep_path = generate_html_report(results, mode["name"], out_dir)

    print(f"\n{'=' * 70}")
    print(f"  Output: {out_dir}/")
    print(f"  Report: report.html")
    print(f"{'=' * 70}\n")

if __name__ == "__main__":
    main()