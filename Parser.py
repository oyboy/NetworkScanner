import os
import xml.etree.ElementTree as ET

class Parser:
    @staticmethod
    def parse_nmap_xml(xml_path, results):
        if not os.path.exists(xml_path): return
        try:
            root = ET.parse(xml_path).getroot()
            for host in root.findall("host"):
                status = host.find("status")
                if status is None or status.get("state") != "up": continue
                
                ip = host.find("address").get("addr")
                if ip not in results:
                    results[ip] = {"os": "", "ports": {}}
                
                osmatch = host.find(".//osmatch")
                if osmatch is not None and not results[ip]["os"]:
                    results[ip]["os"] = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"

                for port in host.findall(".//port"):
                    state = port.find("state").get("state")
                    if state not in ("open", "open|filtered", "unfiltered"): continue
                    
                    pid, proto = port.get("portid"), port.get("protocol")
                    key = f"{pid}/{proto}"
                    
                    if key not in results[ip]["ports"]:
                        results[ip]["ports"][key] = {"port": pid, "proto": proto, "state": state, "service": "", "vulns": []}
                    
                    p_data = results[ip]["ports"][key]
                    
                    svc = port.find("service")
                    if svc is not None:
                        # Сохраняем имя сервиса (http, ssh) и продукт (nginx, OpenSSH)
                        svc_name = svc.get('name', '')
                        svc_product = svc.get('product', '')
                        p_data["service"] = f"{svc_name} {svc_product} {svc.get('version', '')}".strip()
                    
                    for script in port.findall(".//script"):
                        script_id = script.get("id", "")
                        raw_out = script.get("output", "")
                        if not raw_out: continue

                        if script_id == "http-title":
                            title = raw_out.replace("Requested resource was", "").replace("Title:", "").strip().split('\n')[0]
                            if title and "Did not follow redirect" not in title:
                                p_data["service"] += f" [Заголовок: {title}]"
                            continue
                            
                        lines = [line.strip() for line in raw_out.split('\n') if line.strip()]
                        
                        if script_id == "vulners":
                            v_count = 0
                            for line in lines:
                                if ("CVE-" in line or "*EXPLOIT*" in line) and "http" not in line:
                                    clean_line = " ".join([p for p in line.split() if not p.startswith("http")])
                                    entry = f"vulners: {clean_line}"
                                    if entry not in p_data["vulns"] and v_count < 5:
                                        p_data["vulns"].append(entry)
                                        v_count += 1
                        else:
                            is_vuln = False
                            is_unknown = False
                            vuln_title = ""
                            vuln_ids = ""
                            
                            for i, line in enumerate(lines):
                                if line.startswith("VULNERABLE:"):
                                    is_vuln = True
                                    if i + 1 < len(lines): 
                                        vuln_title = lines[i+1].strip()
                                        
                                elif "State: UNKNOWN" in line or "unable to test" in line:
                                    is_unknown = True
                                    
                                elif "State: VULNERABLE" in line or "State: LIKELY VULNERABLE" in line:
                                    is_vuln = True
                                    
                                elif line.startswith("IDs:"):
                                    vuln_ids = line.replace("IDs:", "").strip()
                                    
                                # Отлов одиночных ошибок, игнорируя сырые ссылки
                                elif "CVE-" in line and not line.startswith("IDs:") and not line.startswith("http"):
                                    if line not in p_data["vulns"]: 
                                        p_data["vulns"].append(line)
                                        
                            if is_vuln and not is_unknown and vuln_title:
                                svc_lower = p_data.get("service", "").lower()
                                
                                if "apache" in vuln_title.lower() and "nginx" in svc_lower:
                                    continue
                                if "iis" in vuln_title.lower() and ("nginx" in svc_lower or "apache" in svc_lower):
                                    continue
                                    
                                entry = f"{vuln_title} ({vuln_ids})" if vuln_ids else vuln_title
                                if entry not in p_data["vulns"]: 
                                    p_data["vulns"].append(entry)
        except Exception as e:
            print(f"[!] Ошибка парсинга XML {xml_path}: {e}")