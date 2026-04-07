import os
from datetime import datetime

class ReportGenerator:
    @staticmethod
    def generate_html(results, mode_name, out_dir):
        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
        <title>Отчет Аудита - {mode_name}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #121212; color: #e0e0e0; padding: 20px; }}
            h1 {{ color: #00e676; border-bottom: 2px solid #333; padding-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background: #1e1e1e; border-radius: 8px; overflow: hidden; }}
            th, td {{ border: 1px solid #333; padding: 12px 15px; text-align: left; vertical-align: top; }}
            th {{ background: #262626; color: #00e676; font-weight: 600; text-transform: uppercase; font-size: 0.9em; }}
            tr:hover {{ background: #2a2a2a; }}
            .vuln {{ color: #ff5252; font-weight: 500; font-size: 0.95em; display: block; margin-top: 6px; padding: 4px; border-left: 3px solid #ff5252; background: rgba(255, 82, 82, 0.1); }}
            .svc {{ color: #40c4ff; font-weight: bold; }} 
            .host {{ background: #1a237e; font-size: 1.1em; font-weight: bold; color: #fff; }}
            .title-badge {{ background: #333; color: #aaa; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; margin-left: 10px; }}
            .nuclei-critical {{ color: #fff; background: #e53935; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
            .nuclei-high {{ color: #fff; background: #fb8c00; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
            .nuclei-medium {{ color: #000; background: #ffb300; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
            .nuclei-low {{ color: #000; background: #039be5; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
            .nuclei-info {{ color: #fff; background: #00897b; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
        </style></head><body>
        <h1>Глобальный Отчет: {mode_name}</h1>
        <p style="color: #888;">Сгенерировано: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table><tr><th>Хост / ОС</th><th>Порт</th><th>Статус</th><th>Сервис, Web-Title и Находки</th></tr>"""
        
        for ip, data in sorted(results.items()):
            ports = data.get("ports", {})
            os_info = data.get("os") or "ОС не определена"
            html += f"<tr class='host'><td colspan='4'>{ip} <span style='font-weight: normal; color: #aaa;'>({os_info})</span></td></tr>"
            
            if not ports:
                html += f"<tr><td></td><td colspan='3'>Открытых портов не найдено</td></tr>"
                continue
                
            for key, p in sorted(ports.items(), key=lambda x: int(x[1]["port"])):
                formatted_vulns = []
                for v in p["vulns"]:
                    if "[NUCLEI]" in v:
                        parts = v.split("] ", 2)
                        sev = parts[1].replace("[", "") if len(parts) > 2 else "INFO"
                        text = parts[2] if len(parts) > 2 else v
                        formatted_vulns.append(f"<span class='vuln' style='border-left: 3px solid transparent;'><span class='nuclei-{sev.lower()}'>NUCLEI {sev}</span> {text}</span>")
                    else:
                        formatted_vulns.append(f"<span class='vuln'>⚠️ {v}</span>")
                vulns_html = "".join(formatted_vulns)
                
                svc_str = p['service']
                if "[Заголовок:" in svc_str:
                    parts = svc_str.split("[Заголовок:")
                    svc_str = f"<span class='svc'>{parts[0]}</span><span class='title-badge'>Заголовок: {parts[1].replace(']', '')}</span>"
                else:
                    svc_str = f"<span class='svc'>{svc_str}</span>"
                
                html += f"<tr><td></td><td>{p['port']}/{p['proto']}</td><td>{p['state']}</td><td>{svc_str}{vulns_html}</td></tr>"

        html += "</table></body></html>"
        report_path = os.path.join(out_dir, "report.html")
        with open(report_path, "w", encoding="utf-8") as f: f.write(html)
        return report_path