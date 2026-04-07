import shlex
import subprocess
from utils import sanitize_name

class ReconEngine:
    def __init__(self, out_dir):
        self.out_dir = out_dir

    def run_amass(self, domain):
        print(f"[*] Запуск Amass для домена: {domain}")
        out_file = os.path.join(self.out_dir, f"amass_{sanitize_name(domain)}.txt")
        cmd = f"amass enum -passive -d {domain} -o {out_file}"
        subprocess.run(shlex.split(cmd), capture_output=True)
        
        subdomains = []
        if os.path.exists(out_file):
            with open(out_file, "r") as f:
                subdomains = [line.strip() for line in f if line.strip()]
        print(f"    [+] Amass нашел {len(subdomains)} поддоменов.")
        return subdomains