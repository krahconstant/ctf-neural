"""
CTF·NEURAL v6.1 — Architecture honnête & couverture complète
Principe : on n'affiche JAMAIS un flag qui n'a pas été trouvé par exécution réelle.
Le LLM génère du code, le serveur l'exécute, le flag vient du stdout réel.

v6.1 : optimisations mémoire pour Render Free (512 MB)
- 1 seul worker gunicorn recommandé
- build_ctx réduit (~60% moins de RAM)
- del ctx après étape 1
- strings limitées à 100
"""
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import json, zipfile, tarfile, re, os, tempfile, subprocess, time, stat, shutil, requests, base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "X-API-Key"],
     methods=["GET", "POST", "OPTIONS"])

@app.after_request
def cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

UPLOAD_DIR  = tempfile.mkdtemp()
SANDBOX_DIR = tempfile.mkdtemp()
MAX_SIZE    = 30 * 1024 * 1024

GROQ_PRIMARY  = "llama-3.3-70b-versatile"
GROQ_FALLBACK = ["llama-3.1-8b-instant", "gemma2-9b-it", "mixtral-8x7b-32768"]

def groq_models(api_key):
    try:
        r = requests.get("https://api.groq.com/openai/v1/models",
                         headers={"Authorization": f"Bearer {api_key}"}, timeout=4)
        if r.status_code == 200:
            all_m = r.json().get("data", [])
            active = [m["id"] for m in all_m
                      if m.get("active", True)
                      and not any(x in m["id"] for x in ["whisper","guard","tts","vision"])]
            p = [m for m in active if "3.3" in m]
            o = [m for m in active if "3.3" not in m]
            return (p + o)[:6] if active else [GROQ_PRIMARY] + GROQ_FALLBACK
    except: pass
    return [GROQ_PRIMARY] + GROQ_FALLBACK

def llm(api_key, prompt, system="", max_tokens=4096):
    models = groq_models(api_key)
    sys_msg = system or "Tu es un expert CTF. Génère du code Python précis et fonctionnel."
    last_err = None
    for model in models:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model,
                      "messages": [{"role":"system","content":sys_msg},{"role":"user","content":prompt}],
                      "max_tokens": min(max_tokens, 8000), "temperature": 0.1},
                timeout=90)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"], model
            elif r.status_code == 429:
                last_err = f"rate-limit {model}"; time.sleep(3); continue
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                if any(x in err for x in ["decommissioned","deprecated","not found"]):
                    last_err = f"déprécié: {model}"; continue
                raise Exception(f"{model}: {err}")
        except requests.exceptions.Timeout:
            last_err = f"timeout {model}"; continue
        except Exception as e:
            if any(x in str(e).lower() for x in ["decommission","deprecat","rate","429","not found"]):
                last_err = str(e); time.sleep(2); continue
            raise
    raise Exception(f"Aucun modèle disponible. ({last_err})")

def run(cmd, timeout=25, cwd=None, stdin=None, env_extra=None):
    env = {
        **os.environ,
        "PATH": (
            "/usr/bin:/bin:/usr/local/bin:/usr/sbin:/sbin"
            ":/usr/games:/usr/local/games:/snap/bin:/opt/local/bin"
            ":/root/.local/bin:/home/user/.local/bin"
        ),
        "TERM": "xterm",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str), capture_output=True, text=True,
            timeout=timeout, cwd=cwd or SANDBOX_DIR, input=stdin, env=env
        )
        return {"out": r.stdout[:20000], "err": r.stderr[:6000], "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"out": "", "err": f"Timeout {timeout}s", "code": -1}
    except Exception as e:
        return {"out": "", "err": str(e), "code": -1}

def tool_available(name):
    return bool(shutil.which(name))

def run_py(code, timeout=45, cwd=None):
    work_dir = cwd or SANDBOX_DIR
    tmp = os.path.join(SANDBOX_DIR, f"sol_{int(time.time()*1000)}.py")
    try:
        with open(tmp, "w") as f:
            f.write(code)
        return run(["python3", "-u", tmp], timeout=timeout, cwd=work_dir)
    finally:
        try: os.remove(tmp)
        except: pass

def pip_install(packages):
    if not packages: return
    safe = [p for p in packages if re.match(r"^[a-zA-Z0-9_\-\.\[\]]+$", p)]
    if safe:
        run(
            f"pip install --quiet --break-system-packages {' '.join(safe)}",
            timeout=90
        )

def extract_code(text):
    m = re.search(r'```python\n([\s\S]*?)```', text)
    if m and len(m.group(1).strip()) > 20: return m.group(1).strip()
    m = re.search(r'```\n([\s\S]*?)```', text)
    if m and len(m.group(1).strip()) > 20: return m.group(1).strip()
    lines = text.split('\n'); code_lines = []; in_code = False
    for line in lines:
        if re.match(r'^(import |from |def |class |#!|#!/)', line): in_code = True
        if in_code: code_lines.append(line)
    if len(code_lines) > 5: return '\n'.join(code_lines)
    return ""

PLACEHOLDERS = {
    "CTF{...}","CTF{flag}","FLAG{...}","CTF{example}","FLAG{example}",
    "CTF{your_flag}","flag{...}","CTF{REDACTED}","CTF{placeholder}",
    "FLAG{flag_here}","CTF{flag_here}","flag{flag}","CTF{insert_flag}",
    "CTF{?}","CTF{test}","CTF{XXXXX}","FLAG{XXXXX}",
}

def find_flag(text):
    if not text: return None
    standard = re.findall(
        r'\b[A-Za-z0-9_\-]+\{[A-Za-z0-9_\-!@#$%^&*()+=/\\.,;:\'"<>? ]{4,120}\}', text)
    for candidate in standard:
        if candidate in PLACEHOLDERS: continue
        if re.match(r'^(CTF|FLAG|flag|ctf)\{\\.+\}$', candidate): continue
        if len(candidate) < 8: continue
        if re.match(r'^[A-Za-z]+\{[0-9]+\}$', candidate) and len(candidate) < 12: continue
        return candidate
    for m in re.findall(r'(?:flag|Flag|FLAG)\s*[:=]\s*([A-Za-z0-9+/]{16,}={0,2})', text):
        try:
            decoded = base64.b64decode(m + "==").decode("utf-8", errors="replace")
            found = find_flag(decoded)
            if found: return found
        except: pass
    for m in re.findall(r'(?:flag|hex|output)\s*[:=]\s*([0-9a-fA-F]{20,})', text, re.IGNORECASE):
        try:
            decoded = bytes.fromhex(m).decode("utf-8", errors="replace")
            found = find_flag(decoded)
            if found: return found
        except: pass
    m = re.search(r'(?:flag|Flag|FLAG)\s*[:=]\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', text)
    if m: return m.group(1)
    return None

def analyze_file(filepath, filename):
    ext  = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath)
    info = {"name":filename,"size":size,"ext":ext,"text":"","hex":"","strings":[],
            "files":[],"file_type":"","static":{},"extra":{}}
    r = run(["file", filepath])
    info["file_type"] = r["out"].strip()
    TEXT_EXT = {
        '.py','.js','.ts','.c','.cpp','.h','.rs','.go','.java','.rb','.php','.html',
        '.css','.sh','.md','.json','.xml','.yaml','.yml','.asm','.s','.txt','.sage',
        '.pl','.lua','.kt','.cs','.r','.swift','.vb','.ps1','.bat','.ex','.exs',
        '.erl','.nim','.sol','.vy','.cairo','.sql','.graphql','.gql','.pem','.crt',
        '.key','.env','.conf','.cfg','.ini','.toml','.dockerfile',
    }
    if ext in TEXT_EXT or (size < 500_000 and not ext):
        try:
            with open(filepath, 'r', errors='replace') as f:
                info["text"] = f.read(30000)  # réduit de 60000 → 30000
        except: pass
    if not info["text"]:
        r = run(["xxd", filepath]); info["hex"] = r["out"][:5000]  # réduit de 10000 → 5000
        r = run(["strings", "-n", "5", filepath])
        info["strings"] = [s for s in r["out"].split("\n") if s.strip()][:100]  # réduit de 300 → 100
    if ext == '.zip': _handle_zip(filepath, info)
    elif ext in ['.tar','.gz','.tgz','.bz2','.xz']: _handle_tar(filepath, info)
    elif ext == '.7z': run(f"7z x -y -o{SANDBOX_DIR} {filepath}", timeout=30)
    if "ELF" in info["file_type"]: _handle_elf(filepath, filename, info)
    elif "PE32" in info["file_type"] or "PE+" in info["file_type"] or ext in ['.exe','.dll']:
        _handle_pe(filepath, filename, info)
    elif ext in ['.class','.jar'] or "Java" in info["file_type"]: _handle_java(filepath, filename, info)
    elif ext == '.pyc' or "python" in info["file_type"].lower(): _handle_pyc(filepath, filename, info)
    elif ext in ['.png','.jpg','.jpeg','.bmp','.gif','.tiff','.webp']: _handle_image(filepath, filename, info)
    elif ext in ['.wav','.mp3','.flac','.ogg','.m4a']: _handle_audio(filepath, filename, info)
    elif ext in ['.pcap','.pcapng','.cap']: _handle_pcap(filepath, filename, info)
    elif ext == '.pdf': _handle_pdf(filepath, filename, info)
    return info

def _copy_to_sandbox(filepath, filename):
    dst = os.path.join(SANDBOX_DIR, filename)
    if not os.path.exists(dst): shutil.copy2(filepath, dst)
    return dst

def _handle_zip(filepath, info):
    try:
        with zipfile.ZipFile(filepath) as z:
            info["files"] = z.namelist()
            parts = []
            for name in info["files"][:30]:  # réduit de 50 → 30
                if any(name.endswith(e) for e in ['.py','.js','.c','.txt','.md','.json','.sh',
                        '.php','.html','.sage','.rb','.rs','.go','.java','.cs','.sol','.pem','.key',
                        '.xml','.yaml','.sql','.graphql']):
                    try:
                        content = z.read(name).decode('utf-8', errors='replace')[:4000]  # réduit de 8000 → 4000
                        parts.append(f"=== {name} ===\n{content}")
                    except: pass
            if parts: info["text"] = "\n\n".join(parts)
            z.extractall(SANDBOX_DIR)
    except Exception as e: info["text"] += f"\n[Erreur ZIP: {e}]"

def _handle_tar(filepath, info):
    try:
        with tarfile.open(filepath) as t:
            info["files"] = t.getnames()
            t.extractall(SANDBOX_DIR)
            parts = []
            for m in t.getmembers()[:30]:  # réduit de 50 → 30
                if m.isfile() and any(m.name.endswith(e) for e in [
                        '.py','.js','.c','.txt','.md','.json','.sh','.php','.html',
                        '.sage','.rb','.rs','.go','.java','.cs','.sol','.pem','.key']):
                    try:
                        f = t.extractfile(m)
                        if f:
                            content = f.read(4000).decode('utf-8', errors='replace')  # réduit de 8000 → 4000
                            parts.append(f"=== {m.name} ===\n{content}")
                    except: pass
            if parts: info["text"] = "\n\n".join(parts)
    except Exception as e: info["text"] += f"\n[Erreur TAR: {e}]"

def _handle_elf(filepath, filename, info):
    try: os.chmod(filepath, stat.S_IRWXU)
    except: pass
    _copy_to_sandbox(filepath, filename)
    info["static"]["symbols"]  = run(["nm", "--demangle", filepath])["out"][:3000]  # réduit
    info["static"]["disasm"]   = run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", filepath])["out"][:8000]  # réduit de 15000 → 8000
    info["static"]["readelf"]  = run(["readelf", "-h", "-S", "-d", filepath])["out"][:3000]
    info["static"]["checksec"] = run(f"checksec --file={filepath} 2>/dev/null || python3 -c \"import pwn; print(pwn.checksec('{filepath}'))\" 2>/dev/null", timeout=8)["out"][:1000]
    info["static"]["ltrace"]   = run(["ltrace", "-e", "strcmp+strncmp+memcmp", filepath], timeout=3, stdin="\n\n\n")["err"][:2000]

def _handle_pe(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    pe_script = f"""
import subprocess, sys
try:
    import pefile
    pe = pefile.PE(r'{filepath}')
    print("== SECTIONS ==", [s.Name.decode().strip() for s in pe.sections])
    print("\\n== IMPORTS ==")
    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        print(f"  {{entry.dll.decode()}}:")
        for imp in entry.imports[:15]:
            if imp.name: print(f"    {{imp.name}}")
except ImportError:
    pass
r = subprocess.run(['strings', '-n', '6', r'{filepath}'], capture_output=True, text=True, timeout=10)
print("\\n== STRINGS =="); print(r.stdout[:3000])
"""
    result = run_py(pe_script, timeout=20)
    info["static"]["pe_analysis"] = (result["out"] + result["err"])[:4000]
    if "CIL" in info["file_type"] or ".NET" in info["file_type"]:
        r = run(["monodis", "--output=/dev/stdout", filepath], timeout=15)
        info["static"]["dotnet_il"] = r["out"][:5000]

def _handle_java(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.jar':
        run(f"cd {SANDBOX_DIR} && jar xf {os.path.join(SANDBOX_DIR, filename)}", timeout=15)
        r = run(["find", SANDBOX_DIR, "-name", "*.class"], timeout=5)
        classes = [c.strip() for c in r["out"].strip().split("\n") if c.strip()][:5]
        parts = []
        for cls in classes:
            r2 = run(["javap", "-c", "-private", cls], timeout=10)
            parts.append(f"=== {cls} ===\n{r2['out'][:2000]}")
        info["static"]["java_disasm"] = "\n".join(parts)[:6000]
    else:
        r = run(["javap", "-c", "-private", filepath], timeout=10)
        info["static"]["java_disasm"] = (r["out"] + r["err"])[:5000]

def _handle_pyc(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    decompile_script = f"""
import dis, marshal, types, sys
try:
    with open(r'{filepath}', 'rb') as f:
        f.read(16)
        code = marshal.loads(f.read())
    print("=== DISASSEMBLY ==="); dis.dis(code)
    print("\\n=== CONSTANTS ===")
    def extract_consts(co, depth=0):
        prefix = "  " * depth
        for c in co.co_consts:
            if isinstance(c, (str, bytes, int, float)): print(f"{{prefix}}{{repr(c)}}")
            if isinstance(c, types.CodeType): extract_consts(c, depth+1)
    extract_consts(code)
except Exception as e:
    print(f"Erreur marshal: {{e}}")
    import subprocess
    r = subprocess.run(['python3', '-m', 'uncompyle6', r'{filepath}'], capture_output=True, text=True, timeout=20)
    print(r.stdout or r.stderr)
"""
    result = run_py(decompile_script, timeout=25)
    info["static"]["pyc_decompile"] = (result["out"] + result["err"])[:6000]  # réduit de 10000 → 6000

def _handle_image(filepath, filename, info):
    dst = _copy_to_sandbox(filepath, filename)
    r = run(["exiftool", filepath], timeout=10); info["extra"]["exiftool"] = r["out"][:2000]
    r = run(["binwalk", "--extract", "--quiet", filepath], timeout=30, cwd=SANDBOX_DIR)
    info["extra"]["binwalk"] = r["out"][:2000]
    r = run(["strings", "-n", "5", filepath])
    info["strings"] = [s for s in r["out"].split("\n") if s.strip()][:100]  # réduit de 200 → 100
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.png','.bmp']:
        r = run(["zsteg", filepath], timeout=15); info["extra"]["zsteg"] = (r["out"]+r["err"])[:2000]
    r = run(["steghide", "extract", "-sf", filepath, "-p", "", "-f", "-xf", "/dev/stdout"], timeout=10)
    if r["code"] == 0 and r["out"]: info["extra"]["steghide"] = r["out"][:1000]
    steg_script = f"""
from PIL import Image
import numpy as np
try:
    img = Image.open(r'{filepath}')
    print(f"Mode: {{img.mode}}, Size: {{img.size}}")
    arr = np.array(img)
    if arr.ndim >= 3:
        lsb_flat = (arr[:,:,0] & 1).flatten()[:1000]
        lsb_bytes = bytearray()
        for i in range(0, len(lsb_flat)-7, 8):
            byte = 0
            for b in range(8): byte = (byte << 1) | int(lsb_flat[i+b])
            lsb_bytes.append(byte)
        decoded = lsb_bytes.decode('ascii', errors='replace')
        print(f"LSB preview: {{''.join(c if 32<=ord(c)<127 else '.' for c in decoded[:200])}}")
except Exception as e: print(f"PIL: {{e}}")
"""
    result = run_py(steg_script, timeout=15); info["extra"]["image_analysis"] = (result["out"]+result["err"])[:2000]

def _handle_audio(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    r = run(["exiftool", filepath], timeout=10); info["extra"]["exiftool"] = r["out"][:1500]
    r = run(["binwalk", filepath], timeout=15); info["extra"]["binwalk"] = r["out"][:1500]
    r = run(["strings", "-n", "5", filepath])
    info["strings"] = [s for s in r["out"].split("\n") if s.strip()][:80]  # réduit de 150 → 80
    info["extra"]["note"] = "Audio: vérifier spectrogramme (Audacity/Sonic Visualiser), DTMF, morse, LSB audio"

def _handle_pcap(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    for key, args in [
        ("tshark_conv", ["tshark", "-r", filepath, "-q", "-z", "conv,tcp"]),
        ("tshark_proto", ["tshark", "-r", filepath, "-q", "-z", "io,phs"]),
        ("tshark_stream0", ["tshark", "-r", filepath, "-q", "-z", "follow,tcp,ascii,0"]),
    ]:
        r = run(args, timeout=15); info["extra"][key] = r["out"][:2000]  # réduit de 3000 → 2000
    r = run(f"tshark -r {filepath} -Y http -T fields -e http.request.method -e http.request.uri -e http.response.code 2>/dev/null | head -50", timeout=15)
    info["extra"]["http_requests"] = r["out"][:1500]
    r = run(f"tshark -r {filepath} -Y dns -T fields -e dns.qry.name 2>/dev/null | sort -u | head -50", timeout=15)
    info["extra"]["dns_queries"] = r["out"][:800]
    pcap_script = f"""
try:
    from scapy.all import rdpcap, TCP, UDP, ICMP, DNS, Raw
    pkts = rdpcap(r'{filepath}')
    print(f"Total paquets: {{len(pkts)}}")
    protos = {{}}
    for p in pkts:
        for proto in [TCP, UDP, ICMP, DNS]:
            if p.haslayer(proto): protos[proto.__name__] = protos.get(proto.__name__,0)+1
    print(f"Protocoles: {{protos}}")
    payloads = []
    for p in pkts:
        if p.haslayer(Raw):
            try:
                data = p[Raw].load.decode('utf-8', errors='replace')
                if any(k in data.lower() for k in ['flag','ctf','password','secret','key']):
                    payloads.append(data[:300])
            except: pass
    if payloads:
        print("=== PAYLOADS SUSPECTS ===")
        for pl in payloads[:5]: print(repr(pl))
except Exception as e: print(f"scapy error: {{e}}")
"""
    result = run_py(pcap_script, timeout=30); info["extra"]["scapy_analysis"] = (result["out"]+result["err"])[:3000]

def _handle_pdf(filepath, filename, info):
    _copy_to_sandbox(filepath, filename)
    r = run(["pdftotext", filepath, "-"], timeout=15); info["text"] = r["out"][:10000]  # réduit de 20000 → 10000
    r = run(["exiftool", filepath], timeout=10); info["extra"]["exiftool"] = r["out"][:1500]
    r = run(["binwalk", filepath], timeout=15); info["extra"]["binwalk"] = r["out"][:1500]
    r = run(["strings", "-n", "5", filepath])
    info["strings"] = [s for s in r["out"].split("\n") if s.strip()][:100]  # réduit de 200 → 100

CAT_KEYWORDS = {
    "pwn": {
        "overflow": 4, "buffer overflow": 5, "stack overflow": 5,
        "rop": 5, "ret2libc": 5, "ret2win": 5, "one_gadget": 4,
        "heap": 3, "tcache": 5, "fastbin": 5, "unsorted bin": 5,
        "use after free": 5, "uaf": 5, "double free": 5,
        "format string": 5, "printf(": 3, "%p %p": 4, "%n": 4,
        "got": 3, "plt": 3, "libc": 3, "shellcode": 4,
        "pwntools": 5, "remote(": 4, "process(": 3,
        "pie": 2, "aslr": 2, "canary": 3, "nx": 2,
        "off by one": 5, "off-by-one": 5, "fsop": 5,
    },
    "reverse": {
        "reversing": 4, "reverse engineering": 5, "decompile": 4,
        "disassemble": 4, "disassembly": 4, "ghidra": 4, "ida": 4,
        "angr": 3, "radare2": 3, "r2": 2,
        "vm": 2, "virtual machine": 3, "bytecode": 3,
        "obfuscation": 4, "anti-debug": 4, "anti-disassembly": 4,
        "crackme": 5, "keygen": 4, "license": 2,
        "strcmp": 3, "strncmp": 3, "check_flag": 4, "verify": 2,
        "xor encrypt": 3, "custom cipher": 3,
    },
    "web": {
        "http": 2, "https": 2, "url": 2, "endpoint": 3,
        "sql injection": 5, "sqli": 5, "union select": 5,
        "xss": 5, "cross site": 4, "script injection": 4,
        "ssti": 5, "server side template": 5, "jinja2": 4, "twig": 4,
        "lfi": 5, "local file inclusion": 5, "path traversal": 4,
        "ssrf": 5, "server side request": 5,
        "xxe": 5, "xml injection": 4,
        "idor": 5, "insecure direct": 4,
        "jwt": 4, "json web token": 4, "bearer": 3,
        "cookie": 3, "session": 2, "csrf": 4,
        "deserialization": 4, "pickle": 4, "unserialize": 4,
        "graphql": 4, "mutation": 3, "query": 2,
        "flask": 3, "django": 3, "express": 2, "php": 3,
        "login": 2, "admin": 2, "password": 2,
        "request": 2, "response": 2, "curl": 2,
        "race condition": 4, "oauth": 4, "cors": 3,
    },
    "crypto": {
        "rsa": 5, "modulus": 4, "public key": 4, "private key": 4,
        "aes": 5, "des": 4, "3des": 4, "rc4": 4,
        "xor": 3, "xor key": 4,
        "caesar": 4, "vigenere": 4, "rot13": 3, "rot": 2,
        "elliptic curve": 5, "ecc": 5, "ecdsa": 5, "ecdh": 5,
        "hash": 3, "sha": 3, "md5": 3, "sha256": 4,
        "hmac": 4, "pbkdf": 4, "bcrypt": 3,
        "padding oracle": 5, "cbc": 4, "ecb": 4, "gcm": 4,
        "encrypt": 3, "decrypt": 3, "cipher": 4,
        "prime": 3, "factor": 3, "wiener": 4, "fermat": 4,
        "lattice": 5, "lwe": 5, "ntru": 5, "lll": 4,
        "base64": 2, "hex encode": 2,
    },
    "forensics": {
        "steg": 4, "steganography": 5, "steghide": 5,
        "lsb": 5, "least significant bit": 5,
        "binwalk": 4, "foremost": 4, "carving": 4,
        "exiftool": 3, "exif": 3, "metadata": 3,
        "pcap": 5, "wireshark": 4, "tshark": 4, "network capture": 5,
        "memory dump": 5, "volatility": 5, "memdump": 5,
        "zsteg": 4, "outguess": 4, "stegsolve": 4,
        "morse": 4, "dtmf": 4, "spectogram": 4, "spectrogram": 5,
        "hidden data": 4, "embedded": 3,
        "wav": 2, "audio": 2, "image forensics": 5,
        "disk image": 4, "autopsy": 4, "sleuthkit": 4,
        "pdf forensics": 4, "office": 2, "docx": 2,
    },
    "blockchain": {
        "solidity": 5, "pragma solidity": 5, "smart contract": 5,
        "ethereum": 4, "web3": 4, "ether": 4, "wei": 3,
        "evm": 5, "opcode": 4, "bytecode evm": 5,
        "reentrancy": 5, "selfdestruct": 5, "delegatecall": 5,
        "tx.origin": 5, "msg.sender": 4, "msg.value": 4,
        "solidity overflow": 4, "integer overflow": 3,
        "abi": 3, "contract address": 4, "deploy": 3,
        "front running": 4, "flash loan": 5,
        "vyper": 5, "cairo": 4,
    },
    "osint": {
        "osint": 5, "open source intelligence": 5,
        "username": 3, "social media": 4, "instagram": 3, "twitter": 3,
        "google dork": 5, "site:": 4, "inurl:": 4, "intitle:": 4,
        "whois": 4, "shodan": 5, "censys": 5,
        "geolocation": 4, "gps": 3, "coordinates": 3,
        "wayback machine": 5, "archive.org": 4,
        "reverse image": 4, "tineye": 4,
    },
    "pyjail": {
        "pyjail": 5, "python jail": 5, "sandbox escape": 5,
        "__class__": 4, "__mro__": 4, "__subclasses__": 5,
        "__builtins__": 4, "builtins": 3,
        "eval(": 4, "exec(": 4, "compile(": 3,
        "getattr": 3, "setattr": 3,
        "forbidden": 3, "blacklist": 3, "whitelist": 3,
        "restricted": 3, "jail": 3, "escape": 2,
        "__import__": 4, "importlib": 3,
    },
}

def guess_cat(info, desc, hint):
    if hint and hint != "auto":
        return hint
    text = " ".join([
        info.get("text", ""),
        " ".join(info.get("strings", [])),
        desc,
        info.get("file_type", ""),
        " ".join(str(v) for v in info.get("extra", {}).values()),
        " ".join(str(v) for v in info.get("static", {}).values()),
    ]).lower()
    ext       = info.get("ext", "").lower()
    file_type = info.get("file_type", "")
    if ext in (".pcap", ".pcapng", ".cap"): return "forensics"
    if ext in (".wav", ".mp3", ".flac", ".ogg", ".m4a"): return "forensics"
    if ext in (".sol", ".vy", ".cairo"): return "blockchain"
    if ext in (".class", ".jar"): return "reverse"
    if ext == ".pyc": return "reverse"
    if "ELF" in file_type:
        pwn_score = sum(v for k, v in CAT_KEYWORDS["pwn"].items() if k in text)
        return "pwn" if pwn_score >= 6 else "reverse"
    if "PE32" in file_type or "PE+" in file_type or ext in (".exe", ".dll", ".com"):
        return "reverse"
    if "Java" in file_type or "Java class" in file_type: return "reverse"
    scores = {cat: 0 for cat in CAT_KEYWORDS}
    for cat, keywords in CAT_KEYWORDS.items():
        for kw, weight in keywords.items():
            if kw in text:
                scores[cat] += weight
    ext_bonus = {
        ".png": ("forensics", 6), ".jpg": ("forensics", 6),
        ".jpeg": ("forensics", 6), ".bmp": ("forensics", 6),
        ".gif": ("forensics", 4), ".tiff": ("forensics", 4),
    }
    if ext in ext_bonus:
        cat, bonus = ext_bonus[ext]
        scores[cat] += bonus
    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else "misc"

SYSTEM = {
    "reverse": """Tu es un expert CTF reverse engineering avec 10 ans d'expérience.
Tu analyses des binaires ELF/PE, bytecodes (Python .pyc, Java .class, Lua .luac), VM custom, obfuscation.
Tu maîtrises : angr, radare2, ghidra, pwndbg, z3, unicorn, capstone.
Tu génères du code Python autonome qui extrait le flag par analyse statique, émulation ou résolution de contraintes.""",
    "pwn": """Tu es un expert CTF binary exploitation (pwn) avec 10 ans d'expérience.
Tu crées des exploits pour : stack overflow, heap (tcache, fastbin, unsorted bin, House of X),
ROP chains, format string, use-after-free, double free, off-by-one, FSOP.
Tu maîtrises pwntools, pwndbg, GEF, ROPgadget, one_gadget, libc-database.
Tu génères des scripts Python pwntools complets avec gestion des offsets, gadgets et leaks libc.""",
    "web": """Tu es un expert CTF web security avec 10 ans d'expérience.
Tu exploites : SQLi (blind, time-based, UNION), SSTI (Jinja2, Twig, FreeMarker), LFI/RFI, SSRF,
XXE, IDOR, JWT attacks, OAuth abuse, CSRF, race conditions, deserialization (pickle, Java, PHP),
GraphQL injection, NoSQL injection, HTTP request smuggling.
Tu génères des scripts Python requests/httpx complets avec gestion des sessions et cookies.""",
    "crypto": """Tu es un expert CTF cryptanalyse avec 10 ans d'expérience.
Tu attaques : RSA (factorisation, e petit, wiener, broadcast, padding oracle, LSB oracle),
AES (ECB, CBC bit-flip, padding oracle, GCM nonce reuse), ECC (ECDSA k-reuse, pohlig-hellman),
XOR (crib-dragging), hash (length extension), chiffres classiques (Vigenère, Rail fence).
Tu maîtrises : pycryptodome, sympy, sage, gmpy2, z3, lattice attacks (LLL).""",
    "forensics": """Tu es un expert CTF forensics et stéganographie avec 10 ans d'expérience.
Tu analyses : PCAP (scapy/tshark), mémoire (Volatility 3), images (LSB, DCT, binwalk, steghide, zsteg),
audio (spectrogramme, DTMF, morse, LSB audio), disques (Autopsy, sleuthkit), PDF, Office, firmware.
Tu génères du code Python qui extrait les données cachées et affiche le flag.""",
    "osint": """Tu es un expert CTF OSINT avec 10 ans d'expérience.
Tu trouves des informations via : Google dorking, Shodan, Censys, WHOIS, DNS, réseaux sociaux,
Wayback Machine, reverse image search, EXIF metadata, geolocalisation.
Tu génères des scripts Python qui automatisent les recherches OSINT.""",
    "pyjail": """Tu es un expert CTF Python jail (pyjail) avec 10 ans d'expérience.
Tu t'échappes via : __class__.__mro__, __subclasses__(), builtins bypass, f-strings tricks,
exec/eval avec encoding, __import__ alternatif, attribute access tricks, audit hooks bypass.
Tu génères du code Python qui s'échappe proprement et affiche le flag.""",
    "blockchain": """Tu es un expert CTF blockchain / smart contracts avec 10 ans d'expérience.
Tu exploites : reentrancy, integer overflow, tx.origin bypass, selfdestruct, delegatecall,
storage layout, front-running, flash loan, EVM opcodes.
Tu utilises : web3.py, eth-brownie, foundry, solcx.""",
    "misc": """Tu es un expert CTF polyvalent avec 10 ans d'expérience.
Tu résous des défis variés : scripting, encodages exotiques, langages ésotériques (Brainfuck, Whitespace),
puzzles logiques, QR codes, ROT/base variations, algorithmes personnalisés.
Tu génères du code Python fonctionnel qui extrait le flag.""",
}

CATEGORY_RULES = {
    "reverse": """- Utilise angr/z3 pour l'analyse symbolique et résolution de contraintes
- Pour les .pyc : utilise marshal + dis pour décompiler, cherche les constantes
- Pour les .class/.jar : utilise javap, cherche les strings et la logique de vérification
- Affiche toutes les constantes, strings et clés trouvées dans le binaire""",
    "pwn": """- from pwn import *; context.binary = ELF('./binary')
- Détecte les protections avec checksec avant de coder l'exploit
- Pour stack : cyclic(1000) + cyclic_find() pour l'offset
- Pour format string : %p.%p.%p pour leaker des adresses, cherche les offsets
- Pour ROP : rop = ROP(elf); gadgets = rop.find_gadget(['pop rdi', 'ret'])
- Gère le leak libc : offset = leak - libc.sym['puts']; libc.address = offset""",
    "web": """- Lance les requêtes contre l'URL fournie dans le défi
- Pour SQLi : essaie ORDER BY, UNION SELECT NULL, error-based, blind boolean
- Pour SSTI Jinja2 : {{7*7}}, {{''.__class__.__mro__[1].__subclasses__()}}
- Pour JWT : pyjwt sans vérification, alg:none, brute force secret HS256
- Pour LFI : /etc/passwd, php://filter/convert.base64-encode/resource=index.php
- Gère les cookies et sessions entre les requêtes""",
    "crypto": """- from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
- Pour RSA petit e : m = gmpy2.iroot(c, e)[0]; print(long_to_bytes(m))
- Pour RSA : essaie factordb.com via requests avant de tenter la factorisation
- Pour XOR : si len(key) petit, essaie brute force sur la longueur de clé
- Pour AES-ECB : détecte et exploite les blocs répétés
- Affiche les valeurs intermédiaires pour débugger""",
    "forensics": """- Pour images : essaie PIL LSB, binwalk extract, steghide, zsteg, exiftool
- Pour PCAP : extrait les streams avec scapy ou tshark, cherche les données sensibles
- Pour mémoire : volatility3 linux.bash, linux.pslist, windows.pslist
- Cherche les flags dans : commentaires, métadonnées, chunks cachés, pixels LSB
- Si binwalk trouve des fichiers embarqués, extrais-les et analyse-les""",
    "osint": """- Génère les requêtes de recherche et liens directs à vérifier
- Analyse les métadonnées EXIF des images fournies
- Cherche sur archive.org avec la date donnée
- Vérifie WHOIS, DNS records (A, MX, TXT, CNAME)""",
    "pyjail": """- Essaie : "".__class__.__mro__[1].__subclasses__() pour lister les classes
- Trouve subprocess.Popen ou os.system dans la liste
- Essaie les encodages : chr(111)+chr(115) pour 'os'
- Bypass avec : getattr(__builtins__, 'exec')('import os; os.system("cat flag")')""",
    "blockchain": """- from web3 import Web3; w3 = Web3(Web3.HTTPProvider(RPC_URL))
- Charge l'ABI et l'adresse du contrat depuis les fichiers fournis
- Pour reentrancy : crée un contrat attaquant avec fallback
- Analyse le bytecode avec pyevmasm si l'ABI n'est pas dispo
- Cherche les clés privées exposées dans le challenge""",
    "misc": """- Essaie tous les encodages : base64, hex, ROT13, URL, HTML entities, base32, base58
- Pour langages ésotériques : utilise une lib Python ou interprète manuellement
- Cherche des patterns visuels ou auditifs dans les données
- Applique les transformations en chaîne si une seule ne suffit pas""",
}

@app.route('/health', methods=['GET'])
def health():
    tools = {t: bool(shutil.which(t))
             for t in ["python3","strings","file","xxd","objdump","nm","readelf","binwalk",
                       "gdb","strace","ltrace","nc","tshark","steghide","zsteg","exiftool",
                       "7z","jar","javap","pdftotext","checksec","ROPgadget","monodis"]}
    python_libs = {}
    for lib, imp in [("pwntools","pwn"),("pycryptodome","Crypto"),("sympy","sympy"),
                     ("z3","z3"),("scapy","scapy"),("PIL","PIL"),("angr","angr"),
                     ("web3","web3"),("gmpy2","gmpy2"),("capstone","capstone"),
                     ("unicorn","unicorn"),("pefile","pefile")]:
        try: __import__(imp); python_libs[lib] = True
        except ImportError: python_libs[lib] = False
    return jsonify({"status":"ok","version":"6.1","engine":"groq/llama-3.3-70b",
                    "tools":tools,"python_libs":python_libs,"categories":list(SYSTEM.keys())})

@app.route('/analyze', methods=['POST','OPTIONS'])
def analyze():
    if request.method == 'OPTIONS': return '', 204
    api_key = request.headers.get('X-API-Key','')
    if not api_key: return jsonify({"error": "Clé API manquante"}), 401

    desc        = request.form.get('description','').strip()
    cat_hint    = request.form.get('category','auto')
    user_hint   = request.form.get('hint','').strip()
    user_remote = request.form.get('remote','').strip()

    info = {"name":"texte","size":len(desc),"ext":".txt","text":desc,"hex":"","strings":[],
            "files":[],"file_type":"text","static":{},"extra":{}}
    filepath = None

    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            fn = secure_filename(f.filename)
            fp = os.path.join(UPLOAD_DIR, fn)
            f.save(fp)
            if os.path.getsize(fp) > MAX_SIZE:
                os.remove(fp); return jsonify({"error":"Fichier trop grand (max 30MB)"}), 400
            filepath = fp
            info = analyze_file(fp, fn)

    if not info["text"] and not info["hex"] and not desc:
        return jsonify({"error":"Aucun contenu"}), 400

    category = guess_cat(info, desc, cat_hint)
    ctx      = build_ctx(info, desc, user_hint, user_remote)
    system   = SYSTEM.get(category, SYSTEM["misc"])

    def stream():
        nonlocal ctx  # permet de libérer après étape 1

        def sse(ev, d):
            return f"data: {json.dumps({'event':ev,'data':d}, ensure_ascii=False)}\n\n"

        yield sse("start", {"file":info["name"],"category":category,"size":info["size"]})

        # ══ ÉTAPE 0 : RECON ══════════════════════════════════════════════════
        yield sse("step", {"step":0,"status":"active"})
        recon = {"category":category,"key_observations":[],"protections":[],"needs_remote":False,"pip_deps":[]}
        try:
            raw, used_model = llm(api_key, f"""Analyse ce défi CTF.

{ctx[:6000]}

Réponds UNIQUEMENT en JSON valide (sans markdown autour) :
{{
  "category": "{category}",
  "sub_type": "type précis (ex: heap UAF, LSB stego, RSA small-e, SSTI Jinja2...)",
  "difficulty": "easy|medium|hard|expert",
  "file_type": "description précise",
  "key_observations": ["obs1","obs2","obs3","obs4","obs5"],
  "protections": ["protections détectées"],
  "attack_vector": "comment obtenir le flag",
  "tools_needed": ["outil1","outil2"],
  "pip_deps": ["paquets pip nécessaires"],
  "needs_remote": false,
  "remote_hint": "host:port ou null",
  "flag_hint": "indice sur le format/emplacement du flag"
}}""", system=system, max_tokens=900)
            try: recon = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except: pass
            deps = recon.get("pip_deps", [])
            if deps: pip_install(deps)
            yield sse("step", {"step":0,"status":"done","data":recon})
            yield sse("log", {"type":"ok","msg":f"[+] {category.upper()} · {recon.get('sub_type','?')} · {recon.get('difficulty','?')} · {used_model}"})
            for o in recon.get("key_observations",[]): yield sse("log", {"type":"dim","msg":f"    ▸ {o}"})
            if recon.get("protections"): yield sse("log", {"type":"warn","msg":f"[!] Protections: {', '.join(recon['protections'])}"})
            if recon.get("needs_remote"): yield sse("log", {"type":"warn","msg":f"[!] Service distant: {recon.get('remote_hint','?')}"})
            if deps: yield sse("log", {"type":"info","msg":f"[*] Dépendances installées: {', '.join(deps)}"})
        except Exception as e:
            yield sse("step", {"step":0,"status":"error"}); yield sse("error", {"msg":str(e)}); return

        # ══ ÉTAPE 1 : ANALYSE ════════════════════════════════════════════════
        yield sse("step", {"step":1,"status":"active"})
        analysis = ""
        try:
            analysis, _ = llm(api_key, f"""Analyse technique approfondie de ce défi CTF.

{ctx[:10000]}

Recon: {json.dumps(recon, ensure_ascii=False)}

Identifie PRÉCISÉMENT :
1. La vulnérabilité ou le mécanisme exact de génération/vérification du flag
2. Les valeurs clés : clés de chiffrement, seeds, constantes, offsets, gadgets, adresses
3. La séquence exacte d'opérations pour obtenir le flag (étape par étape)
4. Les dépendances Python nécessaires
5. Les pièges à éviter (protections, encodages, endianness)
6. Si service distant : protocole exact, format des échanges

Sois TRÈS précis. Cite les valeurs exactes du code.""",
                system=system, max_tokens=3000)
            yield sse("step", {"step":1,"status":"done"})
            yield sse("log", {"type":"ok","msg":"[+] Analyse technique complète"})
            for line in analysis.split('\n')[:6]:
                if line.strip(): yield sse("log", {"type":"dim","msg":f"    {line.strip()[:120]}"})

            # ★ LIBÉRATION MÉMOIRE : ctx n'est plus nécessaire après l'étape 1
            ctx_short = ctx[:3000]
            del ctx
            ctx = ctx_short

        except Exception as e:
            yield sse("step", {"step":1,"status":"error"}); yield sse("error", {"msg":str(e)}); return

        # ══ ÉTAPE 2 : GÉNÉRATION SCRIPT ══════════════════════════════════════
        yield sse("step", {"step":2,"status":"active"})
        remote_hint = recon.get("remote_hint") or ""
        script = ""
        try:
            cat_rules = CATEGORY_RULES.get(category, CATEGORY_RULES["misc"])
            exploit_raw, _ = llm(api_key, f"""Génère le script Python COMPLET qui résout ce défi CTF.

DÉFI:
{ctx}

ANALYSE:
{analysis[:3000]}

RÈGLES ABSOLUES:
1. Afficher le flag : print("FLAG:", flag)  ou  print(flag)
2. Ne JAMAIS afficher un flag inventé — calcule-le depuis les données réelles
3. Tous les imports en haut
4. try/except pour les erreurs (print l'erreur si échec)
5. Les fichiers du challenge sont dans le dossier courant
6. IMPORTANT libs disponibles : sympy, numpy, PIL, scapy, requests
   Si pycryptodome absent → hashlib, struct, itertools (stdlib)
   Si pwntools absent → socket.create_connection((HOST, PORT))
   Si z3 absent → implémente brute-force ou algorithme alternatif

RÈGLES CATÉGORIE {category.upper()}:
{cat_rules}

{"Service distant: HOST='localhost'  PORT=1337  (à remplacer par " + remote_hint + ")" if remote_hint else "Pas de service distant requis."}

Génère UNIQUEMENT le code Python dans ```python ... ```""",
                system=system, max_tokens=5000)
            script = extract_code(exploit_raw)
            if not script and "import" in exploit_raw and "print" in exploit_raw:
                script = exploit_raw.strip()
            yield sse("step", {"step":2,"status":"done"})
            if script: yield sse("log", {"type":"ok","msg":f"[+] Script généré ({len(script.splitlines())} lignes)"})
            else: yield sse("log", {"type":"warn","msg":"[!] Script vide ou non récupérable"})
        except Exception as e:
            yield sse("step", {"step":2,"status":"error"}); yield sse("error", {"msg":str(e)}); return

        # ══ ÉTAPE 3 : EXÉCUTION + RETRY ══════════════════════════════════════
        yield sse("step", {"step":3,"status":"active"})
        exec_out = ""; real_flag = None
        needs_remote = recon.get("needs_remote", False)

        if not script:
            yield sse("log", {"type":"warn","msg":"[!] Pas de script à exécuter"})
            yield sse("step", {"step":3,"status":"done"})
        elif needs_remote:
            yield sse("log", {"type":"warn","msg":f"[!] Service distant requis — {remote_hint or 'host:port non détecté'}"})
            parsed_host, parsed_port = None, None
            if remote_hint:
                m = re.search(r'([a-zA-Z0-9.\-]+):(\d{2,5})', remote_hint)
                if m:
                    parsed_host, parsed_port = m.group(1), int(m.group(2))
            if parsed_host and parsed_port:
                nc_test = run(["nc", "-z", "-w", "3", parsed_host, str(parsed_port)], timeout=6)
                if nc_test["code"] == 0:
                    yield sse("log", {"type":"ok","msg":f"[+] Service distant accessible : {parsed_host}:{parsed_port}"})
                    yield sse("log", {"type":"info","msg":"[*] Tentative d'exécution du script contre le vrai service..."})
                    if filepath:
                        dst = os.path.join(SANDBOX_DIR, info["name"])
                        if not os.path.exists(dst): shutil.copy2(filepath, dst)
                    patched = script.replace('HOST = "localhost"', f'HOST = "{parsed_host}"') \
                                    .replace("HOST = 'localhost'", f"HOST = '{parsed_host}'") \
                                    .replace('PORT = 1337', f'PORT = {parsed_port}') \
                                    .replace('PORT = 4444', f'PORT = {parsed_port}')
                    result = run_py(patched, timeout=60, cwd=SANDBOX_DIR)
                    exec_out = (result["out"] + result["err"]).strip()
                    for line in exec_out.split("\n")[:25]:
                        if line.strip():
                            has_flag_kw = any(k in line.lower() for k in ["flag","ctf","mctf","htb"])
                            yield sse("log", {"type":"flag" if has_flag_kw and "{" in line else "dim","msg":f"    {line[:200]}"})
                    real_flag = find_flag(exec_out)
                    if real_flag:
                        yield sse("log", {"type":"flag","msg":f"[★] FLAG EXTRAIT (remote): {real_flag}"})
                else:
                    yield sse("log", {"type":"warn","msg":f"[!] Service {parsed_host}:{parsed_port} inaccessible depuis le serveur"})
                    yield sse("log", {"type":"info","msg":"[→] Lance le script localement avec python3 solution.py"})
            else:
                yield sse("log", {"type":"info","msg":"[→] Télécharge le script. Change HOST/PORT et lance python3 solution.py"})
            yield sse("step", {"step":3,"status":"done"})
        else:
            if filepath:
                dst = os.path.join(SANDBOX_DIR, info["name"])
                if not os.path.exists(dst): shutil.copy2(filepath, dst)

            current_script = script
            exec_out = ""
            for attempt in range(3):
                label = f"{attempt+1}/3"
                yield sse("log", {"type":"info","msg":f"[*] Exécution (tentative {label})..."})
                result = run_py(current_script, timeout=45, cwd=SANDBOX_DIR)
                exec_out = (result["out"] + result["err"]).strip()

                for line in exec_out.split('\n')[:30]:
                    if line.strip():
                        has_flag_kw = any(k in line.lower() for k in ["flag","ctf","mctf","htb","picoctf","thcon"])
                        yield sse("log", {"type":"flag" if has_flag_kw and '{' in line else "dim","msg":f"    {line[:200]}"})

                real_flag = find_flag(exec_out)
                if real_flag:
                    yield sse("log", {"type":"flag","msg":f"[★] FLAG EXTRAIT: {real_flag}"}); break

                if result["code"] == 0:
                    try:
                        r2 = run(f"find {SANDBOX_DIR} -maxdepth 3 -newer /tmp -type f -exec strings {{}} \\; 2>/dev/null | head -100", timeout=8)
                        real_flag = find_flag(r2["out"])
                        if real_flag:
                            yield sse("log", {"type":"flag","msg":f"[★] FLAG dans sandbox: {real_flag}"}); break
                    except: pass
                    yield sse("log", {"type":"warn","msg":"[!] Exécution OK mais flag non détecté dans l'output"}); break

                if attempt < 2:
                    yield sse("log", {"type":"warn","msg":f"[!] Exit {result['code']} — correction IA..."})
                    try:
                        fix_raw, _ = llm(api_key, f"""Script Python échoué (tentative {label}). Corrige-le.

SCRIPT:
```python
{current_script[:4000]}
```
ERREUR: {result['err'][:1000]}
OUTPUT PARTIEL: {result['out'][:500]}
CONTEXTE: {ctx}

Corrections à faire :
- ImportError → implémente toi-même OU utilise une des libs dispo :
  sympy, numpy, PIL, scapy (pas pwntools ni pycryptodome sur ce serveur)
  Pour la crypto : implémente RSA/AES/XOR avec les modules stdlib (struct, hashlib, itertools)
  Pour les binaires : utilise subprocess.run(["objdump",...]) ou struct.unpack
- FileNotFoundError → les fichiers sont dans le dossier courant
- TypeError/ValueError → vérifie types (bytes vs str, int vs bytes, encode/decode)
- ModuleNotFoundError pour pwntools → utilise socket/subprocess à la place
- Pas de flag dans output → vérifie que print("FLAG:", flag) est bien appelé

Génère le script CORRIGÉ dans ```python ... ```""",
                            system=system, max_tokens=4000)
                        fixed = extract_code(fix_raw)
                        if fixed and fixed != current_script: current_script = fixed; script = fixed
                        else: break
                    except Exception as e2:
                        yield sse("log", {"type":"warn","msg":f"[!] Correction IA: {e2}"}); break

            yield sse("step", {"step":3,"status":"done"})

        # ══ ÉTAPE 4 : SYNTHÈSE ═══════════════════════════════════════════════
        yield sse("step", {"step":4,"status":"active"})
        try:
            writeup_raw, _ = llm(api_key, f"""Écris un writeup CTF concis pour ce défi.

Catégorie: {category} | Fichier: {info['name']}
Analyse: {analysis[:600]}
{"Flag trouvé: " + real_flag if real_flag else "Flag non trouvé automatiquement."}

3-4 phrases : vulnérabilité exploitée, méthode de résolution, pourquoi ça fonctionne.
Texte simple, pas de JSON ni markdown.""",
                system="Tu es un expert CTF. Tu rédiges des writeups clairs et pédagogiques.", max_tokens=400)
            writeup = writeup_raw.strip()
        except:
            writeup = f"Défi {category} analysé. {'Flag extrait.' if real_flag else 'Analyse manuelle requise.'}"

        flag_data = {"flag_found":bool(real_flag),"flag":real_flag,
                     "flag_format":guess_format(info, desc),"confidence":95 if real_flag else 0,
                     "requires_runtime":needs_remote,"writeup":writeup,
                     "next_steps":build_next_steps(real_flag, needs_remote, remote_hint, category)}

        yield sse("step", {"step":4,"status":"done"})
        if real_flag: yield sse("log", {"type":"flag","msg":f"[★] FLAG CONFIRMÉ: {real_flag}"})
        else:
            yield sse("log", {"type":"warn","msg":"[→] Flag non trouvé automatiquement"})
            if needs_remote: yield sse("log", {"type":"info","msg":f"[→] Lance le script contre {remote_hint or 'le serveur du challenge'}"})
            else: yield sse("log", {"type":"info","msg":"[→] Analyse manuelle requise — voir script et analyse"})

        yield sse("done", {"recon":recon,"analysis":analysis,
                           "exploit":f"```python\n{script}\n```" if script else "",
                           "exec_output":exec_out,"flag":flag_data})

        if filepath:
            try: os.remove(filepath)
            except: pass

    return Response(stream_with_context(stream()), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Access-Control-Allow-Origin':'*'})

def build_ctx(info, desc, hint="", remote=""):
    """Construit le contexte — version allégée pour économiser la RAM."""
    ctx  = f"Fichier: {info['name']} ({info['size']} octets)\nType: {info['file_type']}\n"
    if info["files"]: ctx += f"Archive contient: {', '.join(info['files'][:30])}\n"
    if info["text"]: ctx += f"\n--- CONTENU ---\n{info['text'][:10000]}\n"
    elif info["hex"]:
        ctx += f"\n--- HEX DUMP ---\n{info['hex'][:3000]}\n"
        if info["strings"]:
            ctx += f"\n--- STRINGS ({len(info['strings'])} trouvées) ---\n"
            ctx += "\n".join(info["strings"][:80]) + "\n"
    for k, v in info.get("static", {}).items():
        if v: ctx += f"\n--- {k.upper()} ---\n{str(v)[:3000]}\n"
    for k, v in info.get("extra", {}).items():
        if v and str(v).strip(): ctx += f"\n--- {k.upper()} ---\n{str(v)[:1500]}\n"
    if desc: ctx += f"\n--- DESCRIPTION DU DÉFI ---\n{desc}\n"
    if hint: ctx += f"\n--- INDICE ---\n{hint}\n"
    if remote: ctx += f"\n--- SERVICE DISTANT ---\n{remote}\n"
    return ctx

def guess_format(info, desc):
    text = (info.get("text","") + desc).lower()
    if "mctf{" in text or "midnightflag" in text: return "MCTF{...}"
    if "htb{" in text or "hackthebox" in text:    return "HTB{...}"
    if "picoctf{" in text:                        return "picoCTF{...}"
    if "thcon{" in text:                          return "THCON{...}"
    return "CTF{...}"

def build_next_steps(flag, needs_remote, remote, cat):
    if flag: return "Flag trouvé ! Soumets-le sur la plateforme."
    if needs_remote: return f"Lance le script Python téléchargé localement :\n  python3 solution.py\nChange HOST/PORT → {remote or 'serveur du challenge'}."
    steps = {
        "reverse":    "Essaie angr : import angr; proj = angr.Project('./binary'); sm = proj.factory.simulation_manager(); sm.explore(find=b'flag')",
        "pwn":        "Lance le script pwntools contre le serveur. Vérifie les protections avec checksec. Ajuste HOST/PORT.",
        "web":        "Lance le script requests contre l'URL du challenge. Vérifie cookies et headers.",
        "crypto":     "Vérifie que toutes les valeurs (n, e, c, ciphertext) sont correctement copiées.",
        "forensics":  "Utilise binwalk/steghide/volatility/tshark sur le fichier original.",
        "osint":      "Lance les recherches manuellement avec les requêtes générées.",
        "pyjail":     "Essaie le payload dans l'environnement du challenge. Adapte selon les restrictions.",
        "blockchain": "Déploie le contrat d'attaque sur le testnet. Utilise Remix ou foundry.",
    }
    return steps.get(cat, "Analyse manuelle requise. Voir le script généré et l'analyse.")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
