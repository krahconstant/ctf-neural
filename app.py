from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import json, zipfile, re, os, tempfile, subprocess, base64, time, stat, requests
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "X-API-Key", "X-Gemini-Key"],
     methods=["GET", "POST", "OPTIONS"])

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key, X-Gemini-Key"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

UPLOAD_DIR = tempfile.mkdtemp()
SANDBOX_DIR = tempfile.mkdtemp()
MAX_SIZE = 20 * 1024 * 1024  # 20 MB

# ── AGENT SYSTEM PROMPTS ──────────────────────────────────────────────────────
AGENT_PROMPTS = {
    "reverse":
        "Tu es un expert CTF en reverse engineering. Tu analyses des binaires ELF/PE, "
        "du bytecode, des VM custom. Tu maîtrises objdump, strings, ghidra, radare2, "
        "pwndbg, angr, unicorn. Tu identifies les protections anti-debug, les algos "
        "custom, et tu patches les binaires si nécessaire.",
    "pwn":
        "Tu es un expert CTF en binary exploitation. Tu exploites des binaires vulnérables "
        "(stack overflow, heap, ROP chains, format string, UAF). Tu maîtrises pwntools, "
        "ROPgadget, one_gadget. Tu génères des exploits Python fonctionnels avec pwntools.",
    "web":
        "Tu es un expert CTF en web exploitation. Tu exploites SQLi, XSS, SSRF, SSTI, "
        "JWT bypass, LFI/RFI, deserialization, IDOR, OAuth flaws. Tu analyses le code "
        "source PHP/Python/Node et tu génères des scripts d'exploitation.",
    "crypto":
        "Tu es un expert CTF en cryptanalyse. Tu attaques RSA (faible exposant, wiener, "
        "fermat), AES (padding oracle, CBC bitflip), ECC, hash length extension, custom "
        "ciphers. Tu maîtrises SageMath, pycryptodome, sympy, z3.",
    "forensics":
        "Tu es un expert CTF en forensics et stéganographie. Tu analyses des PCAP, "
        "dumps mémoire, images disque, PNG/JPEG/WAV. Tu maîtrises volatility, wireshark, "
        "binwalk, steghide, foremost, exiftool, zsteg.",
    "misc":
        "Tu es un expert CTF polyvalent. Tu résous des défis créatifs: scripting, OSINT, "
        "blockchain, protocoles custom, escape game, puzzle, pyjail.",
}

# ── OUTILS DISPONIBLES SUR LE SERVEUR ────────────────────────────────────────
def check_tools():
    tools = {}
    for t in ["python3","strings","file","xxd","hexdump","binwalk",
              "objdump","nm","readelf","ltrace","strace","gdb","nc"]:
        tools[t] = subprocess.run(["which", t], capture_output=True).returncode == 0
    return tools

AVAILABLE_TOOLS = check_tools()

# ── EXÉCUTION SÉCURISÉE ───────────────────────────────────────────────────────
def run_cmd(cmd, timeout=15, cwd=None, input_data=None):
    """Exécute une commande avec timeout et capture output."""
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True,
            timeout=timeout, cwd=cwd or SANDBOX_DIR,
            input=input_data,
            env={**os.environ, "PATH": "/usr/bin:/bin:/usr/local/bin"}
        )
        return {
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            "returncode": result.returncode,
            "ok": True
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": f"Timeout après {timeout}s", "returncode": -1, "ok": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "ok": False}

def run_python(code, timeout=20, cwd=None):
    """Exécute du code Python dans un fichier temporaire."""
    tmp = os.path.join(SANDBOX_DIR, f"script_{int(time.time()*1000)}.py")
    try:
        with open(tmp, "w") as f:
            f.write(code)
        result = run_cmd(["python3", tmp], timeout=timeout, cwd=cwd or SANDBOX_DIR)
        return result
    finally:
        try: os.remove(tmp)
        except: pass

# ── ANALYSE STATIQUE DU FICHIER ───────────────────────────────────────────────
def static_analysis(filepath, filename):
    ext = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath)
    info = {
        "name": filename, "size": size, "ext": ext,
        "text": "", "hex": "", "strings": [],
        "files": [], "file_type": "", "analysis": {}
    }

    # file command
    r = run_cmd(["file", filepath])
    info["file_type"] = r["stdout"].strip()

    TEXT_EXT = {'.py','.js','.ts','.c','.cpp','.h','.rs','.go','.java',
                '.rb','.php','.html','.css','.sh','.md','.json','.xml',
                '.yaml','.asm','.s','.txt','.sage','.pl','.lua','.kt',
                '.cs','.r','.m','.swift','.vb','.ps1','.bat','.ex','.exs'}

    # Lecture texte
    if ext in TEXT_EXT or size < 300000:
        try:
            with open(filepath, 'r', errors='replace') as f:
                info["text"] = f.read(40000)
        except:
            pass

    # Hex dump
    if not info["text"]:
        r = run_cmd(["xxd", filepath])
        info["hex"] = r["stdout"][:6000] if r["ok"] else ""

    # Strings
    r = run_cmd(["strings", "-n", "4", filepath])
    if r["ok"]:
        info["strings"] = r["stdout"].split("\n")[:150]

    # ZIP : extraire fichiers
    if ext == '.zip':
        try:
            with zipfile.ZipFile(filepath) as z:
                info["files"] = z.namelist()
                parts = []
                for name in info["files"][:30]:
                    if any(name.endswith(e) for e in ['.py','.js','.c','.txt','.md',
                            '.json','.sh','.php','.html','.sage','.rb','.rs','.go','.java']):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')[:5000]
                            parts.append(f"=== {name} ===\n{content}")
                        except:
                            pass
                if parts:
                    info["text"] = "\n\n".join(parts)
                # Extraire tous les fichiers dans sandbox
                z.extractall(SANDBOX_DIR)
        except Exception as e:
            info["text"] = f"[Erreur ZIP: {e}]"

    # ELF : analyse binaire
    if "ELF" in info["file_type"]:
        os.chmod(filepath, stat.S_IRWXU)
        r = run_cmd(["readelf", "-h", filepath])
        info["analysis"]["readelf"] = r["stdout"][:2000]
        r = run_cmd(["nm", "--demangle", filepath])
        info["analysis"]["symbols"] = r["stdout"][:3000]
        r = run_cmd(["objdump", "-d", "--no-show-raw-insn", filepath])
        info["analysis"]["disasm"] = r["stdout"][:8000]

    # PCAP
    if ext in ['.pcap', '.pcapng']:
        r = run_cmd(["strings", filepath])
        info["analysis"]["pcap_strings"] = r["stdout"][:5000]

    return info

def build_context(info, description):
    ctx = f"Fichier: {info['name']} ({info['size']} octets)\n"
    ctx += f"Type: {info['file_type']}\n"
    if info["files"]:
        ctx += f"Contenu archive: {', '.join(info['files'][:40])}\n"
    if info["text"]:
        ctx += f"\nContenu:\n```\n{info['text'][:18000]}\n```\n"
    elif info["hex"]:
        ctx += f"\nHex dump:\n{info['hex'][:4000]}\n"
    if info["strings"]:
        ctx += f"\nStrings extraites:\n{chr(10).join(info['strings'][:80])}\n"
    for k, v in info.get("analysis", {}).items():
        if v:
            ctx += f"\n{k.upper()}:\n{v[:3000]}\n"
    if description:
        ctx += f"\nDescription: {description}\n"
    return ctx

def detect_category(info, description, hint):
    if hint and hint != "auto":
        return hint
    text = (info.get("text","") + " ".join(info.get("strings",[])) + description + info.get("file_type","")).lower()
    ext = info.get("ext","")
    if ext in ['.pcap','.pcapng','.cap']:
        return "forensics"
    if "ELF" in info.get("file_type","") or "PE32" in info.get("file_type",""):
        if any(k in text for k in ["overflow","rop","heap","got","plt","libc","shellcode","ret2"]):
            return "pwn"
        return "reverse"
    if any(k in text for k in ["rsa","aes","encrypt","decrypt","cipher","hash","modulus","prime","elliptic","xor"]):
        return "crypto"
    if any(k in text for k in ["http","sql","xss","login","cookie","jwt","flask","django","php","mysql"]):
        return "web"
    if any(k in text for k in ["steg","hidden","lsb","png","jpeg","wav","mp3","binwalk"]):
        return "forensics"
    return "reverse"

# ── GEMINI API ────────────────────────────────────────────────────────────────
GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
]

def call_groq(api_key, prompt, system="", max_tokens=8192):
    """Appel API Groq avec fallback sur plusieurs modèles."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    sys_msg = system or "Tu es un expert CTF de niveau compétition mondiale. Tes réponses sont précises, techniques et actionnables. Tu génères du code Python fonctionnel."

    last_error = None
    for model in GROQ_MODELS:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": sys_msg},
                    {"role": "user",   "content": prompt},
                ],
                "max_tokens":  min(max_tokens, 8192),
                "temperature": 0.2,
            }
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers, json=payload, timeout=60
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
            elif resp.status_code == 429:
                # Rate limit sur ce modèle → essaie le suivant
                last_error = f"Rate limit sur {model}"
                time.sleep(2)
                continue
            else:
                err = resp.json().get("error", {}).get("message", resp.text)
                raise Exception(f"Groq {model}: {err}")
        except requests.exceptions.Timeout:
            last_error = f"Timeout sur {model}"
            continue
        except Exception as e:
            if "rate" in str(e).lower() or "429" in str(e):
                last_error = str(e)
                time.sleep(2)
                continue
            raise

    raise Exception(f"Tous les modèles Groq indisponibles. Dernière erreur: {last_error}")

# Alias pour compatibilité avec le reste du code
call_gemini = call_groq

# ── EXTRACTION CODE PYTHON ────────────────────────────────────────────────────
def extract_python(text):
    """Extrait le premier bloc de code Python d'une réponse."""
    m = re.search(r'```(?:python|py)\n([\s\S]*?)```', text)
    if m:
        return m.group(1).strip()
    m = re.search(r'```\n([\s\S]*?)```', text)
    if m:
        return m.group(1).strip()
    return ""

def extract_flag(text):
    """Cherche un flag CTF dans le texte."""
    patterns = [
        r'[A-Za-z0-9_]+\{[A-Za-z0-9_\-!@#$%^&*()+=<>?/\\|.,;:\'"` ~]+\}',
        r'flag\s*[:=]\s*([^\n]+)',
        r'FLAG\s*[:=]\s*([^\n]+)',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(0).strip()
    return None

# ── ROUTE PRINCIPALE ──────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok", "version": "4.1",
        "service": "ctf-neural",
        "tools": AVAILABLE_TOOLS,
        "engine": "groq/llama-3.3-70b"
    })

@app.route('/analyze', methods=['POST', 'OPTIONS'])
def analyze():
    if request.method == 'OPTIONS':
        return '', 204

    api_key = request.headers.get('X-API-Key', '') or request.headers.get('X-Gemini-Key', '')
    if not api_key:
        return jsonify({"error": "Clé API Gemini manquante"}), 401

    description = request.form.get('description', '').strip()
    category    = request.form.get('category', 'auto')

    # Prépare le fichier
    filepath = None
    info = {
        "name": "texte", "size": len(description), "ext": ".txt",
        "text": description, "hex": "", "strings": [], "files": [],
        "file_type": "text", "analysis": {}
    }

    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            filename = secure_filename(f.filename)
            filepath = os.path.join(UPLOAD_DIR, filename)
            f.save(filepath)
            if os.path.getsize(filepath) > MAX_SIZE:
                os.remove(filepath)
                return jsonify({"error": "Fichier trop grand (max 20MB)"}), 400
            info = static_analysis(filepath, filename)

    if not info["text"] and not info["hex"] and not description:
        return jsonify({"error": "Aucun contenu à analyser"}), 400

    category = detect_category(info, description, category)
    ctx = build_context(info, description)
    system = AGENT_PROMPTS.get(category, AGENT_PROMPTS["misc"])

    def generate():
        def sse(event, data):
            return f"data: {json.dumps({'event': event, 'data': data}, ensure_ascii=False)}\n\n"

        yield sse("start", {"file": info["name"], "category": category, "size": info["size"]})

        # ── ÉTAPE 0 : RECON ──────────────────────────────────────────────────
        yield sse("step", {"step": 0, "status": "active"})
        try:
            recon_raw = call_gemini(api_key, f"""Analyse ce défi CTF et classifie-le.

{ctx[:6000]}

Réponds UNIQUEMENT en JSON valide:
{{
  "category": "{category}",
  "difficulty": "easy|medium|hard|expert",
  "file_type": "type précis",
  "key_observations": ["obs 1","obs 2","obs 3","obs 4"],
  "protections": ["protection 1"],
  "attack_vector": "vecteur d'attaque principal",
  "main_hint": "indice le plus important pour résoudre",
  "tools_needed": ["outil1","outil2"],
  "confidence": 90
}}""", system=system, max_tokens=1000)

            try:
                recon = json.loads(re.search(r'\{[\s\S]*\}', recon_raw).group())
            except:
                recon = {"category": category, "key_observations": [], "protections": [], "confidence": 60}

            yield sse("step", {"step": 0, "status": "done", "data": recon})
            yield sse("log", {"type": "ok",   "msg": f"[+] {category.upper()} · {recon.get('difficulty','?')} · {recon.get('confidence','?')}%"})
            for obs in recon.get("key_observations", []):
                yield sse("log", {"type": "dim", "msg": f"    ▸ {obs}"})
            if recon.get("protections"):
                yield sse("log", {"type": "warn", "msg": f"[!] Protections: {', '.join(recon['protections'])}"})
            if recon.get("main_hint"):
                yield sse("log", {"type": "info", "msg": f"[*] Indice clé: {recon['main_hint']}"})
        except Exception as e:
            yield sse("step", {"step": 0, "status": "error"})
            yield sse("error", {"msg": f"Recon: {e}"})
            return

        # ── ÉTAPE 1 : ANALYSE APPROFONDIE ────────────────────────────────────
        yield sse("step", {"step": 1, "status": "active"})
        try:
            analysis = call_gemini(api_key, f"""Analyse technique approfondie de ce défi CTF.

{ctx[:10000]}

Recon: {json.dumps(recon, ensure_ascii=False)}

Analyse en détail:
1. Vulnérabilités et faiblesses précises (avec localisation dans le code)
2. Algorithmes, encodages, structures de données clés
3. Flux d'exécution et logique de vérification du flag
4. Points d'entrée pour l'attaque
5. Indices cachés (valeurs magiques, constantes, noms de fonctions)
6. Commandes et outils exacts à utiliser

Sois très précis et technique. Cite des éléments spécifiques du code/binaire.""",
                system=system, max_tokens=3000)

            yield sse("step", {"step": 1, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Analyse technique complète"})
            for line in analysis.split('\n')[:4]:
                if line.strip():
                    yield sse("log", {"type": "dim", "msg": f"    {line.strip()[:120]}"})
        except Exception as e:
            yield sse("step", {"step": 1, "status": "error"})
            yield sse("error", {"msg": f"Analyse: {e}"})
            return

        # ── ÉTAPE 2 : GÉNÉRATION SCRIPT ──────────────────────────────────────
        yield sse("step", {"step": 2, "status": "active"})
        try:
            exploit_raw = call_gemini(api_key, f"""Génère le script Python COMPLET et FONCTIONNEL pour résoudre ce défi CTF.

Défi: {ctx[:8000]}
Analyse: {analysis[:2000]}

RÈGLES IMPÉRATIVES:
1. Script Python 3 complet avec tous les imports
2. Si le flag peut être calculé STATIQUEMENT: calcule-le et affiche print("FLAG:", flag)
3. Utilise pwntools si connexion réseau nécessaire (HOST="localhost", PORT=1337)
4. Utilise pycryptodome pour crypto (from Crypto.Cipher import AES, etc.)
5. Ajoute des print() pour montrer la progression
6. Le script doit être directement exécutable: python3 solution.py
7. Si ZIP: les fichiers sont déjà extraits dans le dossier courant

Format:
```python
#!/usr/bin/env python3
# Solution - {info['name']}
[imports]
[code complet]
if __name__ == "__main__":
    main()
```""", system=system, max_tokens=4000)

            script = extract_python(exploit_raw) or exploit_raw[:3000]
            yield sse("step", {"step": 2, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Script de résolution généré"})

            # Check flag statique dans le script
            static_flag = extract_flag(exploit_raw)
            if static_flag:
                yield sse("log", {"type": "flag", "msg": f"[★] Flag dans le script: {static_flag}"})
        except Exception as e:
            yield sse("step", {"step": 2, "status": "error"})
            yield sse("error", {"msg": f"Script: {e}"})
            return

        # ── ÉTAPE 3 : EXÉCUTION RÉELLE ───────────────────────────────────────
        yield sse("step", {"step": 3, "status": "active"})
        exec_output = ""
        exec_flag = None

        if script:
            yield sse("log", {"type": "info", "msg": "[*] Exécution du script en sandbox..."})
            # Copier le fichier original dans le sandbox si besoin
            if filepath:
                import shutil
                dst = os.path.join(SANDBOX_DIR, info["name"])
                if not os.path.exists(dst):
                    shutil.copy2(filepath, dst)

            result = run_python(script, timeout=25, cwd=SANDBOX_DIR)
            exec_output = result["stdout"] + result["stderr"]

            yield sse("log", {"type": "info" if result["ok"] else "warn",
                              "msg": f"[*] Exit code: {result['returncode']}"})

            for line in exec_output.split('\n')[:20]:
                if line.strip():
                    yield sse("log", {"type": "ok" if "flag" in line.lower() or "{" in line else "dim",
                                      "msg": f"    {line[:150]}"})

            # Cherche le flag dans l'output
            exec_flag = extract_flag(exec_output)
            if exec_flag:
                yield sse("log", {"type": "flag", "msg": f"[★] FLAG EXTRAIT: {exec_flag}"})
                yield sse("step", {"step": 3, "status": "done"})
            elif result["returncode"] != 0 and result["stderr"]:
                # Le script a planté → on demande à l'IA de corriger
                yield sse("log", {"type": "warn", "msg": "[!] Erreur d'exécution, correction IA..."})
                try:
                    fixed_raw = call_gemini(api_key, f"""Ce script Python a produit une erreur. Corrige-le.

Script original:
```python
{script[:3000]}
```

Erreur obtenue:
```
{result['stderr'][:1000]}
```

Output partiel:
```
{result['stdout'][:500]}
```

Contexte du défi:
{ctx[:3000]}

Génère le script CORRIGÉ complet. Si tu ne peux pas corriger (ex: besoin d'un serveur live),
explique exactement ce qu'il faut faire et génère quand même le meilleur script possible.""",
                        system=system, max_tokens=3000)

                    fixed_script = extract_python(fixed_raw) or fixed_raw[:2000]
                    if fixed_script and fixed_script != script:
                        yield sse("log", {"type": "info", "msg": "[*] Re-exécution du script corrigé..."})
                        result2 = run_python(fixed_script, timeout=25, cwd=SANDBOX_DIR)
                        exec_output += "\n--- SCRIPT CORRIGÉ ---\n" + result2["stdout"] + result2["stderr"]
                        exec_flag = extract_flag(exec_output)
                        if exec_flag:
                            yield sse("log", {"type": "flag", "msg": f"[★] FLAG: {exec_flag}"})
                        script = fixed_script
                        for line in result2["stdout"].split('\n')[:10]:
                            if line.strip():
                                yield sse("log", {"type": "dim", "msg": f"    {line[:150]}"})
                except Exception as e2:
                    yield sse("log", {"type": "warn", "msg": f"[!] Correction IA: {e2}"})
                yield sse("step", {"step": 3, "status": "done"})
            else:
                yield sse("step", {"step": 3, "status": "done"})
        else:
            yield sse("step", {"step": 3, "status": "done"})
            yield sse("log", {"type": "warn", "msg": "[!] Pas de script exécutable généré"})

        # ── ÉTAPE 4 : SYNTHÈSE FINALE ─────────────────────────────────────────
        yield sse("step", {"step": 4, "status": "active"})
        try:
            # Si on a déjà le flag, on demande juste le writeup
            if exec_flag:
                flag_context = f"FLAG TROUVÉ PAR EXÉCUTION: {exec_flag}"
            else:
                flag_context = f"Output d'exécution:\n{exec_output[:1000]}\n\nAnalyse:\n{analysis[:500]}"

            final_raw = call_gemini(api_key, f"""Synthèse finale de ce défi CTF.

{flag_context}

Script utilisé:
{script[:1000]}

Réponds UNIQUEMENT en JSON valide:
{{
  "flag_found": true,
  "flag": "valeur_du_flag_ou_null",
  "flag_format": "format ex: CTF{{...}}",
  "confidence": 95,
  "requires_runtime": false,
  "writeup": "Résumé clair en 2-3 phrases: vulnérabilité, méthode, résultat.",
  "next_steps": "Si flag non trouvé: instructions précises"
}}""", system=system, max_tokens=800)

            try:
                flag_data = json.loads(re.search(r'\{[\s\S]*\}', final_raw).group())
            except:
                flag_data = {
                    "flag_found": bool(exec_flag),
                    "flag": exec_flag,
                    "flag_format": "CTF{...}",
                    "confidence": 80 if exec_flag else 30,
                    "requires_runtime": not exec_flag,
                    "writeup": "Analyse complète. Voir le script généré.",
                    "next_steps": "Exécute le script localement avec les bons paramètres."
                }

            # Priorité au flag extrait par exécution réelle
            if exec_flag and not flag_data.get("flag"):
                flag_data["flag"] = exec_flag
                flag_data["flag_found"] = True

            yield sse("step", {"step": 4, "status": "done"})
            if flag_data.get("flag"):
                yield sse("log", {"type": "flag", "msg": f"[★] FLAG FINAL: {flag_data['flag']}"})
            else:
                yield sse("log", {"type": "warn", "msg": f"[!] Format attendu: {flag_data.get('flag_format','CTF{{...}}')}"})
                if flag_data.get("next_steps"):
                    yield sse("log", {"type": "info", "msg": f"[→] {flag_data['next_steps']}"})
        except Exception as e:
            flag_data = {
                "flag_found": bool(exec_flag), "flag": exec_flag,
                "flag_format": "CTF{...}", "confidence": 50,
                "requires_runtime": True, "writeup": str(e),
                "next_steps": "Exécute le script localement."
            }
            yield sse("step", {"step": 4, "status": "done"})

        # ── DONE ────────────────────────────────────────────────────────────
        yield sse("done", {
            "recon":       recon,
            "analysis":    analysis,
            "strategy":    "",
            "exploit":     f"```python\n{script}\n```" if script else exploit_raw,
            "exec_output": exec_output,
            "flag":        flag_data,
            "tokens":      0,
        })

        # Nettoyage
        if filepath:
            try: os.remove(filepath)
            except: pass

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':       'no-cache',
            'X-Accel-Buffering':   'no',
            'Access-Control-Allow-Origin': '*',
        }
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
