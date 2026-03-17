"""
CTF·NEURAL v5.0 — Architecture honnête
Principe : on n'affiche JAMAIS un flag qui n'a pas été trouvé par exécution réelle.
Le LLM génère du code, le serveur l'exécute, le flag vient du stdout réel.
"""
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
import json, zipfile, re, os, tempfile, subprocess, time, stat, shutil, requests
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
MAX_SIZE    = 20 * 1024 * 1024

# ── MODÈLES GROQ (actifs mars 2026) ──────────────────────────────────────────
GROQ_PRIMARY  = "llama-3.3-70b-versatile"
GROQ_FALLBACK = ["llama-3.1-8b-instant", "gemma2-9b-it"]

def groq_models(api_key):
    """Récupère dynamiquement les modèles actifs depuis Groq."""
    try:
        r = requests.get(
            "https://api.groq.com/openai/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=4
        )
        if r.status_code == 200:
            all_m = r.json().get("data", [])
            active = [
                m["id"] for m in all_m
                if m.get("active", True)
                and not any(x in m["id"] for x in ["whisper","guard","tts","vision"])
            ]
            # llama-3.3 en premier
            p = [m for m in active if "3.3" in m]
            o = [m for m in active if "3.3" not in m]
            return (p + o)[:5] if active else [GROQ_PRIMARY] + GROQ_FALLBACK
    except:
        pass
    return [GROQ_PRIMARY] + GROQ_FALLBACK

def llm(api_key, prompt, system="", max_tokens=4096):
    """Appel LLM avec fallback automatique entre modèles actifs."""
    models = groq_models(api_key)
    sys_msg = system or "Tu es un expert CTF. Génère du code Python précis et fonctionnel."
    last_err = None
    for model in models:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": sys_msg},
                        {"role": "user",   "content": prompt},
                    ],
                    "max_tokens":  min(max_tokens, 8000),
                    "temperature": 0.15,
                },
                timeout=90
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"], model
            elif r.status_code == 429:
                last_err = f"rate-limit {model}"
                time.sleep(3)
                continue
            else:
                err = r.json().get("error", {}).get("message", r.text[:200])
                if "decommissioned" in err or "deprecated" in err:
                    last_err = f"déprécié: {model}"
                    continue
                raise Exception(f"{model}: {err}")
        except requests.exceptions.Timeout:
            last_err = f"timeout {model}"
            continue
        except Exception as e:
            if any(x in str(e).lower() for x in ["decommission","deprecat","rate","429"]):
                last_err = str(e)
                time.sleep(2)
                continue
            raise
    raise Exception(f"Aucun modèle disponible. ({last_err})")

# ── OUTILS SYSTÈME ────────────────────────────────────────────────────────────
def run(cmd, timeout=20, cwd=None, stdin=None):
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True,
            timeout=timeout, cwd=cwd or SANDBOX_DIR,
            input=stdin,
            env={**os.environ, "PATH": "/usr/bin:/bin:/usr/local/bin"}
        )
        return {"out": r.stdout[:10000], "err": r.stderr[:3000], "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"out": "", "err": f"Timeout {timeout}s", "code": -1}
    except Exception as e:
        return {"out": "", "err": str(e), "code": -1}

def run_py(code, timeout=25, cwd=None):
    """Exécute un script Python dans le sandbox."""
    tmp = os.path.join(SANDBOX_DIR, f"sol_{int(time.time()*1000)}.py")
    try:
        with open(tmp, "w") as f:
            f.write(code)
        return run(["python3", "-u", tmp], timeout=timeout, cwd=cwd or SANDBOX_DIR)
    finally:
        try: os.remove(tmp)
        except: pass

def extract_code(text):
    """Extrait un bloc de code Python. Cherche plusieurs patterns."""
    # Pattern 1 : ```python ... ```
    m = re.search(r'```python\n([\s\S]*?)```', text)
    if m and len(m.group(1).strip()) > 20:
        return m.group(1).strip()
    # Pattern 2 : ``` ... ```
    m = re.search(r'```\n([\s\S]*?)```', text)
    if m and len(m.group(1).strip()) > 20:
        return m.group(1).strip()
    # Pattern 3 : lignes commençant par import/from/def/# en début de réponse
    lines = text.split('\n')
    code_lines = []
    in_code = False
    for line in lines:
        if re.match(r'^(import |from |def |class |#!|#!/)', line):
            in_code = True
        if in_code:
            code_lines.append(line)
    if len(code_lines) > 5:
        return '\n'.join(code_lines)
    return ""

def find_flag(text):
    """
    Cherche un VRAI flag dans l'output d'exécution.
    STRICT : refuse les placeholders comme CTF{...} ou FLAG{example}.
    """
    if not text:
        return None
    # Patterns de vrais flags
    patterns = [
        r'\b[A-Za-z0-9_\-]+\{[A-Za-z0-9_\-!@#$%^&*()+=/\\.,;:\'"<>? ]{4,80}\}',
    ]
    placeholders = {
        "CTF{...}", "CTF{flag}", "FLAG{...}", "CTF{example}",
        "FLAG{example}", "CTF{your_flag}", "flag{...}",
        "CTF{REDACTED}", "CTF{placeholder}", "FLAG{flag_here}",
        "CTF{flag_here}", "flag{flag}", "CTF{insert_flag}",
    }
    for p in patterns:
        for m in re.finditer(p, text):
            candidate = m.group(0)
            # Vérifie que ce n'est pas un placeholder
            if candidate in placeholders:
                continue
            if re.match(r'^(CTF|FLAG|flag|ctf)\{\.+\}$', candidate):
                continue
            if len(candidate) < 8:
                continue
            return candidate
    return None

# ── ANALYSE STATIQUE ──────────────────────────────────────────────────────────
def analyze_file(filepath, filename):
    ext  = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath)
    info = {
        "name": filename, "size": size, "ext": ext,
        "text": "", "hex": "", "strings": [], "files": [],
        "file_type": "", "static": {}
    }

    r = run(["file", filepath])
    info["file_type"] = r["out"].strip()

    TEXT_EXT = {'.py','.js','.ts','.c','.cpp','.h','.rs','.go','.java','.rb',
                '.php','.html','.css','.sh','.md','.json','.xml','.yaml',
                '.asm','.s','.txt','.sage','.pl','.lua','.kt','.cs','.r',
                '.swift','.vb','.ps1','.bat','.ex','.exs','.erl','.nim'}

    # Texte
    if ext in TEXT_EXT or size < 500_000:
        try:
            with open(filepath, 'r', errors='replace') as f:
                info["text"] = f.read(50000)
        except: pass

    # Hex + strings pour les binaires
    if not info["text"]:
        r = run(["xxd", filepath])
        info["hex"] = r["out"][:8000]
        r = run(["strings", "-n", "4", filepath])
        info["strings"] = [s for s in r["out"].split("\n") if s.strip()][:200]

    # ZIP : extraire contenu
    if ext == '.zip':
        try:
            with zipfile.ZipFile(filepath) as z:
                info["files"] = z.namelist()
                parts = []
                for name in info["files"][:40]:
                    if any(name.endswith(e) for e in [
                        '.py','.js','.c','.txt','.md','.json','.sh',
                        '.php','.html','.sage','.rb','.rs','.go','.java','.cs'
                    ]):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')[:6000]
                            parts.append(f"=== {name} ===\n{content}")
                        except: pass
                if parts:
                    info["text"] = "\n\n".join(parts)
                # Extraire dans sandbox
                z.extractall(SANDBOX_DIR)
        except Exception as e:
            info["text"] += f"\n[Erreur ZIP: {e}]"

    # ELF : analyse approfondie
    if "ELF" in info["file_type"]:
        try: os.chmod(filepath, stat.S_IRWXU)
        except: pass
        shutil.copy2(filepath, os.path.join(SANDBOX_DIR, filename))
        info["static"]["symbols"] = run(["nm", "--demangle", filepath])["out"][:4000]
        info["static"]["disasm"]  = run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", filepath])["out"][:12000]
        info["static"]["readelf"] = run(["readelf", "-h", "-S", filepath])["out"][:3000]

    return info

def build_ctx(info, desc):
    ctx  = f"Fichier: {info['name']} ({info['size']} octets)\n"
    ctx += f"Type: {info['file_type']}\n"
    if info["files"]:
        ctx += f"Archive contient: {', '.join(info['files'][:40])}\n"
    if info["text"]:
        ctx += f"\n--- CONTENU ---\n{info['text'][:20000]}\n"
    elif info["hex"]:
        ctx += f"\n--- HEX DUMP ---\n{info['hex'][:5000]}\n"
        if info["strings"]:
            ctx += f"\n--- STRINGS ({len(info['strings'])} trouvées) ---\n"
            ctx += "\n".join(info["strings"][:100]) + "\n"
    for k, v in info.get("static", {}).items():
        if v:
            ctx += f"\n--- {k.upper()} ---\n{v[:5000]}\n"
    if desc:
        ctx += f"\n--- DESCRIPTION ---\n{desc}\n"
    return ctx

def guess_cat(info, desc, hint):
    if hint and hint != "auto":
        return hint
    text = (info.get("text","") + " ".join(info.get("strings",[])) + desc + info.get("file_type","")).lower()
    ext  = info.get("ext","")
    if ext in ['.pcap','.pcapng','.cap']:           return "forensics"
    if "ELF" in info.get("file_type",""):
        if any(k in text for k in ["overflow","rop","heap","got","plt","libc","shellcode","ret2"]):
            return "pwn"
        return "reverse"
    if "PE32" in info.get("file_type",""):           return "reverse"
    if any(k in text for k in ["rsa","aes","encrypt","decrypt","cipher","xor","hash","modulus","prime","elliptic"]):
        return "crypto"
    if any(k in text for k in ["http","sql","xss","login","cookie","jwt","flask","django","php","mysql","injection"]):
        return "web"
    if any(k in text for k in ["steg","lsb","png","jpeg","wav","hidden","binwalk"]):
        return "forensics"
    return "reverse"

SYSTEM = {
    "reverse":  "Tu es un expert CTF reverse engineering. Tu analyses des binaires ELF/PE, bytecodes, VM custom. Tu génères du code Python qui extrait le flag par analyse statique ou émulation.",
    "pwn":      "Tu es un expert CTF binary exploitation. Tu crées des exploits pwntools (stack, heap, ROP, format string). Tu génères des scripts Python pwntools complets et fonctionnels.",
    "web":      "Tu es un expert CTF web. Tu exploites SQLi, SSTI, LFI, SSRF, JWT, deserialization. Tu génères des scripts Python requests qui extraient le flag d'un service web.",
    "crypto":   "Tu es un expert CTF cryptanalyse. Tu attaques RSA, AES, ECC, XOR, custom ciphers. Tu génères du code Python avec pycryptodome/sympy qui déchiffre et affiche le flag.",
    "forensics":"Tu es un expert CTF forensics/stéganographie. Tu analyses PCAP, mémoire, images. Tu génères du code Python qui extrait les données cachées et affiche le flag.",
    "misc":     "Tu es un expert CTF. Tu résous des défis variés: scripting, OSINT, pyjail, blockchain. Tu génères du code Python fonctionnel qui extrait le flag.",
}

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    tools = {t: shutil.which(t) is not None
             for t in ["python3","strings","file","xxd","objdump","nm",
                       "readelf","binwalk","gdb","strace","nc"]}
    return jsonify({"status":"ok","version":"5.0","engine":"groq/llama-3.3-70b","tools":tools})

@app.route('/analyze', methods=['POST','OPTIONS'])
def analyze():
    if request.method == 'OPTIONS':
        return '', 204

    api_key = request.headers.get('X-API-Key','')
    if not api_key:
        return jsonify({"error": "Clé API manquante"}), 401

    desc     = request.form.get('description','').strip()
    cat_hint = request.form.get('category','auto')

    # Info par défaut (texte seul)
    info = {
        "name":"texte","size":len(desc),"ext":".txt",
        "text":desc,"hex":"","strings":[],"files":[],
        "file_type":"text","static":{}
    }
    filepath = None

    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            fn = secure_filename(f.filename)
            fp = os.path.join(UPLOAD_DIR, fn)
            f.save(fp)
            if os.path.getsize(fp) > MAX_SIZE:
                os.remove(fp)
                return jsonify({"error":"Fichier trop grand (max 20MB)"}), 400
            filepath = fp
            info = analyze_file(fp, fn)

    if not info["text"] and not info["hex"] and not desc:
        return jsonify({"error":"Aucun contenu"}), 400

    category = guess_cat(info, desc, cat_hint)
    ctx      = build_ctx(info, desc)
    system   = SYSTEM.get(category, SYSTEM["misc"])

    def stream():
        def sse(ev, d):
            return f"data: {json.dumps({'event':ev,'data':d}, ensure_ascii=False)}\n\n"

        used_model = GROQ_PRIMARY

        yield sse("start", {"file":info["name"],"category":category,"size":info["size"]})

        # ══ ÉTAPE 0 : RECON ══════════════════════════════════════════════════
        yield sse("step", {"step":0,"status":"active"})
        try:
            raw, used_model = llm(api_key, f"""Analyse ce défi CTF.

{ctx[:8000]}

Réponds UNIQUEMENT en JSON valide (pas de markdown autour) :
{{
  "category": "{category}",
  "difficulty": "easy|medium|hard|expert",
  "file_type": "description précise",
  "key_observations": ["obs1","obs2","obs3","obs4"],
  "protections": ["liste des protections détectées"],
  "attack_vector": "comment obtenir le flag",
  "tools_needed": ["outil1","outil2"],
  "needs_remote": false,
  "remote_hint": "host:port si service distant mentionné, sinon null"
}}""", system=system, max_tokens=800)

            try:
                recon = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except:
                recon = {"category":category,"key_observations":[],"protections":[],"needs_remote":False}

            yield sse("step", {"step":0,"status":"done","data":recon})
            yield sse("log", {"type":"ok",   "msg":f"[+] {category.upper()} · {recon.get('difficulty','?')} · modèle: {used_model}"})
            for o in recon.get("key_observations",[]):
                yield sse("log", {"type":"dim","msg":f"    ▸ {o}"})
            if recon.get("protections"):
                yield sse("log", {"type":"warn","msg":f"[!] Protections: {', '.join(recon['protections'])}"})
            if recon.get("needs_remote"):
                yield sse("log", {"type":"warn","msg":f"[!] Service distant requis: {recon.get('remote_hint','?')}"})
        except Exception as e:
            yield sse("step", {"step":0,"status":"error"})
            yield sse("error", {"msg":str(e)})
            return

        # ══ ÉTAPE 1 : ANALYSE ════════════════════════════════════════════════
        yield sse("step", {"step":1,"status":"active"})
        try:
            analysis, _ = llm(api_key, f"""Analyse technique approfondie de ce défi CTF.

{ctx[:12000]}

Recon: {json.dumps(recon, ensure_ascii=False)}

Identifie:
1. La vulnérabilité ou le mécanisme exact de génération/vérification du flag
2. Les valeurs clés: clés de chiffrement, seeds, constantes, offsets
3. La séquence exacte d'opérations pour obtenir le flag
4. Les dépendances Python nécessaires (pycryptodome, pwntools, z3, etc.)
5. Si service distant: protocole exact, format des échanges

Sois très précis. Cite des valeurs exactes du code si disponibles.""",
                system=system, max_tokens=2500)

            yield sse("step", {"step":1,"status":"done"})
            yield sse("log", {"type":"ok","msg":"[+] Analyse technique complète"})
            for line in analysis.split('\n')[:5]:
                if line.strip():
                    yield sse("log", {"type":"dim","msg":f"    {line.strip()[:120]}"})
        except Exception as e:
            yield sse("step", {"step":1,"status":"error"})
            yield sse("error", {"msg":str(e)})
            return

        # ══ ÉTAPE 2 : GÉNÉRATION SCRIPT ══════════════════════════════════════
        yield sse("step", {"step":2,"status":"active"})
        remote_hint = recon.get("remote_hint") or ""
        script      = ""
        try:
            exploit_raw, _ = llm(api_key, f"""Génère le script Python COMPLET qui résout ce défi CTF et affiche le flag.

DÉFI:
{ctx[:10000]}

ANALYSE:
{analysis[:2500]}

RÈGLES ABSOLUES:
1. Le script doit afficher le flag avec : print("FLAG:", flag)  ou  print(flag)
2. Ne JAMAIS afficher un flag inventé ou placeholder comme CTF{{...}}
3. Calcule le flag à partir des données réelles du fichier/code
4. Tous les imports en haut
5. Gestion d'erreurs avec try/except
6. Si besoin de librairies: pycryptodome, pwntools, z3, sympy, requests, scapy
7. Si service distant ({remote_hint or 'non requis'}):
   HOST = "localhost"  # à changer
   PORT = 1337         # à changer
   Utilise pwntools: io = remote(HOST, PORT)
8. Les fichiers du challenge sont dans le dossier courant

Génère UNIQUEMENT le code Python, dans un bloc ```python ... ```""",
                system=system, max_tokens=4000)

            script = extract_code(exploit_raw)
            if not script:
                yield sse("log", {"type":"warn","msg":"[!] Pas de code Python extrait, tentative de récupération..."})
                # Tentative de récupération : prend tout le texte si ça ressemble à du code
                if "import" in exploit_raw and "print" in exploit_raw:
                    script = exploit_raw.strip()

            yield sse("step", {"step":2,"status":"done"})
            if script:
                yield sse("log", {"type":"ok","msg":f"[+] Script généré ({len(script.splitlines())} lignes)"})
            else:
                yield sse("log", {"type":"warn","msg":"[!] Script vide ou non récupérable"})
        except Exception as e:
            yield sse("step", {"step":2,"status":"error"})
            yield sse("error", {"msg":str(e)})
            return

        # ══ ÉTAPE 3 : EXÉCUTION RÉELLE ═══════════════════════════════════════
        yield sse("step", {"step":3,"status":"active"})
        exec_out   = ""
        real_flag  = None
        needs_remote = recon.get("needs_remote", False)

        if not script:
            yield sse("log", {"type":"warn","msg":"[!] Pas de script à exécuter"})
            yield sse("step", {"step":3,"status":"done"})
        elif needs_remote:
            yield sse("log", {"type":"warn","msg":f"[!] Service distant requis ({remote_hint}) — exécution locale impossible"})
            yield sse("log", {"type":"info","msg":"[→] Télécharge le script et lance-le avec la bonne adresse"})
            yield sse("step", {"step":3,"status":"done"})
        else:
            # Copie le fichier dans le sandbox si besoin
            if filepath:
                dst = os.path.join(SANDBOX_DIR, info["name"])
                if not os.path.exists(dst):
                    shutil.copy2(filepath, dst)

            yield sse("log", {"type":"info","msg":"[*] Exécution dans le sandbox..."})
            result = run_py(script, timeout=30, cwd=SANDBOX_DIR)
            exec_out = (result["out"] + result["err"]).strip()

            # Affiche les premières lignes de l'output
            for line in exec_out.split('\n')[:25]:
                if line.strip():
                    has_flag_kw = any(k in line.lower() for k in ["flag","ctf","mctf","htb","picoctf"])
                    yield sse("log", {
                        "type": "flag" if has_flag_kw and '{' in line else "dim",
                        "msg":  f"    {line[:200]}"
                    })

            # Cherche le flag STRICTEMENT dans l'output réel
            real_flag = find_flag(exec_out)

            if real_flag:
                yield sse("log", {"type":"flag","msg":f"[★] FLAG EXTRAIT: {real_flag}"})
                yield sse("step", {"step":3,"status":"done"})
            elif result["code"] != 0:
                yield sse("log", {"type":"warn","msg":f"[!] Exit {result['code']} — tentative correction..."})

                # Correction automatique (1 seule tentative)
                try:
                    fix_raw, _ = llm(api_key, f"""Ce script Python a planté. Corrige-le pour qu'il affiche le flag.

SCRIPT ORIGINAL:
```python
{script[:3000]}
```

ERREUR:
```
{result['err'][:800]}
```

OUTPUT PARTIEL:
```
{result['out'][:400]}
```

CONTEXTE DU DÉFI:
{ctx[:4000]}

Génère le script CORRIGÉ complet dans un bloc ```python ... ```.
Le script doit afficher le vrai flag avec print("FLAG:", flag).""",
                        system=system, max_tokens=3000)

                    fixed = extract_code(fix_raw)
                    if fixed and fixed != script:
                        yield sse("log", {"type":"info","msg":"[*] Re-exécution script corrigé..."})
                        r2   = run_py(fixed, timeout=30, cwd=SANDBOX_DIR)
                        out2 = (r2["out"] + r2["err"]).strip()
                        exec_out += f"\n\n=== SCRIPT CORRIGÉ ===\n{out2}"

                        for line in out2.split('\n')[:15]:
                            if line.strip():
                                has_f = any(k in line.lower() for k in ["flag","ctf","mctf","htb"])
                                yield sse("log", {
                                    "type": "flag" if has_f and '{' in line else "dim",
                                    "msg":  f"    {line[:200]}"
                                })

                        real_flag = find_flag(out2) or find_flag(exec_out)
                        if real_flag:
                            yield sse("log", {"type":"flag","msg":f"[★] FLAG: {real_flag}"})
                        script = fixed
                except Exception as e2:
                    yield sse("log", {"type":"warn","msg":f"[!] Correction IA: {e2}"})

                yield sse("step", {"step":3,"status":"done"})
            else:
                yield sse("step", {"step":3,"status":"done"})

        # ══ ÉTAPE 4 : SYNTHÈSE (HONNÊTE) ════════════════════════════════════
        yield sse("step", {"step":4,"status":"active"})

        # On ne demande PAS au LLM de "trouver" le flag — on utilise uniquement
        # ce qui a été extrait par exécution réelle.
        try:
            # Demande uniquement le writeup, pas le flag
            writeup_raw, _ = llm(api_key, f"""Écris un writeup CTF concis pour ce défi.

Catégorie: {category}
Fichier: {info['name']}
Analyse: {analysis[:800]}

{"Flag trouvé: " + real_flag if real_flag else "Flag non trouvé automatiquement (service distant ou analyse manuelle requise)"}

Écris 2-3 phrases expliquant:
1. La vulnérabilité ou le mécanisme exploité
2. La méthode de résolution
3. Pourquoi ça fonctionne

Réponds en texte simple, pas de JSON, pas de markdown.""",
                system="Tu es un expert CTF. Tu rédiges des writeups clairs et pédagogiques.",
                max_tokens=400)

            writeup = writeup_raw.strip()
        except:
            writeup = f"Défi {category} analysé. {'Flag extrait par exécution.' if real_flag else 'Exécution manuelle requise.'}"

        # Construction des données finales — FLAG SEULEMENT si trouvé réellement
        flag_data = {
            "flag_found":      bool(real_flag),
            "flag":            real_flag,          # None si pas trouvé → JAMAIS inventé
            "flag_format":     guess_format(info, desc),
            "confidence":      95 if real_flag else 0,
            "requires_runtime": needs_remote,
            "writeup":         writeup,
            "next_steps":      build_next_steps(real_flag, needs_remote, remote_hint, category),
        }

        yield sse("step", {"step":4,"status":"done"})
        if real_flag:
            yield sse("log", {"type":"flag","msg":f"[★] FLAG CONFIRMÉ: {real_flag}"})
        else:
            yield sse("log", {"type":"warn","msg":"[→] Flag non trouvé automatiquement"})
            if needs_remote:
                yield sse("log", {"type":"info","msg":f"[→] Lance le script localement contre {remote_hint or 'le serveur du challenge'}"})
            else:
                yield sse("log", {"type":"info","msg":"[→] Analyse manuelle requise — voir script généré"})

        yield sse("done", {
            "recon":       recon,
            "analysis":    analysis,
            "exploit":     f"```python\n{script}\n```" if script else "",
            "exec_output": exec_out,
            "flag":        flag_data,
        })

        # Nettoyage
        if filepath:
            try: os.remove(filepath)
            except: pass

    return Response(
        stream_with_context(stream()),
        mimetype='text/event-stream',
        headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no','Access-Control-Allow-Origin':'*'}
    )

def guess_format(info, desc):
    """Devine le format du flag depuis le contexte."""
    text = (info.get("text","") + desc).lower()
    if "mctf{" in text or "midnightflag" in text: return "MCTF{...}"
    if "htb{" in text or "hackthebox" in text:    return "HTB{...}"
    if "picoctf{" in text:                        return "picoCTF{...}"
    if "thcon{" in text:                          return "THCON{...}"
    return "CTF{...}"

def build_next_steps(flag, needs_remote, remote, cat):
    if flag:
        return "Flag trouvé ! Soumets-le sur la plateforme."
    if needs_remote:
        return f"Lance le script Python téléchargé localement : python3 solution.py\nChange HOST/PORT pour pointer vers {remote or 'le serveur du challenge'}."
    steps = {
        "reverse":  "Lance le binaire dans gdb/pwndbg avec des inputs variés. Utilise angr pour l'analyse symbolique.",
        "pwn":      "Lance le script pwntools contre le serveur du challenge. Ajuste HOST/PORT.",
        "web":      "Lance le script requests contre l'URL du challenge. Vérifie les cookies de session.",
        "crypto":   "Vérifie que toutes les valeurs numériques (n, e, c) sont correctement copiées.",
        "forensics":"Utilise binwalk/steghide/volatility sur le fichier original.",
    }
    return steps.get(cat, "Analyse manuelle requise. Voir le script généré et l'analyse.")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
