from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from groq import Groq
import json, zipfile, re, os, tempfile, base64, hashlib, time
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, origins="*")

UPLOAD_FOLDER = tempfile.mkdtemp()

# ── SYSTEM PROMPTS PAR CATÉGORIE ─────────────────────────────────────────────
AGENT_PROMPTS = {
    "reverse": """Tu es un expert en reverse engineering de niveau mondial (CTF Top 10 global).
Spécialités: ELF/PE/Mach-O, bytecode Python/Java/.NET, VM custom, obfuscation, anti-debug.
Outils maîtrisés: Ghidra, IDA Pro, radare2, angr, unicorn, pwndbg, ltrace, strace, objdump, strings, file, binwalk.
Techniques: décompilation, émulation, symbolic execution, patching binaire, keygen.
Tu RÉSOUS le défi, tu ne te contentes pas de l'analyser. Tu génères le code qui trouve le flag.""",

    "pwn": """Tu es un expert en binary exploitation de niveau mondial (CTF Top 10 global).
Spécialités: stack/heap overflow, ROP chains, format string, use-after-free, kernel pwn, ASLR/PIE bypass.
Outils maîtrisés: pwntools, ROPgadget, one_gadget, pwndbg, GDB, checksec, ropper.
Tu identifies la vulnérabilité EXACTE, calcules les offsets, génères l'exploit pwntools complet.
Tu RÉSOUS le défi avec un script fonctionnel.""",

    "web": """Tu es un expert en web exploitation de niveau mondial (CTF Top 10 global).
Spécialités: SQLi (blind/error/union), XSS, SSRF, SSTI (Jinja2/Twig/Pebble), JWT forging, LFI/RFI, 
deserialization (PHP/Java/Python), IDOR, path traversal, prototype pollution, CORS abuse, OAuth.
Outils: sqlmap, ffuf, burpsuite, nuclei, curl, Python requests.
Tu identifies la vulnérabilité, génères le payload exact, et le script de récupération du flag.""",

    "crypto": """Tu es un expert en cryptanalyse de niveau mondial (CTF Top 10 global).
Spécialités: RSA (small e, wiener, fermat, common modulus, LSB oracle, padding oracle), AES (ECB, CBC bitflip, 
padding oracle, GCM nonce reuse), ECC (invalid curve, DLP), DH (small subgroup, logjam), hash length extension,
PRNG prediction, XOR (key recovery, many-time-pad), custom ciphers, encodages (base64/hex/rot/morse/bacon).
Outils: SageMath, sympy, pycryptodome, RsaCtfTool, hashcat, CyberChef.
Tu identifies la faiblesse mathématique EXACTE et génères l'attaque en Python.""",

    "forensics": """Tu es un expert en forensics/stéganographie de niveau mondial (CTF Top 10 global).
Spécialités: PCAP analysis (HTTP/DNS/FTP/SMTP extraction), memory forensics (volatility), disk forensics,
stéganographie (PNG LSB, JPEG, WAV, PDF, docx), fichiers cachés, métadonnées, timestamps, carving.
Outils: volatility3, wireshark/tshark, binwalk, steghide, zsteg, stegsolve, foremost, exiftool, 
strings, file, xxd, pngcheck, identify, audacity (spectre), outguess.
Tu identifies la technique de dissimulation et extrais les données cachées.""",

    "misc": """Tu es un expert CTF polyvalent de niveau mondial (CTF Top 10 global).
Spécialités: scripting (bash/python/perl), OSINT, blockchain (Ethereum/Solidity vulns), 
jail escape (Python/Bash/Pyjail), QR codes, steganographie créative, protocoles custom,
encodages exotiques (brainfuck, ook, malbolge, whitespace), puzzles logiques, trivia.
Tu résous tout type de défi créatif avec ingéniosité.""",
}

GLOBAL_SYSTEM_SUFFIX = """
FORMAT DU FLAG: MCTF{...} — c'est le seul format valide pour ce CTF.

RÈGLES ABSOLUES:
1. Tu RÉSOUS le défi, pas seulement tu l'analyses
2. Ton code Python doit être EXÉCUTABLE tel quel (imports inclus)
3. Si le flag est calculable statiquement: tu le calcules et l'affiches
4. Tu cherches MCTF{...} dans TOUTES les sorties possibles
5. Tu testes plusieurs approches si la première échoue
6. Tu n'abandonnes jamais — tu trouves toujours un vecteur d'attaque
"""

# ── EXTRACTION FICHIER ────────────────────────────────────────────────────────
def extract_file_content(filepath, filename):
    ext  = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath)
    result = {"name": filename, "size": size, "ext": ext,
              "text": "", "hex": "", "strings": [], "files": [],
              "b64": "", "entropy": 0.0}

    TEXT_EXT = {'.py','.js','.ts','.c','.cpp','.h','.rs','.go','.java','.rb',
                '.php','.html','.css','.sh','.md','.json','.xml','.yaml','.asm',
                '.s','.txt','.sage','.pl','.lua','.nim','.kt','.cs','.r','.m',
                '.swift','.vb','.ps1','.bat','.ex','.exs','.erl','.sol','.cairo',
                '.move','.vy','.tf','.conf','.ini','.env','.toml'}

    with open(filepath, 'rb') as f:
        raw_bytes = f.read()

    # Entropie Shannon
    if raw_bytes:
        freq = {}
        for b in raw_bytes:
            freq[b] = freq.get(b, 0) + 1
        import math
        entropy = -sum((c/len(raw_bytes)) * math.log2(c/len(raw_bytes)) for c in freq.values())
        result["entropy"] = round(entropy, 2)

    # Texte
    try:
        if ext in TEXT_EXT or size < 500000:
            result["text"] = raw_bytes.decode('utf-8', errors='replace')[:60000]
            return result
    except:
        pass

    # Binaire → hex + strings + b64 (petit fichier)
    result["hex"] = ' '.join(f'{b:02x}' for b in raw_bytes[:2048])
    s, strings = b"", []
    for b in raw_bytes:
        if 32 <= b < 127:
            s += bytes([b])
        else:
            if len(s) >= 4:
                strings.append(s.decode('ascii', errors='replace'))
            s = b""
    if len(s) >= 4:
        strings.append(s.decode('ascii', errors='replace'))
    result["strings"] = strings[:200]

    # Petit binaire → base64 pour l'IA
    if size <= 65536:
        result["b64"] = base64.b64encode(raw_bytes).decode()

    # ZIP → extraire contenu texte
    if ext in ('.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx'):
        try:
            with zipfile.ZipFile(filepath) as z:
                result["files"] = z.namelist()
                parts = []
                for name in result["files"][:50]:
                    if any(name.lower().endswith(e) for e in [
                        '.py','.js','.c','.txt','.md','.json','.sh','.php','.html',
                        '.sage','.rb','.rs','.go','.java','.cs','.ts','.sol','.vy',
                        '.xml','.yaml','.toml','.conf','.env','.cfg','.ini','.log'
                    ]):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')[:8000]
                            parts.append(f"=== {name} ===\n{content}")
                        except:
                            pass
                if parts:
                    result["text"] = "\n\n".join(parts)
        except Exception as e:
            result["text"] = f"[Erreur ZIP: {e}]"

    return result

def build_context(content, description):
    ctx = f"=== DÉFI CTF ===\n"
    ctx += f"Fichier: {content['name']} ({content['size']} octets, ext: {content['ext']})\n"
    if content.get("entropy"):
        ctx += f"Entropie: {content['entropy']}/8.0"
        if content['entropy'] > 7.0:
            ctx += " (HAUTE → probablement chiffré/compressé)"
        elif content['entropy'] < 3.0:
            ctx += " (BASSE → texte ou données simples)"
        ctx += "\n"

    if content["files"]:
        ctx += f"Contenu archive ({len(content['files'])} fichiers): {', '.join(content['files'][:50])}\n"

    if content["text"]:
        ctx += f"\n--- CONTENU ---\n```\n{content['text'][:24000]}\n```\n"
    elif content["b64"]:
        ctx += f"\n--- CONTENU BASE64 (petit binaire) ---\n{content['b64'][:8000]}\n"
        ctx += f"\n--- HEX DUMP ---\n{content['hex'][:3000]}\n"
        if content["strings"]:
            ctx += f"\n--- STRINGS ({len(content['strings'])} trouvées) ---\n"
            ctx += "\n".join(content["strings"][:100])
    elif content["hex"]:
        ctx += f"\n--- HEX DUMP (2KB) ---\n{content['hex']}\n"
        if content["strings"]:
            ctx += f"\n--- STRINGS ({len(content['strings'])} trouvées) ---\n"
            ctx += "\n".join(content["strings"][:100])

    if description:
        ctx += f"\n--- DESCRIPTION / ÉNONCÉ ---\n{description}\n"

    ctx += "\n=== FIN DÉFI ==="
    return ctx

def detect_category(content, description, hint):
    if hint and hint != "auto":
        return hint
    text = (content.get("text","") + " ".join(content.get("strings",[])) + description).lower()
    ext  = content.get("ext","")
    name = content.get("name","").lower()

    scores = {"reverse": 0, "pwn": 0, "web": 0, "crypto": 0, "forensics": 0, "misc": 0}

    # Forensics
    if ext in ['.pcap','.pcapng','.cap']: scores["forensics"] += 10
    for k in ["wireshark","packet","pcap","volatility","memory dump","disk image","steganograph",
               "hidden","metadata","exif","wav","spectrogram","png","jpeg stego"]:
        if k in text: scores["forensics"] += 2

    # Pwn
    if ext in ['.elf'] and any(k in text for k in ["nc ","netcat","exploit","pwn"]):
        scores["pwn"] += 5
    for k in ["overflow","rop","heap","libc","got","plt","shellcode","canary","aslr",
               "pie","nx","ret2","format string","pwntools","one_gadget","gadget"]:
        if k in text: scores["pwn"] += 2

    # Reverse
    if ext in ['.elf','.exe','.dll','.so','.dylib','.pyc','.class']: scores["reverse"] += 4
    for k in ["ghidra","radare","disasm","decompile","antidebug","ptrace","keygen",
               "serial","license","crack","unpack","obfuscat"]:
        if k in text: scores["reverse"] += 2

    # Crypto
    for k in ["rsa","aes","encrypt","decrypt","cipher","hash","modulus","prime","elliptic",
               "xor","base64","caesar","vigenere","rot13","md5","sha","hmac","ecdsa","dh ",
               "diffie","padding oracle","cbc","ecb","gcm","nonce","key","secret"]:
        if k in text: scores["crypto"] += 2

    # Web
    for k in ["http","sql","xss","login","cookie","jwt","flask","django","node","php",
               "mysql","postgres","injection","ssrf","ssti","lfi","rfi","serialize",
               "upload","admin","password","token","session","cors","graphql"]:
        if k in text: scores["web"] += 2

    # Misc
    for k in ["blockchain","solidity","ethereum","smart contract","brainfuck","ook",
               "morse","qr code","barcode","osint","jail","sandbox","pyjail"]:
        if k in text: scores["misc"] += 3

    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "reverse"

# ── GROQ CALL AVEC RETRY ─────────────────────────────────────────────────────
def groq_call(client, model, system, user_content, max_tokens, retries=2):
    full_system = system + GLOBAL_SYSTEM_SUFFIX
    for attempt in range(retries + 1):
        try:
            resp = client.chat.completions.create(
                model=model,
                max_tokens=max_tokens,
                temperature=0.15,   # bas = plus déterministe et précis
                messages=[
                    {"role": "system", "content": full_system},
                    {"role": "user",   "content": user_content}
                ]
            )
            text   = resp.choices[0].message.content
            tokens = resp.usage.prompt_tokens + resp.usage.completion_tokens
            return text, tokens
        except Exception as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise

def extract_flag(text):
    """Cherche MCTF{...} dans un texte."""
    patterns = [
        r'MCTF\{[^}]{1,200}\}',
        r'mctf\{[^}]{1,200}\}',
        r'flag["\s:=]+MCTF\{[^}]{1,200}\}',
        r'FLAG["\s:=]+MCTF\{[^}]{1,200}\}',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            flag = m.group()
            # Normalise vers MCTF{...}
            inner = re.search(r'\{[^}]+\}', flag)
            if inner:
                return "MCTF" + inner.group()
    return None

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "4.0-groq", "service": "ctf-neural"})

@app.route('/analyze', methods=['POST'])
def analyze():
    api_key = request.headers.get('X-API-Key', '')
    if not api_key or not api_key.startswith('gsk_'):
        return jsonify({"error": "Clé API Groq manquante ou invalide (doit commencer par gsk_)"}), 401

    description = request.form.get('description', '').strip()
    category    = request.form.get('category', 'auto')
    model       = request.form.get('model', 'llama-3.3-70b-versatile')

    content = {
        "name": "texte-libre", "size": len(description),
        "ext": ".txt", "text": description,
        "hex": "", "strings": [], "files": [], "b64": "", "entropy": 0.0
    }

    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            filename = secure_filename(f.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            f.save(filepath)
            try:
                content = extract_file_content(filepath, filename)
                # Ajoute la description au contexte même si fichier présent
                if description and not content.get("text","").endswith(description):
                    content["_desc"] = description
            finally:
                try: os.remove(filepath)
                except: pass

    if not content["text"] and not content["hex"] and not content["b64"] and not description:
        return jsonify({"error": "Aucun contenu à analyser"}), 400

    category = detect_category(content, description, category)
    ctx      = build_context(content, description)
    system   = AGENT_PROMPTS.get(category, AGENT_PROMPTS["misc"])

    def generate():
        client       = Groq(api_key=api_key)
        total_tokens = 0
        results      = {}

        def sse(event, data):
            return f"data: {json.dumps({'event': event, 'data': data}, ensure_ascii=False)}\n\n"

        yield sse("start", {"file": content["name"], "category": category, "size": content["size"]})

        # ────────────────────────────────────────────────────────────────────
        # STEP 0 — RECON + CLASSIFICATION
        # ────────────────────────────────────────────────────────────────────
        yield sse("step", {"step": 0, "status": "active", "label": "Reconnaissance"})
        try:
            raw, toks = groq_call(client, model, system, f"""Analyse ce défi CTF de manière exhaustive.

{ctx}

Réponds UNIQUEMENT en JSON valide (aucun texte avant/après, aucun markdown):
{{
  "category": "{category}",
  "difficulty": "easy|medium|hard|expert",
  "file_type": "description précise",
  "language": "langage principal",
  "encoding_detected": "si encodage détecté: base64/hex/rot13/xor/custom/none",
  "key_observations": [
    "observation 1 très précise et technique",
    "observation 2",
    "observation 3",
    "observation 4",
    "observation 5"
  ],
  "protections": ["protection 1", "protection 2"],
  "attack_surface": "surface d'attaque principale",
  "vulnerability": "vulnérabilité ou faiblesse principale identifiée",
  "main_hint": "indice le plus important pour trouver MCTF{{...}}",
  "quick_wins": ["technique rapide 1 à essayer", "technique rapide 2"],
  "confidence": 90
}}""", max_tokens=900)
            total_tokens += toks
            try:
                results["recon"] = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except:
                results["recon"] = {
                    "category": category, "difficulty": "medium",
                    "key_observations": [], "protections": [],
                    "attack_surface": "analyse en cours",
                    "vulnerability": "inconnue",
                    "quick_wins": [], "confidence": 50
                }
            yield sse("step", {"step": 0, "status": "done", "data": results["recon"]})
            r = results["recon"]
            yield sse("log", {"type": "ok",   "msg": f"[+] {r.get('category','?').upper()} · {r.get('difficulty','?')} · confiance {r.get('confidence','?')}%"})
            yield sse("log", {"type": "info", "msg": f"[*] Type: {r.get('file_type','?')} | Encodage: {r.get('encoding_detected','?')}"})
            if r.get("vulnerability"):
                yield sse("log", {"type": "warn", "msg": f"[!] Vulnérabilité: {r['vulnerability']}"})
            for obs in r.get("key_observations", []):
                yield sse("log", {"type": "dim", "msg": f"    ▸ {obs}"})
            if r.get("protections"):
                yield sse("log", {"type": "warn", "msg": f"[!] Protections: {', '.join(r['protections'])}"})
            for qw in r.get("quick_wins", []):
                yield sse("log", {"type": "info", "msg": f"[⚡] Quick win: {qw}"})
            if r.get("main_hint"):
                yield sse("log", {"type": "info", "msg": f"[★] Indice clé: {r['main_hint']}"})
        except Exception as e:
            yield sse("step", {"step": 0, "status": "error"})
            yield sse("error", {"msg": f"Étape Recon: {str(e)}"})
            return

        # ────────────────────────────────────────────────────────────────────
        # STEP 1 — ANALYSE PROFONDE + DÉCODAGE DIRECT
        # ────────────────────────────────────────────────────────────────────
        yield sse("step", {"step": 1, "status": "active", "label": "Analyse approfondie"})
        try:
            recon_ctx = f"""Catégorie: {results['recon'].get('category')}
Difficulté: {results['recon'].get('difficulty')}
Vulnérabilité identifiée: {results['recon'].get('vulnerability')}
Surface d'attaque: {results['recon'].get('attack_surface')}
Observations: {json.dumps(results['recon'].get('key_observations', []))}
Quick wins: {json.dumps(results['recon'].get('quick_wins', []))}"""

            raw, toks = groq_call(client, model, system, f"""Analyse technique approfondie + tentative de résolution directe.

{ctx}

CONTEXTE RECON:
{recon_ctx}

MISSION: Analyse ET résous si possible maintenant.

1. DÉCODAGE IMMÉDIAT: Si tu vois du base64/hex/rot/xor/encodage → décode-le maintenant et cherche MCTF{{...}}
2. ANALYSE DÉTAILLÉE:
   - Vulnérabilités précises avec localisation (ligne, fonction, offset)
   - Algorithme de vérification/génération du flag
   - Flux d'exécution complet
   - Valeurs magiques, constantes, clés hardcodées
3. ATTAQUE DIRECTE: Si le flag est visible/calculable maintenant → donne-le
4. POINTS D'ENTRÉE: Liste ordonnée par probabilité de succès
5. PIÈGES: Anti-debug, fausses pistes, honeypots

Si tu trouves MCTF{{...}} → écris "FLAG_FOUND: MCTF{{valeur}}" en majuscules.""", max_tokens=3000)
            total_tokens += toks
            results["analysis"] = raw

            # Cherche flag dans l'analyse
            flag_direct = extract_flag(raw)
            if flag_direct:
                yield sse("log", {"type": "flag", "msg": f"[★★★] FLAG TROUVÉ EN ANALYSE: {flag_direct}"})
                results["early_flag"] = flag_direct

            yield sse("step", {"step": 1, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Analyse technique complète"})
            for line in raw.split('\n')[:6]:
                if line.strip() and not line.startswith('#') and len(line.strip()) > 10:
                    yield sse("log", {"type": "dim", "msg": f"    {line.strip()[:140]}"})
        except Exception as e:
            yield sse("step", {"step": 1, "status": "error"})
            yield sse("error", {"msg": f"Étape Analyse: {str(e)}"})
            return

        # ────────────────────────────────────────────────────────────────────
        # STEP 2 — STRATÉGIE D'ATTAQUE CIBLÉE
        # ────────────────────────────────────────────────────────────────────
        yield sse("step", {"step": 2, "status": "active", "label": "Stratégie d'attaque"})
        try:
            raw, toks = groq_call(client, model, system, f"""Stratégie de résolution COMPLÈTE pour ce défi CTF.

DÉFI (résumé):
{ctx[:4000]}

ANALYSE:
{results['analysis'][:2000]}

Produis:

## ÉTAPES DE RÉSOLUTION (ordonnées, concrètes)
Étape 1: [action + commande exacte]
Étape 2: ...

## COMMANDES IMMÉDIATES
```bash
# À copier-coller directement
strings fichier | grep MCTF
binwalk -e fichier
file fichier
xxd fichier | head -50
```

## ATTAQUE PRINCIPALE
Décris précisément comment obtenir MCTF{{...}}:
- Quel algorithme inverser / quelle clé utiliser / quel payload injecter
- Output attendu à chaque étape
- Où apparaît le flag

## PLAN B (si l'attaque principale échoue)
Alternative technique complète.""", max_tokens=2000)
            total_tokens += toks
            results["strategy"] = raw
            yield sse("step", {"step": 2, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Stratégie d'attaque définie"})
        except Exception as e:
            yield sse("step", {"step": 2, "status": "error"})
            yield sse("error", {"msg": f"Étape Stratégie: {str(e)}"})
            return

        # ────────────────────────────────────────────────────────────────────
        # STEP 3 — SCRIPT DE RÉSOLUTION COMPLET
        # ────────────────────────────────────────────────────────────────────
        yield sse("step", {"step": 3, "status": "active", "label": "Génération exploit"})
        try:
            raw, toks = groq_call(client, model, system, f"""Génère le script Python COMPLET qui résout ce défi CTF et affiche MCTF{{...}}.

DÉFI:
{ctx[:5000]}

ANALYSE:
{results['analysis'][:1500]}

STRATÉGIE:
{results['strategy'][:1500]}

EXIGENCES ABSOLUES:
1. Script Python 3 complet, exécutable tel quel
2. Tous les imports en tête
3. Si flag statique → le calcule et affiche `print("FLAG:", flag)`
4. Si réseau requis → pwntools/requests complet avec HOST/PORT configurables
5. Gère TOUS les cas: décodage, crypto, exploitation, extraction
6. Cherche et affiche MCTF{{...}} explicitement
7. Commente chaque section importante
8. Ajoute une section "# APPROCHE ALTERNATIVE" si la principale peut échouer

```python
#!/usr/bin/env python3
# CTF·NEURAL Solution — {content['name']}
# Catégorie: {category}
# Flag format: MCTF{{...}}

# === IMPORTS ===
[tous les imports]

# === CONFIGURATION ===
HOST = "localhost"  # modifier si remote
PORT = 1337         # modifier si remote

# === SOLUTION PRINCIPALE ===
def solve():
    [code complet]
    print("FLAG:", flag)

# === APPROCHE ALTERNATIVE ===
def solve_alt():
    [plan B]

if __name__ == "__main__":
    solve()
```""", max_tokens=4000)
            total_tokens += toks
            results["exploit"] = raw

            # Cherche flag dans le script
            flag_in_script = extract_flag(raw)
            if flag_in_script:
                yield sse("log", {"type": "flag", "msg": f"[★★★] FLAG DANS LE SCRIPT: {flag_in_script}"})
                results["script_flag"] = flag_in_script

            yield sse("step", {"step": 3, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Script de résolution généré"})
        except Exception as e:
            yield sse("step", {"step": 3, "status": "error"})
            yield sse("error", {"msg": f"Étape Exploit: {str(e)}"})
            return

        # ────────────────────────────────────────────────────────────────────
        # STEP 4 — EXTRACTION FLAG + SYNTHÈSE
        # ────────────────────────────────────────────────────────────────────
        yield sse("step", {"step": 4, "status": "active", "label": "Extraction flag"})
        try:
            # Priorité: flag trouvé dans les étapes précédentes
            early_flag = results.get("early_flag") or results.get("script_flag")

            all_results = f"""ANALYSE: {results['analysis'][:1000]}
SCRIPT: {results['exploit'][:2000]}
STRATÉGIE: {results['strategy'][:500]}"""

            raw, toks = groq_call(client, model, system, f"""Synthèse finale. TROUVE et DONNE le flag MCTF{{...}}.

{all_results}

DÉFI ORIGINAL:
{ctx[:2000]}

INSTRUCTIONS:
- Si le flag MCTF{{...}} est visible dans l'analyse ou le script → donne-le dans "flag"
- Si tu peux le calculer mentalement → fais-le et donne-le
- Format OBLIGATOIRE: MCTF{{contenu}} (avec accolades)
- Sois certain à 100% avant de le mettre, sinon mets null

Réponds UNIQUEMENT en JSON valide:
{{
  "flag_found": true,
  "flag": "MCTF{{valeur_exacte_ou_null}}",
  "flag_format": "MCTF{{...}}",
  "confidence": 95,
  "requires_runtime": false,
  "solve_method": "méthode exacte utilisée pour trouver le flag",
  "writeup": "Résumé technique complet: vulnérabilité exploitée, méthode d'attaque, comment le flag a été obtenu.",
  "next_steps": "Si non trouvé: commandes exactes à exécuter pour obtenir le flag"
}}""", max_tokens=800)
            total_tokens += toks

            try:
                flag_data = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except:
                flag_data = {
                    "flag_found": False, "flag": None, "confidence": 0,
                    "flag_format": "MCTF{...}", "requires_runtime": True,
                    "solve_method": "voir script généré",
                    "writeup": "Analyse complète effectuée. Voir le script généré.",
                    "next_steps": "Exécute le script Python généré."
                }

            # Override si flag trouvé plus tôt
            if early_flag and not flag_data.get("flag"):
                flag_data["flag"] = early_flag
                flag_data["flag_found"] = True
                flag_data["confidence"] = 99

            # Validation format MCTF
            if flag_data.get("flag"):
                f_val = flag_data["flag"]
                if not re.match(r'^MCTF\{.+\}$', f_val):
                    # Tente extraction
                    extracted = extract_flag(f_val)
                    if extracted:
                        flag_data["flag"] = extracted
                    else:
                        flag_data["flag"] = None
                        flag_data["flag_found"] = False

            results["flag_data"] = flag_data
            yield sse("step", {"step": 4, "status": "done"})

            fd = results["flag_data"]
            if fd.get("flag"):
                yield sse("log", {"type": "flag", "msg": f"[★★★] FLAG: {fd['flag']}"})
                yield sse("log", {"type": "ok",   "msg": f"[+] Méthode: {fd.get('solve_method','?')}"})
                yield sse("log", {"type": "ok",   "msg": f"[+] Confiance: {fd.get('confidence','?')}%"})
            else:
                yield sse("log", {"type": "warn", "msg": f"[!] Flag nécessite exécution dynamique. Format: MCTF{{...}}"})
                if fd.get("next_steps"):
                    yield sse("log", {"type": "info", "msg": f"[→] {fd['next_steps']}"})
        except Exception as e:
            yield sse("step", {"step": 4, "status": "error"})
            yield sse("error", {"msg": f"Étape Flag: {str(e)}"})
            return

        # ── DONE ─────────────────────────────────────────────────────────────
        yield sse("done", {
            "recon":    results.get("recon", {}),
            "analysis": results.get("analysis", ""),
            "strategy": results.get("strategy", ""),
            "exploit":  results.get("exploit", ""),
            "flag":     results.get("flag_data", {}),
            "tokens":   total_tokens,
        })

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'X-API-Key, Content-Type',
        }
    )

@app.route('/analyze', methods=['OPTIONS'])
def analyze_options():
    return '', 204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'X-API-Key, Content-Type',
    }

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
