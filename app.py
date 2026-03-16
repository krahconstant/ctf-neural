from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from groq import Groq
import json, zipfile, re, os, tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app, origins="*")

UPLOAD_FOLDER = tempfile.mkdtemp()

AGENT_PROMPTS = {
    "reverse":  "Tu es un expert en reverse engineering (ELF, PE, Mach-O, bytecode, VM custom). Tu maîtrises objdump, ghidra, radare2, pwndbg, angr, unicorn. Tu analyses les protections anti-debug, les algorithmes custom, les structures de données.",
    "pwn":      "Tu es un expert en binary exploitation (stack overflow, heap, ROP chains, format string, kernel pwn). Tu maîtrises pwntools, ROPgadget, one_gadget, pwndbg. Tu identifies les vulnérabilités et génères des exploits fonctionnels.",
    "web":      "Tu es un expert en web exploitation (SQLi, XSS, SSRF, SSTI, JWT, OAuth, LFI/RFI, deserialization, IDOR, path traversal). Tu maîtrises sqlmap, ffuf, burpsuite, nuclei. Tu analyses le code source et les comportements HTTP.",
    "crypto":   "Tu es un expert en cryptanalyse (RSA, AES, ECC, DH, hash, PRNG, custom ciphers). Tu maîtrises SageMath, sympy, pycryptodome, RsaCtfTool, hashcat. Tu identifies les faiblesses mathématiques et implémente les attaques.",
    "forensics":"Tu es un expert en forensics et stéganographie (pcap, mémoire dump, disque, images PNG/JPEG/WAV, PDF). Tu maîtrises volatility, wireshark, binwalk, steghide, foremost, exiftool, zsteg, strings.",
    "misc":     "Tu es un expert CTF polyvalent. Tu analyses tous types de défis créatifs: scripting, OSINT, blockchain, reversing de protocoles, escape game, puzzle.",
}

def extract_file_content(filepath, filename):
    ext = os.path.splitext(filename)[1].lower()
    size = os.path.getsize(filepath)
    result = {
        "name": filename, "size": size, "ext": ext,
        "text": "", "hex": "", "strings": [], "files": []
    }
    TEXT_EXT = {'.py','.js','.ts','.c','.cpp','.h','.rs','.go','.java','.rb',
                '.php','.html','.css','.sh','.md','.json','.xml','.yaml','.asm',
                '.s','.txt','.sage','.pl','.lua','.nim','.kt','.cs','.r','.m',
                '.swift','.vb','.ps1','.bat','.nim','.ex','.exs','.erl'}
    try:
        if ext in TEXT_EXT or size < 200000:
            with open(filepath, 'r', errors='replace') as f:
                result["text"] = f.read(40000)
            return result
    except:
        pass
    with open(filepath, 'rb') as f:
        data = f.read()
    result["hex"] = ' '.join(f'{b:02x}' for b in data[:768])
    s, strings = b"", []
    for b in data:
        if 32 <= b < 127:
            s += bytes([b])
        else:
            if len(s) >= 4:
                strings.append(s.decode('ascii', errors='replace'))
            s = b""
    if len(s) >= 4:
        strings.append(s.decode('ascii', errors='replace'))
    result["strings"] = strings[:120]
    if ext == '.zip':
        try:
            with zipfile.ZipFile(filepath) as z:
                result["files"] = z.namelist()
                parts = []
                for name in result["files"][:30]:
                    if any(name.endswith(e) for e in ['.py','.js','.c','.txt','.md','.json','.sh','.php','.html','.sage','.rb','.rs','.go','.java','.cs','.ts']):
                        try:
                            content = z.read(name).decode('utf-8', errors='replace')[:4000]
                            parts.append(f"=== {name} ===\n{content}")
                        except:
                            pass
                if parts:
                    result["text"] = "\n\n".join(parts)
        except Exception as e:
            result["text"] = f"[Erreur lecture ZIP: {e}]"
    return result

def build_context(content, description):
    ctx = f"Fichier: {content['name']} ({content['size']} octets, type: {content['ext']})\n"
    if content["files"]:
        ctx += f"Contenu archive: {', '.join(content['files'][:40])}\n"
    if content["text"]:
        ctx += f"\nContenu du fichier:\n```\n{content['text'][:16000]}\n```\n"
    elif content["hex"]:
        ctx += f"\nHex dump (768 premiers octets):\n{content['hex']}\n"
        if content["strings"]:
            ctx += f"\nChaînes ASCII extraites ({len(content['strings'])} trouvées):\n"
            ctx += "\n".join(content["strings"][:60])
    if description:
        ctx += f"\n\nDescription fournie:\n{description}\n"
    return ctx

def detect_category(content, description, hint):
    if hint and hint != "auto":
        return hint
    text = (content.get("text","") + " ".join(content.get("strings",[])) + description).lower()
    name = content.get("name","").lower()
    ext  = content.get("ext","")
    if ext in ['.pcap','.pcapng','.cap'] or "wireshark" in text or "packet" in text:
        return "forensics"
    if any(k in text for k in ["overflow","rop","heap","libc","got","plt","shellcode","canary","aslr","pie","nx","ret2"]):
        return "pwn"
    if ext in ['.elf','.exe','.dll','.so','.dylib'] or any(k in text for k in ["ghidra","radare","disasm","decompile","antidebug","ptrace"]):
        return "reverse"
    if any(k in text for k in ["rsa","aes","encrypt","decrypt","cipher","hash","modulus","prime","elliptic","xor key","base64","caesar","vigenere"]):
        return "crypto"
    if any(k in text for k in ["http","sql","xss","login","cookie","jwt","flask","django","node","php","mysql","postgres","injection"]):
        return "web"
    return "reverse"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "3.1-groq", "service": "ctf-neural"})

@app.route('/analyze', methods=['POST'])
def analyze():
    api_key = request.headers.get('X-API-Key', '')
    # Groq keys start with "gsk_"
    if not api_key or not api_key.startswith('gsk_'):
        return jsonify({"error": "Clé API Groq manquante ou invalide (doit commencer par gsk_)"}), 401

    description = request.form.get('description', '').strip()
    category    = request.form.get('category', 'auto')
    model       = request.form.get('model', 'llama-3.3-70b-versatile')

    content = {
        "name": "texte-libre", "size": len(description),
        "ext": ".txt", "text": description,
        "hex": "", "strings": [], "files": []
    }

    if 'file' in request.files:
        f = request.files['file']
        if f and f.filename:
            filename = secure_filename(f.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            f.save(filepath)
            try:
                content = extract_file_content(filepath, filename)
            finally:
                try:
                    os.remove(filepath)
                except:
                    pass

    if not content["text"] and not content["hex"] and not description:
        return jsonify({"error": "Aucun contenu à analyser"}), 400

    category = detect_category(content, description, category)
    ctx = build_context(content, description)
    system = AGENT_PROMPTS.get(category, AGENT_PROMPTS["misc"]) + "\n\nTu es un expert CTF de niveau compétition mondiale. Tes réponses sont précises, techniques et actionnables. Tu génères du code Python fonctionnel."

    def groq_call(client, model, system, user_content, max_tokens):
        """Helper: call Groq API and return (text, tokens_used)"""
        resp = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user_content}
            ]
        )
        text   = resp.choices[0].message.content
        tokens = resp.usage.prompt_tokens + resp.usage.completion_tokens
        return text, tokens

    def generate():
        client = Groq(api_key=api_key)
        total_tokens = 0
        results = {}

        def sse(event, data):
            return f"data: {json.dumps({'event': event, 'data': data}, ensure_ascii=False)}\n\n"

        yield sse("start", {
            "file": content["name"],
            "category": category,
            "size": content["size"]
        })

        # ── STEP 0: RECON ────────────────────────────────────────────────────
        yield sse("step", {"step": 0, "status": "active", "label": "Reconnaissance"})
        try:
            raw, toks = groq_call(client, model, system, f"""Analyse ce défi CTF et classifie-le précisément.

{ctx}

Réponds UNIQUEMENT en JSON valide (pas de markdown, pas de texte avant/après):
{{
  "category": "{category}",
  "difficulty": "easy|medium|hard|expert",
  "file_type": "description précise du type de fichier",
  "language": "langage/techno principale détectée",
  "key_observations": [
    "observation technique précise 1",
    "observation technique précise 2",
    "observation technique précise 3",
    "observation technique précise 4"
  ],
  "protections": ["liste des protections/mitigations détectées"],
  "attack_surface": "description courte de la surface d'attaque",
  "main_hint": "indice principal le plus important pour résoudre",
  "confidence": 95
}}""", max_tokens=700)
            total_tokens += toks
            try:
                results["recon"] = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except:
                results["recon"] = {
                    "category": category, "difficulty": "medium",
                    "key_observations": [], "protections": [],
                    "attack_surface": "analyse en cours", "confidence": 50
                }
            yield sse("step", {"step": 0, "status": "done", "data": results["recon"]})
            r = results["recon"]
            yield sse("log", {"type": "ok",   "msg": f"[+] {r.get('category','?').upper()} · {r.get('difficulty','?')} · confiance {r.get('confidence','?')}%"})
            yield sse("log", {"type": "info", "msg": f"[*] Type: {r.get('file_type','?')}"})
            for obs in r.get("key_observations", []):
                yield sse("log", {"type": "dim", "msg": f"    ▸ {obs}"})
            if r.get("protections"):
                yield sse("log", {"type": "warn", "msg": f"[!] Protections: {', '.join(r['protections'])}"})
            if r.get("main_hint"):
                yield sse("log", {"type": "info", "msg": f"[*] Indice clé: {r['main_hint']}"})
        except Exception as e:
            yield sse("step", {"step": 0, "status": "error"})
            yield sse("error", {"msg": f"Étape Recon: {str(e)}"})
            return

        # ── STEP 1: ANALYSE ──────────────────────────────────────────────────
        yield sse("step", {"step": 1, "status": "active", "label": "Analyse approfondie"})
        try:
            raw, toks = groq_call(client, model, system, f"""Analyse technique approfondie de ce défi CTF.

{ctx}

Classification: catégorie={results['recon'].get('category')}, difficulté={results['recon'].get('difficulty')}, surface={results['recon'].get('attack_surface')}

Analyse détaillée:
1. **Vulnérabilités identifiées**: liste précise avec localisation dans le code/binaire
2. **Algorithmes et structures**: identifie les algos, les encodages, les structures de données clés
3. **Flux d'exécution**: comment le programme fonctionne, comment le flag est vérifié/généré
4. **Points d'entrée**: où et comment attaquer
5. **Indices cachés**: valeurs magiques, constantes, noms de fonctions, commentaires révélateurs
6. **Outils recommandés**: liste spécifique avec commandes d'usage
7. **Pièges possibles**: anti-debug, fausses pistes, obfuscation

Sois très précis et technique. Cite des éléments spécifiques du code/binaire.""", max_tokens=2200)
            total_tokens += toks
            results["analysis"] = raw
            yield sse("step", {"step": 1, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Analyse technique complète"})
            for line in results["analysis"].split('\n')[:5]:
                if line.strip() and not line.startswith('#'):
                    yield sse("log", {"type": "dim", "msg": f"    {line.strip()[:130]}"})
        except Exception as e:
            yield sse("step", {"step": 1, "status": "error"})
            yield sse("error", {"msg": f"Étape Analyse: {str(e)}"})
            return

        # ── STEP 2: STRATÉGIE ────────────────────────────────────────────────
        yield sse("step", {"step": 2, "status": "active", "label": "Stratégie d'attaque"})
        try:
            raw, toks = groq_call(client, model, system, f"""Stratégie de résolution step-by-step pour ce défi CTF.

Défi: {ctx[:3500]}
Analyse: {results['analysis'][:1500]}

Fournis:
**Étapes de résolution** (numérotées, dans l'ordre):
- Étape 1: [action concrète + commande exacte]
- Étape 2: [...]
- ...

**Commandes clés** (bash/Python à copier-coller):
```bash
# commandes exactes
```

**Ce qu'on cherche à chaque étape**: validation, output attendu

**Construction du flag**: comment obtenir la valeur finale

Sois 100% concret avec du vrai code exécutable.""", max_tokens=1600)
            total_tokens += toks
            results["strategy"] = raw
            yield sse("step", {"step": 2, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Stratégie d'attaque définie"})
        except Exception as e:
            yield sse("step", {"step": 2, "status": "error"})
            yield sse("error", {"msg": f"Étape Stratégie: {str(e)}"})
            return

        # ── STEP 3: EXPLOIT ──────────────────────────────────────────────────
        yield sse("step", {"step": 3, "status": "active", "label": "Génération exploit"})
        try:
            raw, toks = groq_call(client, model, system, f"""Génère le script Python de résolution COMPLET et FONCTIONNEL pour ce défi CTF.

Défi: {ctx[:4500]}
Analyse: {results['analysis'][:1200]}
Stratégie: {results['strategy'][:1200]}

Génère UN SEUL script Python complet:
- Tous les imports nécessaires en tête
- Des commentaires explicatifs pour chaque section
- Gestion des erreurs robuste
- Variables HOST/PORT configurables si connexion réseau
- Si le flag peut être calculé STATIQUEMENT: calcule-le et affiche `print("FLAG:", flag)`
- Si besoin d'exécution dynamique: script pwntools/requests complet avec TODO clairement indiqué

Format attendu:
```python
#!/usr/bin/env python3
# CTF Solution - [nom du défi]
# Catégorie: {category}

[imports]

[code complet]

if __name__ == "__main__":
    main()
```

Le script doit être directement exécutable sans modification (sauf HOST/PORT si remote).""", max_tokens=3000)
            total_tokens += toks
            results["exploit"] = raw
            yield sse("step", {"step": 3, "status": "done"})
            yield sse("log", {"type": "ok", "msg": "[+] Script de résolution généré"})
            flag_in_code = re.search(r'FLAG[:\s]+([A-Za-z0-9_\-]+\{[^}]{3,80}\})', results["exploit"])
            if flag_in_code:
                yield sse("log", {"type": "flag", "msg": f"[★] Flag détecté dans le code: {flag_in_code.group(1)}"})
        except Exception as e:
            yield sse("step", {"step": 3, "status": "error"})
            yield sse("error", {"msg": f"Étape Exploit: {str(e)}"})
            return

        # ── STEP 4: FLAG ─────────────────────────────────────────────────────
        yield sse("step", {"step": 4, "status": "active", "label": "Extraction flag"})
        try:
            raw, toks = groq_call(client, model, system, f"""Synthèse finale pour ce défi CTF.

Analyse: {results['analysis'][:700]}
Script généré: {results['exploit'][:1200]}

Réponds UNIQUEMENT en JSON valide:
{{
  "flag_found": true,
  "flag": "valeur_complete_du_flag_ou_null",
  "flag_format": "format attendu ex: CTF{{...}} ou MCTF{{...}}",
  "confidence": 85,
  "requires_runtime": false,
  "writeup": "Résumé de la solution en 2-3 phrases: vulnérabilité exploitée, méthode, résultat.",
  "next_steps": "Si flag non trouvé: instructions précises et concrètes pour continuer"
}}

Si le flag est calculable statiquement depuis le code, indique-le dans 'flag'.
Sinon mets null et explique dans 'next_steps'.""", max_tokens=700)
            total_tokens += toks
            try:
                results["flag_data"] = json.loads(re.search(r'\{[\s\S]*\}', raw).group())
            except:
                results["flag_data"] = {
                    "flag_found": False, "flag": None, "confidence": 0,
                    "flag_format": "CTF{...}", "requires_runtime": True,
                    "writeup": "Analyse complète. Voir le script généré.",
                    "next_steps": "Exécute le script Python généré avec les bons paramètres."
                }
            yield sse("step", {"step": 4, "status": "done"})
            fd = results["flag_data"]
            if fd.get("flag"):
                yield sse("log", {"type": "flag", "msg": f"[★] FLAG: {fd['flag']}"})
            else:
                yield sse("log", {"type": "warn", "msg": f"[!] Flag non extrait statiquement. Format: {fd.get('flag_format','CTF{{...}}')}"})
                if fd.get("next_steps"):
                    yield sse("log", {"type": "info", "msg": f"[*] {fd['next_steps']}"})
        except Exception as e:
            yield sse("step", {"step": 4, "status": "error"})
            yield sse("error", {"msg": f"Étape Flag: {str(e)}"})
            return

        # ── DONE ────────────────────────────────────────────────────────────
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
