#!/usr/bin/env bash
# CTF·NEURAL v6.0 — Script d'installation des outils système
# Usage : sudo bash setup.sh
set -e

echo "[*] Mise à jour apt..."
apt-get update -qq

echo "[*] Installation des outils système..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    binutils file xxd \
    gdb strace ltrace \
    binwalk foremost \
    libimage-exiftool-perl \
    steghide \
    tshark \
    netcat-openbsd \
    radare2 \
    7zip \
    default-jdk \
    checksec \
    ruby ruby-dev build-essential \
    python3-pip \
    libmagic1 \
    2>/dev/null || true

echo "[*] Installation de zsteg (Ruby gem)..."
gem install zsteg --no-document 2>/dev/null || echo "[!] zsteg optionnel, skip"

echo "[*] Installation des librairies Python..."
pip install --break-system-packages -r requirements.txt 2>/dev/null || \
pip install -r requirements.txt

echo "[*] Installation des librairies Python optionnelles..."
pip install --break-system-packages \
    pwntools \
    pycryptodome \
    z3-solver \
    gmpy2 \
    capstone \
    unicorn \
    pefile \
    web3 \
    angr \
    2>/dev/null || true

echo ""
echo "[+] Installation terminée !"
echo "[*] Lance le serveur avec : gunicorn app:app --bind 0.0.0.0:5000"
echo "[*] Ou en développement : python3 app.py"
