FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    binutils \
    file \
    xxd \
    binwalk \
    strace \
    ltrace \
    binutils \
    libmagic1 \
    steghide \
    foremost \
    exiftool \
    ncat \
    gdb \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD gunicorn app:app --workers 2 --threads 4 --timeout 180 --bind 0.0.0.0:$PORT
