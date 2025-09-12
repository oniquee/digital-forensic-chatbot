# Gunakan image Python 3.12 slim
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Salin semua file project ke container
COPY . .

# Install OS dependency untuk python-magic & library lain yang diperlukan
RUN apt-get update && apt-get install -y \
    libmagic1 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Buat virtual environment
RUN python -m venv --copies /opt/venv

# Aktifkan venv & install dependencies
RUN . /opt/venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

# Tambahkan venv ke PATH
ENV PATH="/opt/venv/bin:$PATH"

# Jalankan bot
CMD ["python", "bot.py"]
