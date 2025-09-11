import requests

# Misal URL endpoint API DeepSeek (ganti dengan URL sebenarnya)
DEEPSEEK_API_URL = "https://api.deepseek.com/analyze"

def analisis_bukti(pesan: str) -> str:
    # Jika ada API yang sebenarnya, kirim request ke API:
    try:
        payload = {'text': pesan}
        response = requests.post(DEEPSEEK_API_URL, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Misal API mengembalikan field 'analysis'
            return data.get('analysis', 'Analisis tidak tersedia.')
        else:
            return f"Error dari DeepSeek: {response.status_code}"
    except Exception as e:
        # Jika API belum tersedia, simulasi respon
        return f"Simulasi: Analisis ditemukan indikasi anomali pada pesan '{pesan[:30]}...'"
