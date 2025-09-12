import logging
import os
import time
import re
import json
from datetime import datetime

import pandas as pd
import numpy as np
import magic
import exifread
from email import policy
from email.parser import BytesParser
from langdetect import detect
from PIL import Image, ImageChops
import cv2
from stegano import lsb
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext

# Load environment variables
load_dotenv()
TELEGRAM_TOKEN = os.getenv("7648089371:AAGYA2t5FlowsKd4WiBf7L8TRjXjvIb0Lv4")
DEEPSEEK_API_KEY = os.getenv("sk-e4935818cbe24a0e924c7be6d40157e5")

TELEGRAM_TOKEN = "7648089371:AAGYA2t5FlowsKd4WiBf7L8TRjXjvIb0Lv4"
DEEPSEEK_API_KEY = "sk-e4935818cbe24a0e924c7be6d40157e5"

# Upload directory
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --------- SPAM MODEL ---------
def train_spam_model():
    data = {
        "email": [
            "Free money!!! Click here to claim your prize.",
            "Urgent: Your account has been compromised. Login now.",
            "Congratulations! You won a $1000 gift card.",
            "Earn $5000 daily from home. No experience needed!",
            "Your PayPal account needs verification. Click here.",
            "You have won a prize! Click to claim.",
            "Account security alert - immediate action required",
            "Limited time offer - 50% discount today only",
            "Your package delivery failed - update your details",
            "Investment opportunity with 200% returns",
            "Hello, let's meet tomorrow to discuss the project",
            "Your recent order has been shipped",
            "Meeting reminder: Team sync at 2pm",
            "Please find attached the report you requested",
            "Password reset confirmation",
            "Invoice #12345 for your recent purchase",
            "Your appointment confirmation",
            "Monthly newsletter from our company",
            "Your subscription renewal notice",
            "Thank you for your application"
        ],
        "label": [
            "spam","spam","spam","spam","spam",
            "spam","spam","spam","spam","spam",
            "ham","ham","ham","ham","ham",
            "ham","ham","ham","ham","ham"
        ]
    }
    df = pd.DataFrame(data)
    vectorizer = CountVectorizer(stop_words='english', max_features=2000)
    X = vectorizer.fit_transform(df["email"])
    model = MultinomialNB()
    model.fit(X, df["label"])
    return model, vectorizer

spam_model, vectorizer = train_spam_model()

# --------- TELEGRAM HANDLERS ---------
async def start(update: Update, context: CallbackContext):
    await update.message.reply_text(
        "Hello! I’m your Digital Forensics Assistant🤖\n\n"
        "I can analyze digital evidence in multiple languages and provide results in English.\n"
        "Supported files:\n"
        "📧 Emails (.eml/.msg)\n"
        "📊 CSV/Excel files\n"
        "📝 Log files\n"
        "🖼️ Images (JPEG/PNG metadata & analysis)\n\n"
        "Simply send me text or files for analysis."
    )

async def handle_text(update: Update, context: CallbackContext):
    user_text = update.message.text
    text_preview = user_text[:300] + ('...' if len(user_text) > 300 else '')

    try:
        # Spam detection
        text_features = vectorizer.transform([user_text])
        prediction = spam_model.predict(text_features)[0]
        proba = spam_model.predict_proba(text_features)[0]
        spam_idx = list(spam_model.classes_).index("spam")
        spam_confidence = proba[spam_idx] * 100

        # Suspicious patterns
        suspicious_patterns = {
            'URLs': r'(https?://\S+)',
            'IPs': r'\b\d{1,3}(\.\d{1,3}){3}\b',
            'Phones': r'(\+?\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}',
            'BTC': r'(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}',
            'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        found_patterns = [name for name, regex in suspicious_patterns.items() if re.search(regex, user_text, re.IGNORECASE)]

        # Language detection
        try:
            lang = detect(user_text[:500])
            lang_result = f"Language: {lang.upper()}"
        except:
            lang_result = "Language: Unknown"

        # Build response
        response = [
            "🔍 *Text Analysis Results*",
            f"🛡️ *Spam Detection*: {'SPAM 🚨' if prediction=='spam' else 'Legitimate ✅'}",
            f"   - Confidence: {spam_confidence:.1f}%",
            "",
            f"🔎 *Content Preview*: {text_preview}"
        ]
        if found_patterns:
            response.extend(["", "⚠️ *Suspicious Patterns*"] + [f"   - {p}" for p in found_patterns])
        response.append(f"\n{lang_result}")

        await update.message.reply_text("\n".join(response), parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Text analysis error: {e}")
        await update.message.reply_text(f"❌ Analysis failed: {str(e)[:100]}")

async def handle_document(update: Update, context: CallbackContext):
    document = update.message.document
    file_id = document.file_id
    file = await context.bot.get_file(file_id)

    MAX_FILE_SIZE = 30 * 1024 * 1024
    if document.file_size > MAX_FILE_SIZE:
        await update.message.reply_text("❌ File too large (max 30MB)")
        return

    file_path = os.path.join(UPLOAD_DIR, document.file_name)
    await file.download_to_drive(file_path)

    await update.message.reply_text(f"📥 Received: {document.file_name}\nAnalyzing... Please wait")
    start_time = time.time()

    try:
        mime_type = get_file_type(file_path)
        ext = os.path.splitext(document.file_name)[1].lower()

        if "message/rfc822" in mime_type or ext in ('.eml', '.msg'):
            result = analyze_email(file_path)
        elif "text/csv" in mime_type or ext == '.csv':
            result = analyze_csv(file_path)
        elif "text/plain" in mime_type or ext == '.log':
            result = analyze_log(file_path)
        elif "application/json" in mime_type or ext == '.json':
            result = analyze_json(file_path)
        elif "image" in mime_type or ext in ('.jpg','.jpeg','.png','.bmp'):
            result = analyze_image(file_path)
        else:
            result = f"⚠️ Unsupported file type: {mime_type}"
    except Exception as e:
        logger.error(f"File analysis error: {e}")
        result = f"❌ Analysis failed: {str(e)}"

    elapsed = time.time() - start_time
    time_str = f"{elapsed:.2f}s" if elapsed < 60 else f"{elapsed/60:.2f}min"

    await update.message.reply_text(f"📄 {document.file_name}\n⏱ {time_str}\n\n{result}")

# --------- ANALYSIS FUNCTIONS (Email, CSV, Log, JSON, Image) ---------
# --- Email ---
def analyze_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        results = ["✉️ EMAIL HEADERS:"]
        for header in ['From', 'To', 'Subject', 'Date']:
            if header in msg:
                results.append(f"- {header}: {msg[header]}")

        # Body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        if body:
            features = vectorizer.transform([body])
            prediction = spam_model.predict(features)[0]
            proba = spam_model.predict_proba(features)[0]
            spam_idx = list(spam_model.classes_).index("spam")
            confidence = proba[spam_idx]*100
            results.append("\n🛡️ SPAM ANALYSIS:")
            results.append(f"- Result: {'SPAM 🚨' if prediction=='spam' else 'NOT SPAM ✅'}")
            results.append(f"- Confidence: {confidence:.1f}%")
        return "\n".join(results)
    except Exception as e:
        return f"❌ Email analysis failed: {str(e)}"

# --- CSV ---
def analyze_csv(file_path):
    try:
        encodings = ['utf-8','latin-1','ISO-8859-1','windows-1252']
        df = None
        for enc in encodings:
            try:
                df = pd.read_csv(file_path, encoding=enc)
                break
            except:
                continue
        if df is None: return "❌ Failed to read CSV"

        results = [f"📊 CSV FILE: Rows={len(df):,}, Columns={len(df.columns)}"]
        text_cols = [c for c in df.columns if any(k in c.lower() for k in ['text','body','message','content','comment'])]
        for col in text_cols[:3]:
            sample = df[col].dropna().astype(str).head(50).tolist()
            features = vectorizer.transform(sample)
            preds = spam_model.predict(features)
            spam_count = sum(p=='spam' for p in preds)
            results.append(f"- Column '{col}': Spam rate {spam_count/len(preds)*100:.1f}%")
        return "\n".join(results)
    except Exception as e:
        return f"❌ CSV analysis failed: {str(e)}"

# --- Log ---
def analyze_log(file_path):
    try:
        with open(file_path,'r',encoding='utf-8',errors='ignore') as f:
            lines = f.readlines()
        results = ["📜 LOG FILE ANALYSIS:"]
        errors = [l.strip() for l in lines[:200] if 'error' in l.lower() or 'fail' in l.lower() or 'exception' in l.lower()]
        warns  = [l.strip() for l in lines[:200] if 'warn' in l.lower() or 'warning' in l.lower()]
        results.append(f"- Total scanned: {min(len(lines),200)}, Errors: {len(errors)}, Warnings: {len(warns)}")
        return "\n".join(results)
    except Exception as e:
        return f"❌ Log analysis failed: {str(e)}"

# --- JSON ---
def analyze_json(file_path):
    try:
        with open(file_path,'r',encoding='utf-8') as f:
            data = json.load(f)
        issues = []
        def scan(obj, path=""):
            if isinstance(obj, dict):
                for k,v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    if isinstance(v,(dict,list)): scan(v,new_path)
                    else:
                        if any(x in k.lower() for x in ['error','fail','warn','exception','critical']):
                            issues.append((new_path,str(v)))
            elif isinstance(obj,list):
                for i,item in enumerate(obj):
                    scan(item,f"{path}[{i}]")
        scan(data)
        results = [f"📑 JSON: Found {len(issues)} potential issues"]
        return "\n".join(results)
    except Exception as e:
        return f"❌ JSON analysis failed: {str(e)}"

# --- IMAGE ---
def analyze_image(file_path):
    results = ["🖼️ IMAGE FORENSIC ANALYSIS"]

    # Metadata
    try:
        metadata = extract_metadata(file_path)
        results.append("METADATA:")
        results.extend(f"- {k}: {v}" for k,v in metadata.items())
    except Exception as e:
        results.append(f"❌ Metadata failed: {e}")

    # Steganography
    try:
        if file_path.lower().endswith(('.jpg','.png','.bmp')):
            hidden = lsb.reveal(file_path)
            results.append(f"LSB Steganography: {hidden[:100]+'...' if hidden else 'None'}")
    except:
        results.append("LSB analysis failed")

    # ELA
    try:
        ela_score = perform_ela(file_path)
        results.append(f"ELA average error: {ela_score:.2f}")
    except:
        results.append("ELA failed")

    return "\n".join(results)

def extract_metadata(file_path):
    meta = {}
    try:
        with open(file_path,'rb') as f:
            tags = exifread.process_file(f, details=False)
        for tag in ['Image Make','Image Model','EXIF DateTimeOriginal','GPS GPSLatitude','GPS GPSLongitude']:
            if tag in tags: meta[tag] = str(tags[tag])
    except:
        pass
    return meta

def perform_ela(file_path):
    im = Image.open(file_path).convert('RGB')
    temp = file_path + "_resave.jpg"
    im.save(temp,'JPEG',quality=90)
    im_resave = Image.open(temp)
    diff = ImageChops.difference(im, im_resave)
    extrema = diff.getextrema()
    os.remove(temp)
    score = np.mean([ex[1] for ex in extrema])
    return score

def get_file_type(file_path):
    try:
        if magic:
            m = magic.Magic(mime=True)
            return m.from_file(file_path)
    except:
        pass
    return "Unknown"

# --------- MAIN ---------
def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.run_polling()

if __name__ == "__main__":
    main()
