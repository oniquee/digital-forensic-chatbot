import logging
import os
import time
import magic
import pandas as pd
import json
import exifread
from email import policy
from email.parser import BytesParser
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext
)
from PIL import Image, ImageChops, ImageEnhance
from stegano import lsb
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import re
from langdetect import detect  # pip install langdetect
from datetime import datetime
import numpy as np
import cv2
import pandas as pd

# Telegram Bot Token
TELEGRAM_TOKEN = "7648089371:AAGYA2t5FlowsKd4WiBf7L8TRjXjvIb0Lv4"

# Upload directory
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", 
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Spam Detection Model
def train_spam_model():
    # Enhanced training data with more examples
    data = {
        "email": [
            # English spam examples
            "Free money!!! Click here to claim your prize.",
            "Urgent: Your account has been compromised. Login now.",
            "Congratulations! You won a $1000 gift card.",
            "Earn $5000 daily from home. No experience needed!",
            "Your PayPal account needs verification. Click here.",
            
            # International spam examples (translated to English)
            "You have won a prize! Click to claim.",  # Generic
            "Account security alert - immediate action required",  # Generic
            "Limited time offer - 50% discount today only",  # Generic
            "Your package delivery failed - update your details",  # Generic
            "Investment opportunity with 200% returns",  # Generic
            
            
            # Ham examples
            "Hello, let's meet tomorrow to discuss the project",
            "Your recent order has been shipped",
            "Meeting reminder: Team sync at 2pm",
            "Please find attached the report you requested",
            "Password reset confirmation",
            
            # International ham examples
            "Invoice #12345 for your recent purchase",
            "Your appointment confirmation",
            "Monthly newsletter from our company",
            "Your subscription renewal notice",
            "Thank you for your application"
        ],
        "label": [
            "spam", "spam", "spam", "spam", "spam",
            "spam", "spam", "spam", "spam", "spam",
            "ham", "ham", "ham", "ham", "ham",
            "ham", "ham", "ham", "ham", "ham"
        ]
    }

    df = pd.DataFrame(data)
    vectorizer = CountVectorizer(stop_words='english', max_features=2000)
    X = vectorizer.fit_transform(df["email"])
    model = MultinomialNB()
    model.fit(X, df["label"])
    
    return model, vectorizer

spam_model, vectorizer = train_spam_model()

# Command handlers
async def start(update: Update, context: CallbackContext):
    await update.message.reply_text(
        "Hello! I’m your Digital Forensics Assistant🤖 \n\n"
        "I can analyze various digital evidence in multiple languages and provide results in English.\n"
        "Supported file types:\n"
        "📧 Emails (`.eml` files or raw text)\n"
        "📊 CSV/Excel files\n"
        "📝 Log files (server logs, access logs, error logs)\n"
        "🖼️ Images (JPEG/PNG metadata or basic analysis)\n\n"
        "🌍 Supported languages → Results in English.\n"
        "💡 **How to use**: Simply send me a file or text for analysis.",
    )

async def handle_text(update: Update, context: CallbackContext):
    user_text = update.message.text
    
    # Truncate for preview (300 chars max)
    text_preview = user_text[:300] + ('...' if len(user_text) > 300 else '')
    
    try:
        # 1. Spam Analysis (single calculation)
        text_features = vectorizer.transform([user_text])
        spam_prediction = spam_model.predict(text_features)[0]
        spam_confidence = spam_model.predict_proba(text_features)[0][1] * 100
        
        # 2. Suspicious Pattern Detection
        suspicious_patterns = {
            'URLs': r'(https?://\S+)',
            'IPs': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'Phones': r'(\+?\d{1,3}[-\.\s]?)?\(?\d{3}\)?[-\.\s]?\d{3}[-\.\s]?\d{4}',
            'BTC': r'(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}',
            'Emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        found_patterns = [
            name for name, regex in suspicious_patterns.items() 
            if re.search(regex, user_text, re.IGNORECASE)
        ]

        # 3. Language Detection
        try:
            lang = detect(user_text[:500])  # Limit to first 500 chars for performance
            lang_result = f"Language: {lang.upper()}"
        except Exception as e:
            logger.error(f"Language detection failed: {e}")
            lang_result = "Language: Unknown"

        # Build response
        response = [
            "🔍 *Text Analysis Results*",
            "",
            f"🛡️ *Spam Detection*: {'SPAM 🚨' if spam_prediction == 'spam' else 'Legitimate ✅'}",
            f"   - Confidence: {spam_confidence:.1f}%",
            "",
            f"🔎 *Content Preview*:",
            f"{text_preview}"
        ]

        if found_patterns:
            response.extend([
                "",
                "⚠️ *Suspicious Patterns*:",
                "\n".join(f"   - {p}" for p in found_patterns)
            ])

        response.extend([
            "",
            lang_result
        ])

        await update.message.reply_text(
            "\n".join(response),
            parse_mode="Markdown"
        )

    except Exception as e:
        logger.error(f"Text analysis error: {e}")
        await update.message.reply_text(
            "❌ Analysis failed. Please try again or send a different text.\n"
            f"Error: {str(e)[:100]}"
        )

async def handle_document(update: Update, context: CallbackContext):
    document = update.message.document
    file_id = document.file_id
    file = await context.bot.get_file(file_id)

    # File size limit (10MB)
    if document.file_size > 30 * 1024 * 1024:
        await update.message.reply_text("❌ File too large (max 30MB)")
        return

    # Save file
    file_path = os.path.join(UPLOAD_DIR, document.file_name)
    await file.download_to_drive(file_path)

    await update.message.reply_text(
        f"📥 File received: {document.file_name}\n"
        f"Analyzing... Please wait"
    )
    start_time = time.time()

    try:
        # Detect file type
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        file_ext = os.path.splitext(document.file_name)[1].lower()
        
        logger.info(f"Analyzing file: {document.file_name} (Type: {file_type}, Ext: {file_ext})")

        # Route to appropriate analyzer
        if "message/rfc822" in file_type or file_ext in ('.eml', '.msg'):
            result = analyze_email(file_path)
        elif "text/csv" in file_type or file_ext == '.csv':
            result = analyze_csv(file_path)
        elif "text/plain" in file_type or file_ext == '.log':
            result = analyze_log(file_path)
        elif "application/json" in file_type or file_ext == '.json':
            result = analyze_json(file_path)
        elif "image" in file_type or file_ext in ('.jpg', '.jpeg', '.png', '.gif'):
            result = analyze_image(file_path)
        else:
            result = f"⚠️ Unsupported file type: {file_type}"

    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        result = f"❌ Analysis failed: {str(e)}"

    elapsed_time = time.time() - start_time
    time_str = f"{elapsed_time:.2f}s" if elapsed_time < 60 else f"{elapsed_time/60:.2f}min"

    await update.message.reply_text(
        f"📄 File: {document.file_name}\n"
        f"⏱ Analysis Time: {time_str}\n\n"
        f"🔎 Analysis Results:\n\n{result}"
    )

def analyze_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        results = []
        
        # Extract headers
        results.append("✉️ EMAIL HEADERS:")
        for header in ['From', 'To', 'Subject', 'Date']:
            if header in msg:
                results.append(f"- {header}: {msg[header]}")
        
        # Get email body text
        email_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    email_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            email_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        # Spam analysis
        if email_text:
            email_features = vectorizer.transform([email_text])
            prediction = spam_model.predict(email_features)[0]
            confidence = spam_model.predict_proba(email_features)[0][1] * 100
            
            results.append("\n🛡️ SPAM ANALYSIS:")
            results.append(f"- Result: {'SPAM 🚨' if prediction == 'spam' else 'NOT SPAM ✅'}")
            results.append(f"- Confidence: {confidence:.1f}%")
            
            if prediction == "spam":
                # Extract suspicious phrases
                suspicious_phrases = [
                    "free", "win", "prize", "urgent", "click", 
                    "account", "verify", "password", "limited", "offer"
                ]
                found_phrases = [phrase for phrase in suspicious_phrases if phrase in email_text.lower()]
                if found_phrases:
                    results.append(f"- Suspicious phrases: {', '.join(found_phrases[:5])}{'...' if len(found_phrases)>5 else ''}")
        
        # Check for attachments
        if msg.is_multipart():
            attachments = [part.get_filename() for part in msg.walk() if part.get_filename()]
            if attachments:
                results.append("\n📎 ATTACHMENTS:")
                results.extend(f"- {name}" for name in attachments[:3])
                if len(attachments) > 3:
                    results.append(f"- ...and {len(attachments)-3} more")
        
        return "\n".join(results)
    
    except Exception as e:
        return f"❌ Email analysis failed: {str(e)}"

def analyze_csv(file_path):
    try:
        # Try multiple encodings
        encodings = ['utf-8', 'latin-1', 'ISO-8859-1', 'windows-1252']
        df = None
        
        for encoding in encodings:
            try:
                df = pd.read_csv(file_path, encoding=encoding)
                break
            except:
                continue
        
        if df is None:
            return "❌ Failed to read CSV with multiple encodings"
        
        results = ["📊 CSV FILE ANALYSIS:"]
        
        # Basic info
        results.append(f"- Rows: {len(df):,}")
        results.append(f"- Columns: {len(df.columns)}")
        results.append(f"- Sample columns: {', '.join(df.columns[:5])}{'...' if len(df.columns)>5 else ''}")
        
        # Look for text columns to analyze
        text_columns = [col for col in df.columns 
                       if any(key in col.lower() for key in ['text', 'message', 'body', 'content', 'comment'])]
        
        if not text_columns:
            return "\n".join(results) + "\n\nℹ️ No text columns found for content analysis"
        
        # Analyze each text column
        for col in text_columns[:3]:  # Limit to 3 columns to avoid long processing
            try:
                sample_texts = df[col].dropna().astype(str).head(50).tolist()
                if not sample_texts:
                    continue
                    
                features = vectorizer.transform(sample_texts)
                predictions = spam_model.predict(features)
                
                spam_count = sum(p == "spam" for p in predictions)
                spam_percent = spam_count / len(predictions) * 100
                
                results.append(f"\n📝 Column '{col}' Analysis:")
                results.append(f"- Spam rate: {spam_percent:.1f}% ({spam_count}/{len(predictions)})")
                
                # Show example spam messages
                if spam_count > 0:
                    example_spam = next(
                    (t for t, p in zip(sample_texts, predictions) if p == "spam" and len(t) > 10), 
                    None
                    )
                    if example_spam:
                        results.append(f"- Example spam: {example_spam[:100]}{'...' if len(example_spam)>100 else ''}")
            except Exception as e:
                results.append(f"\n⚠️ Failed to analyze column '{col}': {str(e)}")
        
        return "\n".join(results)
    
    except Exception as e:
        return f"❌ CSV analysis failed: {str(e)}"

def analyze_log(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
            
        results = ["📜 LOG FILE ANALYSIS:"]
        error_lines = []
        warning_lines = []
        
        # Analyze first 200 lines
        for line in lines[:200]:
            line = line.strip()
            if not line:
                continue
                
            # Detect issues (case insensitive)
            line_lower = line.lower()
            if "error" in line_lower:
                error_lines.append(line)
            elif "warn" in line_lower or "warning" in line_lower:
                warning_lines.append(line)
            elif "fail" in line_lower or "exception" in line_lower:
                error_lines.append(line)
        
        # Add summary
        results.append(f"- Total lines scanned: {min(len(lines), 200)}")
        results.append(f"- Errors found: {len(error_lines)}")
        results.append(f"- Warnings found: {len(warning_lines)}")
        
        # Add examples if found
        if error_lines:
            results.append("\n🔴 ERROR EXAMPLES:")
            results.extend(f"- {line[:120]}{'...' if len(line)>120 else ''}" 
                         for line in error_lines[:3])
            if len(error_lines) > 3:
                results.append(f"- ...and {len(error_lines)-3} more errors")
        
        if warning_lines:
            results.append("\n🟡 WARNING EXAMPLES:")
            results.extend(f"- {line[:120]}{'...' if len(line)>120 else ''}" 
                         for line in warning_lines[:3])
            if len(warning_lines) > 3:
                results.append(f"- ...and {len(warning_lines)-3} more warnings")
        
        if not error_lines and not warning_lines:
            results.append("\n✅ No errors or warnings found in scanned lines")
        
        return "\n".join(results)
    
    except Exception as e:
        return f"❌ Log analysis failed: {str(e)}"

def analyze_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        results = ["📑 JSON FILE ANALYSIS:"]
        issues = []
        
        def scan_json(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    if isinstance(value, (dict, list)):
                        scan_json(value, new_path)
                    else:
                        # Check for suspicious fields
                        key_lower = str(key).lower()
                        if any(s in key_lower for s in ['error', 'fail', 'warn', 'exception', 'critical']):
                            issues.append((new_path, str(value)))
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    scan_json(item, f"{path}[{i}]")
        
        scan_json(data)
        
        # Add summary
        results.append(f"- Found {len(issues)} potential issues")
        
        if issues:
            results.append("\n⚠️ POTENTIAL ISSUES:")
            for path, value in issues[:5]:  # Limit to 5 examples
                results.append(f"- {path}: {value[:100]}{'...' if len(value)>100 else ''}")
            if len(issues) > 5:
                results.append(f"- ...and {len(issues)-5} more")
        else:
            results.append("\n✅ No suspicious fields found")
        
        return "\n".join(results)
    
    except Exception as e:
        return f"❌ JSON analysis failed: {str(e)}"

# def analyze_image(file_path):
#     results = [" IMAGE ANALYSIS:"]
    
#     # EXIF Metadata
#     try:
#         with open(file_path, "rb") as file:
#             tags = exifread.process_file(file, details=False)
        
#         if tags:
#             results.append("\n EXIF METADATA:")
#             for tag in ['Image Make', 'Image Model', 'EXIF DateTimeOriginal', 
#                        'GPS GPSLatitude', 'GPS GPSLongitude']:
#                 if tag in tags:
#                     results.append(f"- {tag.split()[-1]}: {tags[tag]}")
#     except Exception as e:
#         results.append(f"\n Failed to read EXIF data: {str(e)}")
    
#     # Steganography detection
#     try:
#         if file_path.lower().endswith(('.png', '.bmp')):
#             hidden_msg = lsb.reveal(file_path)
#             if hidden_msg:
#                 results.append("\n STEGANOGRAPHY DETECTED:")
#                 results.append(f"- Hidden message: {hidden_msg[:100]}{'...' if len(hidden_msg)>100 else ''}")
#             else:
#                 results.append("\n No steganography detected (LSB method)")
#     except Exception:
#         results.append("\n Could not check for steganography (LSB)")
    
#     # Image manipulation detection (ELA)
#     try:
#         if file_path.lower().endswith(('.jpg', '.jpeg')):
#             ela_result = detect_ela(file_path)
#             if ela_result:
#                 results.append("\n POSSIBLE IMAGE MANIPULATION DETECTED")
#                 results.append("- Error Level Analysis shows high inconsistency")
#             else:
#                 results.append("\n No signs of manipulation detected (ELA)")
#     except Exception as e:
#         results.append(f"\n Failed to perform ELA analysis: {str(e)}")
    
#     return "\n".join(results)

# def detect_ela(image_path, threshold=50):
#     try:
#         original = Image.open(image_path).convert("RGB")
#         temp_path = image_path + "_temp.jpg"
#         original.save(temp_path, "JPEG", quality=90)
#         compressed = Image.open(temp_path)
        
#         ela_image = ImageChops.difference(original, compressed)
#         extrema = ela_image.getextrema()
#         max_diff = max([ex[1] for ex in extrema])
        
#         os.remove(temp_path)
#         return max_diff > threshold
#     except:
#         return False
def analyze_image(file_path):
    """Comprehensive image forensic analysis with enhanced detection methods"""
    results = ["🖼️ IMAGE FORENSIC ANALYSIS"]
    
    # 1. Enhanced Metadata Analysis
    try:
        metadata = extract_metadata(file_path)
        if metadata:
            results.append("\nMETADATA ANALYSIS")
            results.extend(f"- {k}: {v}" for k,v in metadata.items())
        else:
            results.append("\n⚠️ No metadata found or metadata stripped")
    except Exception as e:
        results.append(f"\n❌ Metadata analysis failed: {str(e)}")
    
    # 2. Advanced Steganography Detection
    stego_results = detect_steganography(file_path)
    results.append("\nSTEGANOGRAPHY ANALYSIS")
    results.extend(stego_results)
    
    # 3. Comprehensive Manipulation Detection
    manip_results = detect_manipulation(file_path)
    results.append("\nMANIPULATION ANALYSIS")
    results.extend(manip_results)
    
    # 4. File Integrity Checks
    results.append("\nFILE INTEGRITY")
    results.append(f"- File type: {get_file_type(file_path)}")
    results.append(f"- File size: {os.path.getsize(file_path)/1024:.2f} KB")
    
    return "\n".join(results)

def extract_metadata(file_path):
    """Enhanced metadata extraction with more forensic details"""
    metadata = {}
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            
        # Standard metadata
        standard_tags = {
            'Image Make': 'Camera Make',
            'Image Model': 'Camera Model',
            'EXIF DateTimeOriginal': 'Creation Date',
            'EXIF ExposureTime': 'Exposure Time',
            'EXIF FNumber': 'Aperture',
            'EXIF ISOSpeedRatings': 'ISO',
            'GPS GPSLatitude': 'Latitude',
            'GPS GPSLongitude': 'Longitude'
        }
        
        for tag, name in standard_tags.items():
            if tag in tags:
                metadata[name] = str(tags[tag])
                
        # Check for metadata anomalies
        if 'Creation Date' in metadata:
            try:
                from dateutil import parser
                create_date = parser.parse(metadata['Creation Date'])
                modify_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                if abs((modify_date - create_date).total_seconds()) > 3600:
                    metadata['⚠️ Warning'] = 'Creation/modification time mismatch'
            except:
                pass
                
    except Exception as e:
        metadata['Error'] = str(e)
        
    return metadata

def analyze_image(file_path):
    """Comprehensive image forensic analysis with all dependencies resolved"""
    results = ["🖼️ IMAGE FORENSIC ANALYSIS"]
    
    # 1. Enhanced Metadata Analysis
    try:
        metadata = extract_metadata(file_path)
        if metadata:
            results.append("\nMETADATA ANALYSIS")
            results.extend(f"- {k}: {v}" for k,v in metadata.items())
        else:
            results.append("\n⚠️ No metadata found or metadata stripped")
    except Exception as e:
        results.append(f"\n❌ Metadata analysis failed: {str(e)}")
    
    # 2. Advanced Steganography Detection
    stego_results = detect_steganography(file_path)
    results.append("\nSTEGANOGRAPHY ANALYSIS")
    results.extend(stego_results)
    
    # 3. Comprehensive Manipulation Detection
    manip_results = detect_manipulation(file_path)
    results.append("\nMANIPULATION ANALYSIS")
    results.extend(manip_results)
    
    # 4. File Integrity Checks
    results.append("\nFILE INTEGRITY")
    results.append(f"- File type: {get_file_type(file_path)}")
    results.append(f"- File size: {os.path.getsize(file_path)/1024:.2f} KB")
    
    return "\n".join(results)

def extract_metadata(file_path):
    """Enhanced metadata extraction"""
    metadata = {}
    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            
        standard_tags = {
            'Image Make': 'Camera Make',
            'Image Model': 'Camera Model',
            'EXIF DateTimeOriginal': 'Creation Date',
            'EXIF ExposureTime': 'Exposure Time',
            'EXIF FNumber': 'Aperture',
            'EXIF ISOSpeedRatings': 'ISO',
            'GPS GPSLatitude': 'Latitude',
            'GPS GPSLongitude': 'Longitude'
        }
        
        for tag, name in standard_tags.items():
            if tag in tags:
                metadata[name] = str(tags[tag])
                
        # Check for metadata anomalies
        if 'Creation Date' in metadata:
            try:
                create_date = datetime.strptime(str(metadata['Creation Date']), '%Y:%m:%d %H:%M:%S')
                modify_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                if abs((modify_date - create_date).total_seconds()) > 3600:
                    metadata['⚠️ Warning'] = 'Creation/modification time mismatch'
            except:
                pass
                
    except Exception as e:
        metadata['Error'] = str(e)
        
    return metadata

def detect_steganography(file_path):
    """Multi-method steganography detection"""
    results = []
    
    # LSB Steganography
    try:
        if file_path.lower().endswith(('.png', '.bmp')):
            hidden = lsb.reveal(file_path)
            if hidden:
                results.append(f"- LSB: Hidden message found ({len(hidden)} chars)")
                results.append(f"  Preview: {hidden[:100]}{'...' if len(hidden)>100 else ''}")
            else:
                results.append("- LSB: No hidden data detected")
    except Exception as e:
        results.append(f"- ❌ LSB analysis failed: {str(e)}")
    
    # DCT Coefficient Analysis (JPEG)
    try:
        if file_path.lower().endswith(('.jpg', '.jpeg')):
            dct_anomalies = analyze_dct_coefficients(file_path)
            if dct_anomalies > 0.15:
                results.append(f"- DCT: Suspicious anomalies detected (score: {dct_anomalies:.2f})")
            else:
                results.append("- DCT: No significant anomalies")
    except Exception as e:
        results.append(f"- ❌ DCT analysis failed: {str(e)}")
    
    return results

def analyze_dct_coefficients(image_path):
    """Analyze JPEG DCT coefficients for steganography"""
    try:
        # Read image and convert to grayscale
        img = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return 0
            
        # Calculate DCT
        dct = cv2.dct(np.float32(img)/255.0)
        
        # Analyze high-frequency components
        h, w = dct.shape
        # Look at the upper-left 8x8 corner where most data hides
        suspicious_blocks = 0
        block_size = 8
        for y in range(0, h//block_size):
            for x in range(0, w//block_size):
                block = dct[y*block_size:(y+1)*block_size, x*block_size:(x+1)*block_size]
                # Count non-zero high-frequency coefficients
                if np.count_nonzero(block[4:,4:]) > 10:
                    suspicious_blocks += 1
        
        return suspicious_blocks / (h//block_size * w//block_size)
    except:
        return 0

def detect_manipulation(file_path):
    """Comprehensive manipulation detection"""
    results = []
    
    # Error Level Analysis
    try:
        ela_score = perform_ela(file_path)
        if ela_score > 0.4:
            results.append(f"- ELA: High manipulation probability (score: {ela_score:.2f})")
        elif ela_score > 0.2:
            results.append(f"- ELA: Possible manipulation (score: {ela_score:.2f})")
        else:
            results.append("- ELA: No signs of manipulation")
    except Exception as e:
        results.append(f"- ❌ ELA failed: {str(e)}")
    
    # Clone Detection
    try:
        cloned_regions = detect_cloned_regions(file_path)
        if cloned_regions > 0:
            results.append(f"- Clone: {cloned_regions} copied regions detected")
        else:
            results.append("- Clone: No copy-move artifacts found")
    except Exception as e:
        results.append(f"- ❌ Clone detection failed: {str(e)}")
    
    return results

def detect_cloned_regions(image_path, threshold=0.8):
    """Basic copy-move forgery detection"""
    try:
        img = cv2.imread(image_path)
        if img is None:
            return 0
            
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        sift = cv2.SIFT_create()
        kp, des = sift.detectAndCompute(gray, None)
        
        if des is None or len(des) < 2:
            return 0
            
        # FLANN parameters
        FLANN_INDEX_KDTREE = 1
        index_params = dict(algorithm=FLANN_INDEX_KDTREE, trees=5)
        search_params = dict(checks=50)
        
        flann = cv2.FlannBasedMatcher(index_params, search_params)
        matches = flann.knnMatch(des, des, k=2)
        
        # Filter matches
        good = []
        for m,n in matches:
            if m.distance < threshold * n.distance and m.queryIdx != m.trainIdx:
                good.append(m)
                
        return len(good)
    except:
        return 0

def perform_ela(image_path, quality=90):
    """Enhanced Error Level Analysis"""
    try:
        original = Image.open(image_path).convert('RGB')
        temp_path = f"{image_path}_temp.jpg"
        original.save(temp_path, 'JPEG', quality=quality)
        compressed = Image.open(temp_path)
        
        diff = ImageChops.difference(original, compressed)
        extrema = diff.getextrema()
        max_diff = max(ex[1] for ex in extrema)
        ela_score = min(max_diff / 255, 1.0)
        
        os.remove(temp_path)
        return ela_score
    except Exception:
        return -1

def get_file_type(file_path):
    """Get precise file type"""
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(file_path)
    except:
        return "Unknown"

def main():
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    
    # Run bot
    application.run_polling()

if __name__ == "__main__":
    main()