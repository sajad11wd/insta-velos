import os
import re
import html
import hmac
import json
import time
import sqlite3
import secrets
import mimetypes
import threading
from datetime import datetime
from io import BytesIO
from pathlib import Path
from collections import defaultdict, deque

import requests
import telebot
from telebot import types
from flask import Flask, request, render_template_string, redirect, url_for, abort, send_file, make_response

# ================= CONFIG =================
BOT_TOKEN = os.getenv("BOT_TOKEN", "PUT_BOT_TOKEN_HERE")
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "6479956975"))
BASE_URL = os.getenv("BASE_URL", "https://your-domain.example")
PORT = int(os.getenv("PORT", "8080"))
DB_PATH = os.getenv("DB_PATH", "insta_velos_store.db")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "receipts"))
LOG_FILE = Path(os.getenv("LOG_FILE", "activity.log"))
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
DEFAULT_LANGUAGE = "en"
SITE_NAME = "Insta Velos"
USE_TELEGRAM_WEBHOOK = os.getenv("USE_TELEGRAM_WEBHOOK", "0") == "1"
MAX_QTY_PER_ORDER = int(os.getenv("MAX_QTY_PER_ORDER", "10000"))
MAX_RECEIPT_MB = 8
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}

# ================= CATEGORIES =================
CATEGORIES = {
    "premium": {
        "title_en": "INSTAGRAM ACC",
        "title_ar": "الباقة الاحترافية",
        "desc_en": "Premium Quality - Best for claiming\nCreated in 2025\nFull Access: User, Pass, MID, Android Session, Cookies.",
        "desc_ar": "باقة رقمية احترافية للاستخدامات المتقدمة.\nآلية تسليم منظمة ومراجعة سريعة.\nتتضمن ملف TXT كامل بعد الموافقة.",
        "price": 0.025,
        "file": Path("stock_premium.txt"),
    },
    "mid": {
        "title_en": "INSTAGRAM ACC #2",
        "title_ar": "الباقة المتوسطة",
        "desc_en": "Medium Quality - Balanced use\nCreated around 1 month ago\nFull Access: User, Pass, MID, Android Session, Cookies.",
        "desc_ar": "باقة رقمية متوازنة للاستخدام المعتاد.\nتسعير محسّن مع آلية تسليم مستقرة.\nتتضمن ملف TXT كامل بعد الموافقة.",
        "price": 0.018,
        "file": Path("stock_mid.txt"),
    },
    "basic": {
        "title_en": "INSTAGRAM ACC #3",
        "title_ar": "الباقة الأساسية",
        "desc_en": "Basic Quality (Nue) - For testing/light use\nNew accounts\nFull Access: User, Pass, MID, Android Session, Cookies.",
        "desc_ar": "باقة رقمية أساسية للاستخدامات الخفيفة.\nشراء بسيط وهيكل تكلفة مرن.\nتتضمن ملف TXT كامل بعد الموافقة.",
        "price": 0.012,
        "file": Path("stock_basic.txt"),
    },
}

PAYMENTS = {
    "zain": {"name_en": "ZainCash", "name_ar": "زين كاش", "mult": 1.56, "details": "+9647722221671"},
    "master": {"name_en": "MasterCard", "name_ar": "ماستر كارد", "mult": 1.56, "details": "7869330741"},
    "ltc": {"name_en": "Litecoin", "name_ar": "لايتكوين", "mult": 1.00, "details": "LRS4aNhSduRqF1vY8wVcTvQFnvKLNu4MmF"},
    "usdt_bep20": {"name_en": "USDT BEP20", "name_ar": "USDT BEP20", "mult": 1.00, "details": "0x8fb3f981bdea648fdc56150493866d9330690806"},
    "usdt_trc20": {"name_en": "USDT TRC20", "name_ar": "USDT TRC20", "mult": 1.00, "details": "TUc8BesrPhCRGrwwMgmCa5cB7mhsb9Fw2S"},
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_RECEIPT_MB * 1024 * 1024
app.config["SECRET_KEY"] = SECRET_KEY
bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None)

# ================= BASIC SECURITY =================
REQUEST_BUCKETS = defaultdict(deque)
DRAFT_ORDERS = {}
BOT_STATE = {}
TEMP_STOCK_FILE = Path("tmp_stock_upload.txt")


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def rate_limit(key: str, limit: int, window_sec: int) -> bool:
    now = time.time()
    dq = REQUEST_BUCKETS[key]
    while dq and now - dq[0] > window_sec:
        dq.popleft()
    if len(dq) >= limit:
        return False
    dq.append(now)
    return True


def sign_value(value: str) -> str:
    sig = hmac.new(SECRET_KEY.encode("utf-8"), value.encode("utf-8"), "sha256").hexdigest()
    return f"{value}.{sig}"


def verify_signed_value(signed: str) -> bool:
    if "." not in signed:
        return False
    value, sig = signed.rsplit(".", 1)
    expected = hmac.new(SECRET_KEY.encode("utf-8"), value.encode("utf-8"), "sha256").hexdigest()
    return hmac.compare_digest(sig, expected)


def safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", name)


def validate_email(value: str) -> bool:
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value))


def validate_telegram_username(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_]{4,32}", value))


def allowed_receipt(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com data:;"
    )
    return response

# ================= DB =================
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_connect()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            telegram TEXT NOT NULL,
            category TEXT NOT NULL,
            qty INTEGER NOT NULL,
            payment TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL,
            blob TEXT DEFAULT '',
            token TEXT NOT NULL,
            receipt_path TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    for key, item in CATEGORIES.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)",
            (f"price_{key}", str(item["price"])),
        )
    conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('min_order', '1')")
    conn.commit()
    conn.close()

init_db()
def get_price(category_key: str) -> float:
    conn = db_connect()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (f"price_{category_key}",)).fetchone()
    conn.close()
    return float(row["value"]) if row else float(CATEGORIES[category_key]["price"])


def set_price(category_key: str, value: float):
    conn = db_connect()
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (f"price_{category_key}", str(value)),
    )
    conn.commit()
    conn.close()
    log_action("price_update", f"{category_key} => {value}")


def get_min_order() -> int:
    conn = db_connect()
    row = conn.execute("SELECT value FROM settings WHERE key='min_order'").fetchone()
    conn.close()
    return int(row["value"]) if row else 1


def set_min_order(value: int):
    conn = db_connect()
    conn.execute(
        "INSERT INTO settings(key, value) VALUES('min_order', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(value),),
    )
    conn.commit()
    conn.close()
    log_action("min_order_update", str(value))


def log_action(action: str, details: str):
    timestamp = datetime.utcnow().isoformat()
    conn = db_connect()
    conn.execute(
        "INSERT INTO logs(action, details, created_at) VALUES(?, ?, ?)",
        (action, details, timestamp),
    )
    conn.commit()
    conn.close()
    old = LOG_FILE.read_text(encoding="utf-8") if LOG_FILE.exists() else ""
    LOG_FILE.write_text(old + f"[{timestamp}] {action}: {details}\n", encoding="utf-8")


def recent_logs(limit: int = 20):
    conn = db_connect()
    rows = conn.execute("SELECT action, details, created_at FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows

# ================= STOCK =================
def ensure_stock_files():
    for item in CATEGORIES.values():
        item["file"].touch(exist_ok=True)


def stock_count(category_key: str) -> int:
    fp = CATEGORIES[category_key]["file"]
    if not fp.exists():
        return 0
    return len([l for l in fp.read_text(encoding="utf-8").splitlines() if l.strip()])


def add_stock(category_key: str, content: str) -> int:
    lines = [x.strip() for x in content.splitlines() if x.strip()]
    if not lines:
        return 0
    fp = CATEGORIES[category_key]["file"]
    with fp.open("a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    log_action("stock_add", f"{category_key}: +{len(lines)}")
    return len(lines)


def clear_all_stock():
    for item in CATEGORIES.values():
        item["file"].write_text("", encoding="utf-8")
    log_action("stock_clear", "all categories cleared")


def take_stock(category_key: str, amount: int) -> list[str]:
    fp = CATEGORIES[category_key]["file"]
    lines = [x.strip() for x in fp.read_text(encoding="utf-8").splitlines() if x.strip()]
    picked = lines[:amount]
    remain = lines[amount:]
    fp.write_text(("\n".join(remain) + "\n") if remain else "", encoding="utf-8")
    return picked

# ================= HELPERS =================
def calc_total(category_key: str, qty: int, payment_key: str) -> float:
    return round(get_price(category_key) * qty * PAYMENTS[payment_key]["mult"], 6)


def is_admin(chat_id: int) -> bool:
    return chat_id == ADMIN_CHAT_ID


def admin_keyboard():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True)
    kb.row("Add Stock", "Clear All Stock")
    kb.row("Completed Orders", "Recent Activity")
    kb.row("Change Prices", "Set Min Order")
    return kb


def category_inline(prefix: str):
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("Premium", callback_data=f"{prefix}:premium"),
        types.InlineKeyboardButton("Medium", callback_data=f"{prefix}:mid"),
        types.InlineKeyboardButton("Basic", callback_data=f"{prefix}:basic"),
    )
    return kb

# ================= WEBSITE =================
INDEX_HTML = """
<!doctype html>
<html lang="{{ lang }}" dir="{{ 'rtl' if lang == 'ar' else 'ltr' }}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ site_name }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#040814;--bg2:#0a1020;--card:rgba(11,18,32,.78);--card2:rgba(15,23,42,.82);--acc:#5ee7ff;--acc2:#8b5cf6;--acc3:#38bdf8;--txt:#f8fafc;--muted:#94a3b8;--line:rgba(255,255,255,.08);--shadow:0 30px 80px rgba(0,0,0,.35)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--txt);background:
radial-gradient(circle at 15% 20%, rgba(94,231,255,.13), transparent 26%),
radial-gradient(circle at 80% 15%, rgba(139,92,246,.18), transparent 28%),
radial-gradient(circle at 70% 75%, rgba(56,189,248,.12), transparent 24%),
linear-gradient(135deg,#020617 0%,#081021 45%,#060b16 100%);
min-height:100vh;overflow-x:hidden}
body:before{content:'';position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);background-size:34px 34px;mask-image:radial-gradient(circle at center, black, transparent 78%);opacity:.18}
.wrap{max-width:1340px;margin:auto;padding:30px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:28px}
.brand{display:flex;align-items:center;gap:14px}.brand-mark{width:48px;height:48px;border-radius:16px;background:linear-gradient(135deg,var(--acc),var(--acc2));box-shadow:0 10px 30px rgba(94,231,255,.25)}.brand-title{font-size:34px;font-weight:900;letter-spacing:.3px}.brand-title span{color:var(--acc)}
.lang{display:flex;gap:10px}.lang a{text-decoration:none;color:var(--txt);padding:10px 14px;border:1px solid var(--line);border-radius:14px;background:rgba(255,255,255,.04);transition:.25s}.lang a:hover,.lang a.active{transform:translateY(-2px);background:linear-gradient(90deg,var(--acc3),var(--acc2));color:#04101d;border-color:transparent;font-weight:800}
.hero{display:grid;grid-template-columns:1.15fr .85fr;gap:22px;align-items:stretch}
.panel{background:var(--card);border:1px solid var(--line);border-radius:30px;backdrop-filter:blur(20px);box-shadow:var(--shadow)}
.hero-main{padding:46px 44px;position:relative;overflow:hidden}
.hero-main:after{content:'';position:absolute;inset:auto -80px -80px auto;width:220px;height:220px;border-radius:999px;background:radial-gradient(circle, rgba(94,231,255,.20), transparent 65%)}
.badge{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;background:rgba(94,231,255,.10);border:1px solid rgba(94,231,255,.16);color:var(--acc);font-size:13px;font-weight:700;letter-spacing:.04em}
.title{font-size:68px;line-height:1.02;margin:18px 0 16px;font-weight:900;max-width:840px}
.title .shine{background:linear-gradient(90deg,#ffffff 0%,#9be7ff 45%,#b499ff 100%);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{font-size:18px;line-height:1.95;color:var(--muted);max-width:790px}
.hero-actions{display:flex;gap:14px;flex-wrap:wrap;margin-top:28px}.hero-btn{appearance:none;border:none;border-radius:16px;padding:15px 20px;font-weight:800;cursor:pointer;text-decoration:none}.hero-btn.primary{background:linear-gradient(90deg,var(--acc3),var(--acc2));color:#06101b;box-shadow:0 16px 34px rgba(56,189,248,.18)}.hero-btn.secondary{background:rgba(255,255,255,.04);color:var(--txt);border:1px solid var(--line)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:26px}.stat{padding:18px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.05);border-radius:20px}.stat .n{font-size:32px;font-weight:900}.stat .l{margin-top:6px;color:var(--muted);font-size:14px}
.hero-side{padding:28px;display:grid;gap:14px}.feature{padding:20px;border-radius:22px;background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.03));border:1px solid rgba(255,255,255,.05)}.feature h4{margin:0 0 8px;font-size:18px}.feature p{margin:0;color:var(--muted);line-height:1.8}.orb{height:180px;border-radius:26px;background:radial-gradient(circle at 30% 30%, rgba(94,231,255,.30), transparent 35%),radial-gradient(circle at 70% 40%, rgba(139,92,246,.24), transparent 30%),linear-gradient(135deg, rgba(255,255,255,.03), rgba(255,255,255,.01));border:1px solid rgba(255,255,255,.05)}
.section-head{display:flex;justify-content:space-between;align-items:end;gap:12px;margin:38px 0 16px}.section-head h2{margin:0;font-size:32px}.section-head p{margin:6px 0 0;color:var(--muted)}
.catalog{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card{position:relative;padding:24px;border-radius:28px;background:var(--card2);border:1px solid var(--line);box-shadow:var(--shadow);overflow:hidden;transition:.28s ease}.card:hover{transform:translateY(-10px);border-color:rgba(94,231,255,.24);box-shadow:0 34px 80px rgba(0,0,0,.42)}.card:before{content:'';position:absolute;inset:auto -80px -80px auto;width:200px;height:200px;background:radial-gradient(circle, rgba(94,231,255,.15), transparent 60%)}
.kicker{display:inline-flex;padding:8px 12px;border-radius:999px;background:rgba(255,255,255,.05);font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--acc)}.product-title{font-size:28px;font-weight:800;margin:16px 0 8px}.price{font-size:38px;font-weight:900;margin:8px 0 14px}.desc{white-space:pre-wrap;line-height:1.85;color:var(--muted);min-height:126px}.stock-line{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:16px;padding:14px;border-radius:16px;background:rgba(255,255,255,.04)}.stock-pill{display:inline-flex;align-items:center;padding:8px 12px;border-radius:999px;background:rgba(94,231,255,.10);color:var(--acc);font-weight:700;font-size:13px}.buy{width:100%;margin-top:18px;appearance:none;border:none;border-radius:16px;padding:15px 18px;background:linear-gradient(90deg,var(--acc3),var(--acc2));color:#06101b;font-weight:900;cursor:pointer;box-shadow:0 12px 28px rgba(56,189,248,.18)}
.notice{margin-top:18px;padding:16px 18px;border-radius:18px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.05);color:var(--muted)}
.floating-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:20px}.floating-strip .item{padding:16px;border-radius:18px;background:rgba(255,255,255,.04);text-align:center;border:1px solid rgba(255,255,255,.04)}
.muted{color:var(--muted)}
.modal{display:none;position:fixed;inset:0;background:rgba(2,6,23,.82);z-index:50;align-items:center;justify-content:center;padding:20px}.modal.show{display:flex}.box{width:min(900px,100%);padding:28px;background:rgba(6,10,20,.95);border:1px solid var(--line);border-radius:28px;box-shadow:var(--shadow)}
.checkout-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}.checkout-head h2{margin:0;font-size:30px}.close-btn{appearance:none;border:none;border-radius:14px;padding:12px 16px;background:rgba(255,255,255,.06);color:var(--txt);font-weight:700;cursor:pointer}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}.field{display:flex;flex-direction:column;gap:8px}.field label{font-size:14px;color:var(--muted);font-weight:600}input,select,textarea{width:100%;padding:15px 16px;border-radius:16px;border:1px solid var(--line);background:#0c1426;color:var(--txt);outline:none;transition:.2s}input:focus,select:focus,textarea:focus{border-color:rgba(94,231,255,.26);box-shadow:0 0 0 4px rgba(94,231,255,.08)}.full{grid-column:1/-1}
.preview{padding:16px;border-radius:18px;background:rgba(255,255,255,.05);font-weight:800}.payment-box{padding:14px 16px;border-radius:16px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.04)}.warning{margin-top:8px;color:#fbbf24;font-weight:800}.cta{appearance:none;border:none;border-radius:16px;padding:16px 18px;background:linear-gradient(90deg,var(--acc3),var(--acc2));color:#06101b;font-weight:900;cursor:pointer;box-shadow:0 16px 34px rgba(56,189,248,.18)}
.footer{text-align:center;color:var(--muted);padding:34px 0 10px}
@media(max-width:1080px){.hero,.catalog,.floating-strip,.stats,.grid{grid-template-columns:1fr}.title{font-size:46px}.hero-main,.hero-side,.box{padding:24px}}
</style>
<script>
const prices = {{ prices_json|safe }};
const payments = {{ payments_json|safe }};
const stocks = {{ stock_json|safe }};
const minOrder = {{ min_order }};
const copy = {{ copy_json|safe }};
function openBuy(category){
  document.getElementById('category').value = category;
  document.getElementById('buyModal').classList.add('show');
  document.body.style.overflow = 'hidden';
  updatePrice();
}
function closeBuy(){
  document.getElementById('buyModal').classList.remove('show');
  document.body.style.overflow = 'auto';
}
function updatePrice(){
  const c = document.getElementById('category').value;
  const q = parseInt(document.getElementById('quantity').value || '0');
  const p = document.getElementById('payment_method').value;
  const total = (prices[c] || 0) * q * ((payments[p] && payments[p].mult) ? payments[p].mult : 1);
  document.getElementById('pricePreview').innerText = q > 0 ? `${copy.total}: ${total.toFixed(3)}` : `${copy.total}: 0`;
  document.getElementById('paymentDetails').innerText = payments[p] ? `${copy.paymentInfo}: ${payments[p].details}` : '';
  let warn = '';
  if (q && q < minOrder) warn = `${copy.minOrder}: ${minOrder}`;
  else if (q && q > stocks[c]) warn = copy.notEnough;
  document.getElementById('orderWarning').innerText = warn;
}
</script>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="brand-mark"></div>
      <div class="brand-title">{{ site_name }} <span>Store</span></div>
    </div>
    <div class="lang">
      <a href="/?lang=en" class="{{ 'active' if lang=='en' else '' }}">English</a>
      <a href="/?lang=ar" class="{{ 'active' if lang=='ar' else '' }}">العربية</a>
    </div>
  </div>

  <section class="hero">
    <div class="panel hero-main">
      <div class="badge">{{ copy.badge }}</div>
      <div class="title"><span class="shine">{{ copy.heroTitle }}</span></div>
      <div class="sub">{{ copy.heroText }}</div>
      <div class="hero-actions">
        <a href="#catalog" class="hero-btn primary">{{ copy.buyNow }}</a>
        <a href="#overview" class="hero-btn secondary">{{ copy.learnMore }}</a>
      </div>
      <div class="stats">
        <div class="stat"><div class="n">{{ stock_counts['premium'] }}</div><div class="l">{{ copy.premiumLabel }}</div></div>
        <div class="stat"><div class="n">{{ stock_counts['mid'] }}</div><div class="l">{{ copy.midLabel }}</div></div>
        <div class="stat"><div class="n">{{ stock_counts['basic'] }}</div><div class="l">{{ copy.basicLabel }}</div></div>
      </div>
      <div class="notice">{{ copy.minimumNotice }} <b>{{ min_order }}</b></div>
    </div>
    <div class="panel hero-side" id="overview">
      <div class="orb"></div>
      <div class="feature"><h4>{{ copy.f1t }}</h4><p>{{ copy.f1d }}</p></div>
      <div class="feature"><h4>{{ copy.f2t }}</h4><p>{{ copy.f2d }}</p></div>
      <div class="feature"><h4>{{ copy.f3t }}</h4><p>{{ copy.f3d }}</p></div>
    </div>
  </section>

  <div class="floating-strip">
    <div class="item"><strong>{{ copy.instantPricing }}</strong><div class="muted">{{ copy.instantPricingText }}</div></div>
    <div class="item"><strong>{{ copy.verifiedCheckout }}</strong><div class="muted">{{ copy.verifiedCheckoutText }}</div></div>
    <div class="item"><strong>{{ copy.liveAvailability }}</strong><div class="muted">{{ copy.liveAvailabilityText }}</div></div>
    <div class="item"><strong>{{ copy.privateDelivery }}</strong><div class="muted">{{ copy.privateDeliveryText }}</div></div>
  </div>

  <div class="section-head" id="catalog">
    <div>
      <h2>{{ copy.catalogTitle }}</h2>
      <p>{{ copy.catalogText }}</p>
    </div>
  </div>

  <section class="catalog">
    {% for k,v in categories.items() %}
    <article class="card">
      <div class="kicker">{{ copy.catalogTag }}</div>
      <div class="product-title">{{ v.title }}</div>
      <div class="price">${{ '%.3f'|format(v.price) }}</div>
      <div class="desc">{{ v.desc }}</div>
      <div class="stock-line">
        <div>{{ copy.stock }}</div>
        <div class="stock-pill">{{ stock_counts[k] }}</div>
      </div>
      <button class="buy" onclick="openBuy('{{ k }}')">{{ copy.buyNow }}</button>
    </article>
    {% endfor %}
  </section>

  <div class="footer">© {{ site_name }}</div>
</div>

<div id="buyModal" class="modal" onclick="if(event.target===this)closeBuy()">
  <div class="box">
    <div class="checkout-head">
      <h2>{{ copy.checkout }}</h2>
      <button class="close-btn" type="button" onclick="closeBuy()">{{ copy.close }}</button>
    </div>
    <form method="post" action="/order?lang={{ lang }}">
      <div class="grid">
        <div class="field">
          <label>{{ copy.email }}</label>
          <input type="email" name="email" required>
        </div>
        <div class="field">
          <label>{{ copy.telegram }}</label>
          <input type="text" name="telegram_username" placeholder="username" required>
        </div>
        <div class="field">
          <label>{{ copy.category }}</label>
          <select id="category" name="category" onchange="updatePrice()">
            {% for k,v in categories.items() %}
            <option value="{{ k }}">{{ v.title }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="field">
          <label>{{ copy.quantity }}</label>
          <input id="quantity" type="number" min="1" max="{{ max_qty }}" name="quantity" oninput="updatePrice()" required>
        </div>
        <div class="field full">
          <label>{{ copy.payment }}</label>
          <select id="payment_method" name="payment_method" onchange="updatePrice()">
            {% for k,v in payments.items() %}
            <option value="{{ k }}">{{ v.name }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="field full">
          <div id="pricePreview" class="preview">{{ copy.total }}: 0</div>
          <div id="paymentDetails" class="payment-box muted"></div>
          <div id="orderWarning" class="warning"></div>
        </div>
        <div class="field full">
          <label>{{ copy.notes }}</label>
          <textarea name="notes" rows="3" placeholder="{{ copy.optional }}"></textarea>
        </div>
        <div class="field full">
          <button class="cta" type="submit">{{ copy.goToCart }}</button>
        </div>
      </div>
    </form>
  </div>
</div>
</body>
</html>
"""

PAYMENT_HTML = """
<!doctype html>
<html lang="{{ lang }}" dir="{{ 'rtl' if lang == 'ar' else 'ltr' }}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ copy.paymentPage }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#020617,#0f172a);color:#f8fafc;padding:32px}.box{max-width:860px;margin:auto;background:rgba(11,18,32,.86);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:30px;box-shadow:0 30px 80px rgba(0,0,0,.35)}.muted{color:#94a3b8}.grid{display:grid;gap:12px}.value{padding:14px 16px;border-radius:16px;background:rgba(255,255,255,.04)}.btn{appearance:none;border:none;border-radius:16px;padding:14px 18px;background:linear-gradient(90deg,#38bdf8,#8b5cf6);color:#06101b;font-weight:900;cursor:pointer}.upload{padding:16px;border-radius:16px;background:#0c1426;border:1px solid rgba(255,255,255,.08)}
</style></head>
<body>
<div class="box">
<h1>{{ copy.paymentPage }}</h1>
<div class="grid">
<div class="value">{{ copy.category }}: <b>{{ category_title }}</b></div>
<div class="value">{{ copy.quantity }}: <b>{{ quantity }}</b></div>
<div class="value">{{ copy.total }}: <b>{{ total_price }}</b></div>
<div class="value">{{ copy.payment }}: <b>{{ payment_name }}</b></div>
<div class="value">{{ copy.paymentInfo }}: <b>{{ payment_details }}</b></div>
</div>
<form method="post" action="/submit-payment/{{ draft_token }}?lang={{ lang }}" enctype="multipart/form-data" style="margin-top:20px">
  <div class="upload">
    <label>{{ copy.uploadReceipt }}</label><br><br>
    <input type="file" name="receipt" accept="image/*" required>
  </div>
  <br>
  <button class="btn" type="submit">{{ copy.paid }}</button>
</form>
</div>
</body>
</html>
"""

STATUS_HTML = """
<!doctype html>
<html lang="{{ lang }}" dir="{{ 'rtl' if lang == 'ar' else 'ltr' }}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ copy.order }} #{{ order.id }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#020617,#0f172a);color:#f8fafc;padding:32px}.box{max-width:820px;margin:auto;background:rgba(11,18,32,.86);border:1px solid rgba(255,255,255,.08);border-radius:28px;padding:30px;box-shadow:0 30px 80px rgba(0,0,0,.35)}.muted{color:#94a3b8}.ok{color:#22c55e}.bad{color:#ef4444}.warn{color:#f59e0b}pre{white-space:pre-wrap;background:#111827;padding:18px;border-radius:18px;border:1px solid rgba(255,255,255,.06)}a{color:#5ee7ff}
</style></head>
<body>
<div class="box">
<h1>{{ copy.order }} #{{ order.id }}</h1>
<p class="muted">{{ copy.status }}: <b>{{ order.status }}</b></p>
{% if order.status == 'approved' and order.blob %}
<p class="ok">{{ copy.approved }}</p>
<pre>{{ order.blob }}</pre>
<a href="/download/{{ order.id }}?token={{ order.token }}">{{ copy.download }}</a>
{% elif order.status == 'rejected' %}
<p class="bad">{{ copy.rejected }}</p>
{% else %}
<p class="warn">{{ copy.waiting }}</p>
{% endif %}
</div>
</body>
</html>
"""

COPY = {
    "en": {
        "badge": "Elite digital delivery workflow",
        "heroTitle": "Premium Instagram accounts with a high-end storefront experience.",
        "heroText": "Browse premium, medium, and basic account tiers, check live stock, choose your payment method",
        "premiumLabel": "INSTAGRAM ACC",
        "midLabel": "INSTAGRAM ACC #2",
        "basicLabel": "INSTAGRAM ACC #2",
        "minimumNotice": "Minimum order quantity:",
        "f1t": "Live inventory visibility",
        "f1d": "Each category displays real-time stock with a clean, premium layout.",
        "f2t": "Smooth payment flow",
        "f2d": "Supports ZainCash, MasterCard, Litecoin, USDT BEP20, and USDT TRC20 with automatic price calculation.",
        "f3t": "Private order tracking",
        "f3d": "Each buyer receives a private status page for review progress and TXT delivery.",
        "catalogTitle": "Premium Catalog",
        "catalogText": "Refined product cards, live stock display, and direct checkout flow.",
        "catalogTag": "Digital Goods",
        "stock": "Live Stock",
        "buyNow": "Start Purchase",
        "learnMore": "Explore More",
        "instantPricing": "Instant Pricing",
        "instantPricingText": "Totals update live as quantity and payment method change.",
        "verifiedCheckout": "Verified Checkout",
        "verifiedCheckoutText": "Receipt-based manual approval keeps fulfillment controlled.",
        "liveAvailability": "Live Availability",
        "liveAvailabilityText": "Each category reflects real stock before the order is placed.",
        "privateDelivery": "Private Delivery",
        "privateDeliveryText": "Approved orders receive TXT delivery with a private tracking page.",
        "checkout": "Complete Purchase",
        "close": "Close",
        "email": "Email",
        "telegram": "Telegram Username",
        "category": "Category",
        "quantity": "Quantity",
        "payment": "Payment Method",
        "notes": "Notes",
        "optional": "Optional",
        "goToCart": "Go to Cart",
        "total": "Final Total",
        "paymentInfo": "Payment details",
        "notEnough": "Requested quantity is higher than available stock.",
        "minOrder": "Minimum order quantity is",
        "paymentPage": "Payment Page",
        "uploadReceipt": "Upload receipt image",
        "paid": "I Have Paid",
        "order": "Order",
        "status": "Status",
        "approved": "Approved. Your TXT delivery is ready.",
        "rejected": "This order was rejected.",
        "waiting": "Please wait 3 to 5 minutes while your payment is being reviewed.",
        "download": "Download TXT",
    },
    "ar": {
        "badge": "نظام راقٍ لتسليم المنتجات الرقمية",
        "heroTitle": "مخزون رقمي فاخر بتجربة متجر احترافية عالية المستوى.",
        "heroText": "تصفح الفئات الممتازة والمتوسطة والأساسية، راقب المخزون المباشر، اختر وسيلة الدفع، ارفع الإيصال، واستلم ملف TXT بعد الموافقة اليدوية.",
        "premiumLabel": "الفئة الممتازة",
        "midLabel": "الفئة المتوسطة",
        "basicLabel": "الفئة الأساسية",
        "minimumNotice": "الحد الأدنى للطلب:",
        "f1t": "رؤية مباشرة للمخزون",
        "f1d": "كل فئة تعرض المخزون الحالي بشكل مباشر ضمن واجهة راقية وواضحة.",
        "f2t": "تدفق دفع سلس",
        "f2d": "يدعم زين كاش وماستر كارد ولايتكوين وUSDT BEP20 وUSDT TRC20 مع حساب تلقائي للإجمالي.",
        "f3t": "متابعة خاصة للطلب",
        "f3d": "يحصل كل مشتري على صفحة خاصة لمتابعة المراجعة واستلام ملف TXT بعد الموافقة.",
        "catalogTitle": "الكتالوج الاحترافي",
        "catalogText": "بطاقات منظمة، مخزون مباشر، وتجربة شراء واضحة وسريعة.",
        "catalogTag": "منتجات رقمية",
        "stock": "المخزون المباشر",
        "buyNow": "ابدأ الشراء",
        "learnMore": "استكشف المزيد",
        "instantPricing": "تسعير فوري",
        "instantPricingText": "يتم تحديث الإجمالي مباشرة حسب الكمية وطريقة الدفع.",
        "verifiedCheckout": "شراء موثّق",
        "verifiedCheckoutText": "الموافقة اليدوية عبر الإيصال تجعل التنفيذ أكثر دقة وتحكمًا.",
        "liveAvailability": "توفر مباشر",
        "liveAvailabilityText": "كل فئة تعرض الكمية الفعلية قبل إتمام الطلب.",
        "privateDelivery": "تسليم خاص",
        "privateDeliveryText": "بعد الموافقة يحصل العميل على ملف TXT مع صفحة تتبع خاصة.",
        "checkout": "إتمام الشراء",
        "close": "إغلاق",
        "email": "البريد الإلكتروني",
        "telegram": "يوزر تيليجرام",
        "category": "الفئة",
        "quantity": "الكمية",
        "payment": "وسيلة الدفع",
        "notes": "ملاحظات",
        "optional": "اختياري",
        "goToCart": "الذهاب إلى السلة",
        "total": "الإجمالي النهائي",
        "paymentInfo": "معلومات الدفع",
        "notEnough": "الكمية المطلوبة أكبر من المخزون المتوفر.",
        "minOrder": "الحد الأدنى للطلب هو",
        "paymentPage": "صفحة الدفع",
        "uploadReceipt": "ارفع صورة الإيصال",
        "paid": "تم الدفع",
        "order": "الطلب",
        "status": "الحالة",
        "approved": "تمت الموافقة. ملف TXT جاهز.",
        "rejected": "تم رفض هذا الطلب.",
        "waiting": "يرجى الانتظار من 3 إلى 5 دقائق لحين مراجعة الدفع.",
        "download": "تحميل TXT",
    }
}

@app.get("/")
def home():
    lang = request.args.get("lang", DEFAULT_LANGUAGE)
    if lang not in COPY:
        lang = DEFAULT_LANGUAGE
    prices = {k: get_price(k) for k in CATEGORIES}
    payments = {k: {"name": v[f"name_{lang}"], "mult": v["mult"], "details": v["details"]} for k, v in PAYMENTS.items()}
    categories = {k: {"title": v[f"title_{lang}"], "desc": v[f"desc_{lang}"], "price": prices[k]} for k, v in CATEGORIES.items()}
    stock = {k: stock_count(k) for k in CATEGORIES}
    return render_template_string(
        INDEX_HTML,
        site_name=SITE_NAME,
        lang=lang,
        copy=COPY[lang],
        copy_json=json.dumps(COPY[lang], ensure_ascii=False),
        categories=categories,
        stock_counts=stock,
        stock_json=json.dumps(stock),
        prices_json=json.dumps(prices),
        payments_json=json.dumps(payments, ensure_ascii=False),
        payments=payments,
        min_order=get_min_order(),
        max_qty=MAX_QTY_PER_ORDER,
    )

@app.post("/order")
def order():
    if not rate_limit(f"order:{client_ip()}", 20, 300):
        abort(429)
    email = (request.form.get("email") or "").strip()
    telegram = (request.form.get("telegram_username") or "").strip().lstrip("@")
    category = (request.form.get("category") or "").strip()
    payment = (request.form.get("payment_method") or "").strip()
    notes = html.escape((request.form.get("notes") or "").strip())[:500]
    lang = request.args.get("lang", DEFAULT_LANGUAGE)
    try:
        qty = int((request.form.get("quantity") or "0").strip())
    except ValueError:
        return redirect(url_for("home"))
    if lang not in COPY:
        lang = DEFAULT_LANGUAGE
    if not validate_email(email) or not validate_telegram_username(telegram):
        return redirect(url_for("home", lang=lang))
    if category not in CATEGORIES or payment not in PAYMENTS:
        return redirect(url_for("home", lang=lang))
    if qty < get_min_order():
        return COPY[lang]["minOrder"] + f" {get_min_order()}"
    if qty > MAX_QTY_PER_ORDER:
        return COPY[lang]["notEnough"]
    if qty > stock_count(category):
        return COPY[lang]["notEnough"]

    total = calc_total(category, qty, payment)
    raw_token = secrets.token_hex(16)
    draft_token = sign_value(raw_token)
    DRAFT_ORDERS[draft_token] = {
        "email": email,
        "telegram": telegram,
        "category": category,
        "qty": qty,
        "payment": payment,
        "notes": notes,
        "total": total,
        "lang": lang,
    }

    return render_template_string(
        PAYMENT_HTML,
        lang=lang,
        copy=COPY[lang],
        category_title=CATEGORIES[category][f"title_{lang}"],
        quantity=qty,
        total_price=total,
        payment_name=PAYMENTS[payment][f"name_{lang}"],
        payment_details=PAYMENTS[payment]["details"],
        draft_token=draft_token,
    )

@app.post("/submit-payment/<draft_token>")
def submit_payment(draft_token):
    if not rate_limit(f"payment:{client_ip()}", 20, 300):
        abort(429)
    if not verify_signed_value(draft_token):
        abort(400)
    draft = DRAFT_ORDERS.get(draft_token)
    receipt = request.files.get("receipt")
    lang = request.args.get("lang", DEFAULT_LANGUAGE)
    if lang not in COPY:
        lang = DEFAULT_LANGUAGE
    if not draft or not receipt:
        return redirect(url_for("home", lang=lang))
    if not receipt.filename or not allowed_receipt(receipt.filename):
        return redirect(url_for("home", lang=lang))

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ext = Path(receipt.filename).suffix.lower()
    safe_name = safe_filename(f"receipt_{int(datetime.utcnow().timestamp())}_{draft['telegram']}{ext}")
    receipt_path = UPLOAD_DIR / safe_name
    receipt.save(receipt_path)

    token = sign_value(secrets.token_hex(16))
    conn = db_connect()
    cur = conn.execute(
        "INSERT INTO orders(email, telegram, category, qty, payment, total, status, blob, token, receipt_path, notes, created_at) VALUES(?,?,?,?,?,?, 'pending','',?,?,?,?)",
        (
            draft["email"],
            draft["telegram"],
            draft["category"],
            draft["qty"],
            draft["payment"],
            draft["total"],
            token,
            str(receipt_path),
            draft["notes"],
            datetime.utcnow().isoformat(),
        ),
    )
    order_id = cur.lastrowid
    conn.commit()
    conn.close()
    DRAFT_ORDERS.pop(draft_token, None)

    log_action("order_created", f"order #{order_id}")
    kb = types.InlineKeyboardMarkup()
    kb.row(
        types.InlineKeyboardButton("Accept", callback_data=f"order_accept:{order_id}"),
        types.InlineKeyboardButton("Reject", callback_data=f"order_reject:{order_id}"),
    )
    bot.send_message(
        ADMIN_CHAT_ID,
        f"New Order #{order_id}\n\nEmail: {draft['email']}\nTelegram: @{draft['telegram']}\nCategory: {CATEGORIES[draft['category']]['title_en']}\nQuantity: {draft['qty']}\nPayment: {PAYMENTS[draft['payment']]['name_en']}\nTotal: {draft['total']}",
        reply_markup=kb,
    )
    return redirect(f"{BASE_URL.rstrip('/')}/status/{order_id}?token={token}&lang={draft['lang']}")

@app.get("/status/<int:order_id>")
def status(order_id):
    lang = request.args.get("lang", DEFAULT_LANGUAGE)
    if lang not in COPY:
        lang = DEFAULT_LANGUAGE
    token = request.args.get("token", "")
    if not verify_signed_value(token):
        abort(404)
    conn = db_connect()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    conn.close()
    if not order or token != order["token"]:
        abort(404)
    return render_template_string(STATUS_HTML, lang=lang, copy=COPY[lang], order=order)

@app.get("/download/<int:order_id>")
def download(order_id):
    token = request.args.get("token", "")
    if not verify_signed_value(token):
        abort(404)
    conn = db_connect()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    conn.close()
    if not order or token != order["token"] or order["status"] != "approved":
        abort(404)
    return send_file(BytesIO(order["blob"].encode("utf-8")), mimetype="text/plain", as_attachment=True, download_name=f"order_{order_id}.txt")

# ================= BOT =================
@bot.message_handler(commands=["start"])
def start_cmd(message):
    if not is_admin(message.chat.id):
        bot.send_message(message.chat.id, "Welcome")
        return
    bot.send_message(message.chat.id, "Main Control Panel", reply_markup=admin_keyboard())

@bot.message_handler(content_types=["document"])
def handle_document(message):
    if not is_admin(message.chat.id):
        return
    state = BOT_STATE.get(message.chat.id)
    if state != "await_stock_txt":
        return
    if not message.document.file_name.lower().endswith(".txt"):
        bot.reply_to(message, "Please upload a TXT file only.")
        return
    file_info = bot.get_file(message.document.file_id)
    file_bytes = bot.download_file(file_info.file_path)
    TEMP_STOCK_FILE.write_bytes(file_bytes)
    bot.send_message(message.chat.id, "Select the category for this stock file.", reply_markup=category_inline("save_stock"))

@bot.message_handler(func=lambda m: True)
def handle_messages(message):
    if not is_admin(message.chat.id):
        return
    text = (message.text or "").strip()
    state = BOT_STATE.get(message.chat.id)

    if text == "Add Stock":
        BOT_STATE[message.chat.id] = "await_stock_txt"
        bot.send_message(message.chat.id, "Upload a TXT stock file now.")
        return
    if text == "Clear All Stock":
        clear_all_stock()
        bot.send_message(message.chat.id, "All stock deleted.", reply_markup=admin_keyboard())
        return
    if text == "Completed Orders":
        conn = db_connect()
        rows = conn.execute("SELECT id, telegram, qty, created_at FROM orders WHERE status='approved' ORDER BY id DESC LIMIT 20").fetchall()
        conn.close()
        text_out = "No completed orders yet." if not rows else "\n".join([f"#{r['id']} | @{r['telegram']} | {r['qty']} | {r['created_at']}" for r in rows])
        bot.send_message(message.chat.id, text_out, reply_markup=admin_keyboard())
        return
    if text == "Recent Activity":
        rows = recent_logs(20)
        text_out = "No activity yet." if not rows else "\n".join([f"[{r['created_at']}] {r['action']} => {r['details']}" for r in rows])
        bot.send_message(message.chat.id, text_out, reply_markup=admin_keyboard())
        return
    if text == "Change Prices":
        bot.send_message(message.chat.id, "Choose a category to change its price.", reply_markup=category_inline("set_price"))
        return
    if text == "Set Min Order":
        BOT_STATE[message.chat.id] = "await_min_order"
        bot.send_message(message.chat.id, "Send the new minimum order quantity.")
        return

    if state == "await_min_order":
        try:
            value = int(text)
            if value < 1:
                raise ValueError
        except ValueError:
            bot.send_message(message.chat.id, "Send a valid integer greater than zero.")
            return
        set_min_order(value)
        BOT_STATE.pop(message.chat.id, None)
        bot.send_message(message.chat.id, f"Minimum order updated to {value}.", reply_markup=admin_keyboard())
        return

    if state and state.startswith("await_price:"):
        category_key = state.split(":", 1)[1]
        try:
            new_price = float(text)
        except ValueError:
            bot.send_message(message.chat.id, "Send a valid number only.")
            return
        set_price(category_key, new_price)
        BOT_STATE.pop(message.chat.id, None)
        bot.send_message(message.chat.id, f"Price updated for {category_key} => {new_price}", reply_markup=admin_keyboard())
        return

@bot.callback_query_handler(func=lambda call: True)
def callbacks(call):
    if not is_admin(call.message.chat.id):
        bot.answer_callback_query(call.id, "Unauthorized")
        return
    data = call.data

    if data.startswith("save_stock:"):
        category_key = data.split(":", 1)[1]
        if not TEMP_STOCK_FILE.exists():
            bot.answer_callback_query(call.id, "No uploaded file found")
            return
        added = add_stock(category_key, TEMP_STOCK_FILE.read_text(encoding="utf-8"))
        TEMP_STOCK_FILE.unlink(missing_ok=True)
        BOT_STATE.pop(call.message.chat.id, None)
        bot.answer_callback_query(call.id, "Done")
        bot.send_message(call.message.chat.id, f"Added {added} items to {category_key}.", reply_markup=admin_keyboard())
        return

    if data.startswith("set_price:"):
        category_key = data.split(":", 1)[1]
        BOT_STATE[call.message.chat.id] = f"await_price:{category_key}"
        bot.answer_callback_query(call.id, "Send new price")
        bot.send_message(call.message.chat.id, f"Send the new price for {category_key}.")
        return

    if data.startswith("order_accept:") or data.startswith("order_reject:"):
        action, raw_id = data.split(":", 1)
        try:
            order_id = int(raw_id)
        except ValueError:
            bot.answer_callback_query(call.id, "Invalid ID")
            return
        conn = db_connect()
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            conn.close()
            bot.answer_callback_query(call.id, "Order not found")
            return
        if order["status"] != "pending":
            conn.close()
            bot.answer_callback_query(call.id, f"Already {order['status']}")
            return

        if action == "order_reject":
            conn.execute("UPDATE orders SET status='rejected' WHERE id=?", (order_id,))
            conn.commit()
            conn.close()
            log_action("order_rejected", f"order #{order_id}")
            bot.answer_callback_query(call.id, "Rejected")
            bot.send_message(call.message.chat.id, f"Order #{order_id} rejected.", reply_markup=admin_keyboard())
            bot.send_message("@" + order["telegram"], f"Your order #{order_id} was rejected.")
            return

        items = take_stock(order["category"], order["qty"])
        if len(items) < order["qty"]:
            conn.close()
            bot.answer_callback_query(call.id, "Not enough stock")
            bot.send_message(call.message.chat.id, f"Not enough stock for order #{order_id}.")
            return
        blob = "\n".join(items)
        conn.execute("UPDATE orders SET status='approved', blob=? WHERE id=?", (blob, order_id))
        conn.commit()
        conn.close()
        log_action("order_approved", f"order #{order_id}, delivered {len(items)}")
        bot.answer_callback_query(call.id, "Accepted")
        file_name = f"order_{order_id}.txt"
        bot.send_document("@" + order["telegram"], (file_name, blob.encode("utf-8")), caption=f"Order #{order_id} approved")
        bot.send_message(call.message.chat.id, f"Order #{order_id} completed.", reply_markup=admin_keyboard())
        return

    bot.answer_callback_query(call.id, "Done")

# ================= TELEGRAM STARTUP =================
def set_webhook():
    if BOT_TOKEN.startswith("PUT_") or "your-domain.example" in BASE_URL:
        print("Set BOT_TOKEN and BASE_URL first.")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook"
    webhook_url = f"{BASE_URL.rstrip('/')}/telegram/webhook"
    r = requests.post(url, json={"url": webhook_url}, timeout=20)
    print("Webhook response:", r.text)


def run_bot_polling():
    print("BOT STARTED ✅")
    bot.infinity_polling(skip_pending=True)

@app.post("/telegram/webhook")
def telegram_webhook():
    if not USE_TELEGRAM_WEBHOOK:
        return {"ok": True}
    raw = request.get_data().decode("utf-8")
    update = telebot.types.Update.de_json(raw)
    bot.process_new_updates([update])
    return {"ok": True}

# ================= MAIN =================
    
if __name__ == "__main__":
    init_db()
    ensure_stock_files()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    if USE_TELEGRAM_WEBHOOK:
        set_webhook()
    else:
        threading.Thread(target=run_bot_polling, daemon=True).start()
