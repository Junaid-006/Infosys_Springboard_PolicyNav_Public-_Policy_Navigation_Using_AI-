import streamlit as st
import sqlite3
import re
import jwt
import datetime
import bcrypt
import time
import os
import smtplib
import secrets
import hmac
import hashlib
import struct
import PyPDF2
import plotly.graph_objects as go
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from streamlit_option_menu import option_menu

# ============================================================
# CONFIG
# ============================================================
SECRET_KEY         = os.getenv("JWT_SECRET_KEY", "super-secret-change-me")
ADMIN_EMAIL        = os.getenv("ADMIN_EMAIL_ID")
ADMIN_PASSWORD     = os.getenv("ADMIN_PASSWORD")
EMAIL_ID           = os.getenv("EMAIL_ID")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")

ALGORITHM          = "HS256"
MAX_LOGIN_ATTEMPTS = 3
LOCK_TIME          = 300
OTP_EXPIRY         = 600

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(page_title="PolicyNav", page_icon="⚡", layout="wide")

# ============================================================
# GLOBAL STYLES  — clean, modern, professional dark theme
# ============================================================
def apply_theme():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    /* ── Root ── */
    html, body, .stApp {
        background: #0a0e1a !important;
        font-family: 'Inter', sans-serif !important;
        color: #e2e8f0 !important;
    }

    /* ── Hide default Streamlit chrome ── */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding: 2rem 2.5rem 2rem 2.5rem !important; max-width: 1200px; }

    /* ── Headings ── */
    h1 { font-size: 2rem !important; font-weight: 700 !important;
         color: #f1f5f9 !important; letter-spacing: -0.5px; }
    h2 { font-size: 1.4rem !important; font-weight: 600 !important; color: #cbd5e1 !important; }
    h3 { font-size: 1.1rem !important; font-weight: 600 !important; color: #94a3b8 !important; }

    /* ── Inputs ── */
    .stTextInput > div > div > input,
    .stTextArea  > div > div > textarea {
        background: #111827 !important;
        border: 1px solid #1e293b !important;
        border-radius: 10px !important;
        color: #f1f5f9 !important;
        font-family: 'Inter', sans-serif !important;
        padding: 10px 14px !important;
        transition: border-color 0.2s, box-shadow 0.2s;
    }
    .stTextInput > div > div > input:focus,
    .stTextArea  > div > div > textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 3px rgba(99,102,241,0.15) !important;
        outline: none !important;
    }

    /* ── Select box ── */
    .stSelectbox > div > div {
        background: #111827 !important;
        border: 1px solid #1e293b !important;
        border-radius: 10px !important;
        color: #f1f5f9 !important;
    }

    /* ── Buttons ── */
    .stButton > button {
        background: linear-gradient(135deg, #6366f1, #4f46e5) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 10px !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        padding: 10px 20px !important;
        transition: all 0.25s ease !important;
        box-shadow: 0 2px 8px rgba(99,102,241,0.3) !important;
        width: 100%;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #818cf8, #6366f1) !important;
        box-shadow: 0 4px 20px rgba(99,102,241,0.5) !important;
        transform: translateY(-1px) !important;
    }
    .stButton > button:active { transform: translateY(0px) !important; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: #080c18 !important;
        border-right: 1px solid #1e293b !important;
    }
    section[data-testid="stSidebar"] .block-container { padding: 1.5rem 1rem !important; }

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab-list"] {
        background: #111827;
        border-radius: 12px;
        padding: 4px;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        color: #64748b !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
        font-size: 14px !important;
        padding: 8px 18px !important;
        border: none !important;
    }
    .stTabs [aria-selected="true"] {
        background: #6366f1 !important;
        color: #ffffff !important;
    }

    /* ── Metrics ── */
    [data-testid="stMetricValue"] { color: #6366f1 !important; font-weight: 700 !important; }
    [data-testid="stMetricLabel"] { color: #64748b !important; font-size: 13px !important; }

    /* ── Expanders ── */
    .streamlit-expanderHeader {
        background: #111827 !important;
        border-radius: 8px !important;
        color: #94a3b8 !important;
        font-size: 13px !important;
    }

    /* ── Alerts ── */
    .stAlert { border-radius: 10px !important; font-size: 14px !important; }

    /* ── Divider ── */
    hr { border-color: #1e293b !important; }

    /* ── Password strength ── */
    .pw-weak   { color: #f87171; font-weight: 600; font-size: 13px; }
    .pw-medium { color: #fbbf24; font-weight: 600; font-size: 13px; }
    .pw-strong { color: #34d399; font-weight: 600; font-size: 13px; }

    /* ── Card base ── */
    .pn-card {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 14px;
        padding: 24px;
    }

    /* ── Auth page centering ── */
    .auth-wrap {
        max-width: 420px;
        margin: 3rem auto;
    }
    </style>
    """, unsafe_allow_html=True)

apply_theme()

# ============================================================
# DATABASE
# ============================================================
conn   = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL,
    email             TEXT UNIQUE NOT NULL,
    password          BLOB NOT NULL,
    security_question TEXT NOT NULL,
    security_answer   TEXT NOT NULL
)""")

try:
    cursor.execute("ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT 'N/A'")
    conn.commit()
except:
    pass

cursor.execute("""CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password BLOB
)""")

cursor.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
    email TEXT PRIMARY KEY,
    attempts INTEGER,
    last_attempt REAL
)""")

cursor.execute("""CREATE TABLE IF NOT EXISTS analysis_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT,
    analyzed_at TEXT,
    char_count  INTEGER,
    word_count  INTEGER,
    avg_grade   REAL,
    level       TEXT,
    flesch_ease REAL,
    fk_grade    REAL,
    smog        REAL,
    gunning_fog REAL,
    coleman     REAL
)""")

conn.commit()
if ADMIN_EMAIL and ADMIN_PASSWORD:
    cursor.execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,))
    if not cursor.fetchone():
        hp = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username,email,password,security_question,security_answer) VALUES (?,?,?,?,?)",
            ("Admin", ADMIN_EMAIL, hp, "Admin Question", "Admin")
        )
        conn.commit()

# ============================================================
# HELPERS
# ============================================================
def valid_email(e):
    return bool(re.fullmatch(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e))

def check_password_strength(pw):
    if re.search(r"\s", pw):  return "Weak",   ["No spaces allowed"]
    ok = (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw))
    if len(pw) >= 8 and ok:   return "Strong",  []
    if len(pw) >= 6 and ok:   return "Medium",  ["Add 2+ chars for Strong"]
    return "Weak", ["Too short (aim for 8+)"]

def pw_strength_html(pw):
    s, f = check_password_strength(pw)
    cls  = {"Weak":"pw-weak","Medium":"pw-medium","Strong":"pw-strong"}[s]
    icon = {"Weak":"✗","Medium":"◑","Strong":"✓"}[s]
    hint = f" — {', '.join(f)}" if f else ""
    return f"<span class='{cls}'>{icon} {s}{hint}</span>"

# ============================================================
# RATE LIMITING
# ============================================================
def is_locked(email):
    cursor.execute("SELECT attempts, last_attempt FROM login_attempts WHERE email=?", (email,))
    row = cursor.fetchone()
    if row:
        att, last = row
        if att >= MAX_LOGIN_ATTEMPTS:
            rem = LOCK_TIME - (time.time() - last)
            if rem > 0: return True, int(rem)
    return False, 0

def record_fail(email):
    cursor.execute("SELECT attempts FROM login_attempts WHERE email=?", (email,))
    row = cursor.fetchone()
    now = time.time()
    if row:
        cursor.execute("UPDATE login_attempts SET attempts=?, last_attempt=? WHERE email=?",
                       (row[0]+1, now, email))
    else:
        cursor.execute("INSERT INTO login_attempts VALUES (?,?,?)", (email, 1, now))
    conn.commit()

def reset_attempts(email):
    cursor.execute("DELETE FROM login_attempts WHERE email=?", (email,))
    conn.commit()

# ============================================================
# JWT
# ============================================================
def create_token(email):
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    return jwt.encode({"email": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["email"]
    except:
        return None

# ============================================================
# OTP
# ============================================================
def generate_otp():
    secret  = secrets.token_bytes(20)
    msg     = struct.pack(">Q", int(time.time()))
    h       = hmac.new(secret, msg, hashlib.sha1).digest()
    offset  = h[19] & 0xf
    code    = ((h[offset]&0x7f)<<24|(h[offset+1]&0xff)<<16|
               (h[offset+2]&0xff)<<8|(h[offset+3]&0xff))
    return f"{code%1000000:06d}"

def create_otp_token(otp, email):
    otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
    payload  = {"otp_hash":otp_hash,"sub":email,"type":"otp",
                "iat":datetime.datetime.utcnow(),
                "exp":datetime.datetime.utcnow()+datetime.timedelta(seconds=OTP_EXPIRY)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_otp_token(token, input_otp, email):
    try:
        p = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if p.get("type")!="otp":    return False,"Invalid token type"
        if p.get("sub") !=email:    return False,"Token mismatch"
        if bcrypt.checkpw(input_otp.encode(), p["otp_hash"].encode()):
            return True,"Valid"
        return False,"Incorrect OTP"
    except jwt.ExpiredSignatureError: return False,"OTP expired"
    except jwt.InvalidTokenError:     return False,"Invalid token"

# ============================================================
# EMAIL
# ============================================================
def send_otp(to_email):
    otp             = generate_otp()
    msg             = MIMEMultipart("alternative")
    msg["Subject"]  = "PolicyNav — Your Verification Code"
    msg["From"]     = EMAIL_ID
    msg["To"]       = to_email
    html = f"""
    <html><body style="margin:0;padding:0;background:#0a0e1a;font-family:Inter,sans-serif;">
    <div style="max-width:520px;margin:40px auto;background:#111827;padding:40px;
                border-radius:16px;border:1px solid #1e293b;">
        <div style="text-align:center;margin-bottom:28px;">
            <span style="font-size:32px;">⚡</span>
            <h2 style="color:#f1f5f9;margin:8px 0 4px;font-size:22px;">PolicyNav</h2>
            <p style="color:#64748b;font-size:13px;margin:0;">Verification Code</p>
        </div>
        <p style="color:#94a3b8;font-size:15px;text-align:center;">
            Use the code below to verify your identity for
            <strong style="color:#6366f1;">{to_email}</strong>
        </p>
        <div style="background:#0a0e1a;border:1px solid #6366f1;border-radius:12px;
                    text-align:center;padding:24px;margin:24px 0;">
            <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#818cf8;">
                {otp}
            </span>
        </div>
        <p style="color:#64748b;font-size:13px;text-align:center;">
            Valid for <strong>10 minutes</strong>. Never share this code.
        </p>
        <hr style="border-color:#1e293b;margin:24px 0;">
        <p style="color:#374151;font-size:11px;text-align:center;">© 2026 PolicyNav</p>
    </div></body></html>
    """
    msg.attach(MIMEText(html,"html"))
    try:
        sv = smtplib.SMTP("smtp.gmail.com",587)
        sv.starttls()
        sv.login(EMAIL_ID, EMAIL_APP_PASSWORD)
        sv.sendmail(EMAIL_ID, to_email, msg.as_string())
        sv.quit()
        st.session_state.otp_token = create_otp_token(otp, to_email)
        return True,"Sent"
    except Exception as ex:
        return False, str(ex)

# ============================================================
# READABILITY
# ============================================================
def get_readability_metrics(text):
    import textstat
    scores = {
        "Flesch Reading Ease":  textstat.flesch_reading_ease(text),
        "Flesch-Kincaid Grade": textstat.flesch_kincaid_grade(text),
        "SMOG Index":           textstat.smog_index(text),
        "Gunning Fog":          textstat.gunning_fog(text),
        "Coleman-Liau":         textstat.coleman_liau_index(text),
    }
    stats = {
        "Sentences":     textstat.sentence_count(text),
        "Words":         textstat.lexicon_count(text, removepunct=True),
        "Syllables":     textstat.syllable_count(text),
        "Complex Words": textstat.difficult_words(text),
        "Characters":    textstat.char_count(text),
    }
    return scores, stats

def create_gauge(value, title, min_val=0, max_val=100, color="#6366f1"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=value,
        title={"text": title, "font": {"color": "#94a3b8", "size": 13}},
        number={"font": {"color": color, "size": 22}},
        gauge={
            "axis":        {"range":[min_val,max_val],"tickwidth":1,"tickcolor":"#334155"},
            "bar":         {"color": color},
            "bgcolor":     "#111827",
            "borderwidth": 1,
            "bordercolor": "#1e293b",
            "steps":       [{"range":[min_val,max_val],"color":"#0f172a"}],
        }
    ))
    fig.update_layout(paper_bgcolor="#111827", font={"color":"#94a3b8","family":"Inter"},
                      height=230, margin=dict(l=10,r=10,t=40,b=10))
    return fig

# ============================================================
# SESSION DEFAULTS
# ============================================================
for k,v in [("token",None),("page","login"),("otp_stage",None)]:
    if k not in st.session_state: st.session_state[k] = v

# ============================================================
# SHARED UI COMPONENTS
# ============================================================
def auth_header(title, subtitle):
    st.markdown(f"""
    <div style="text-align:center;padding:2rem 0 1.5rem;">
        <div style="font-size:40px;margin-bottom:12px;">⚡</div>
        <h1 style="font-size:1.8rem !important;color:#f1f5f9 !important;margin:0;">PolicyNav</h1>
        <p style="color:#475569;font-size:14px;margin:6px 0 0;">{subtitle}</p>
    </div>
    <div style="text-align:center;margin-bottom:1.5rem;">
        <span style="font-size:1.1rem;font-weight:600;color:#e2e8f0;">{title}</span>
    </div>
    """, unsafe_allow_html=True)

def card_start():
    st.markdown('<div class="pn-card">', unsafe_allow_html=True)

def card_end():
    st.markdown('</div>', unsafe_allow_html=True)

def divider_text(text):
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:12px;margin:16px 0;">
        <div style="flex:1;height:1px;background:#1e293b;"></div>
        <span style="color:#475569;font-size:12px;">{text}</span>
        <div style="flex:1;height:1px;background:#1e293b;"></div>
    </div>
    """, unsafe_allow_html=True)

def section_header(icon, title, subtitle=""):
    st.markdown(f"""
    <div style="margin-bottom:1.5rem;">
        <div style="display:flex;align-items:center;gap:10px;">
            <span style="font-size:24px;">{icon}</span>
            <div>
                <h1 style="margin:0;font-size:1.6rem !important;">{title}</h1>
                {"<p style='margin:2px 0 0;color:#475569;font-size:13px;'>"+subtitle+"</p>" if subtitle else ""}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def kpi_card(col, icon, label, value, accent="#6366f1"):
    col.markdown(f"""
    <div style="background:#111827;border:1px solid #1e293b;border-radius:14px;
                padding:20px;text-align:center;border-top:3px solid {accent};">
        <div style="font-size:26px;margin-bottom:6px;">{icon}</div>
        <div style="font-size:28px;font-weight:700;color:{accent};font-family:Inter;">{value}</div>
        <div style="color:#64748b;font-size:12px;margin-top:4px;">{label}</div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# SIDEBAR  (used by all logged-in pages)
# ============================================================
def render_sidebar(email, username, is_admin):
    with st.sidebar:
        # Brand
        st.markdown(f"""
        <div style="padding:16px 8px 8px;text-align:center;">
            <div style="font-size:28px;">⚡</div>
            <div style="font-weight:700;font-size:16px;color:#f1f5f9;margin:4px 0;">PolicyNav</div>
            <div style="font-size:11px;color:#475569;">Public Policy Navigation</div>
        </div>
        <hr style="border-color:#1e293b;margin:12px 0;">
        """, unsafe_allow_html=True)

        # User info chip
        initials = username[:2].upper()
        st.markdown(f"""
        <div style="background:#1e293b;border-radius:12px;padding:12px 14px;
                    display:flex;align-items:center;gap:12px;margin-bottom:12px;">
            <div style="background:#6366f1;border-radius:50%;width:36px;height:36px;
                        display:flex;align-items:center;justify-content:center;
                        font-weight:700;font-size:13px;color:white;flex-shrink:0;">
                {initials}
            </div>
            <div style="overflow:hidden;">
                <div style="font-weight:600;font-size:13px;color:#e2e8f0;
                            white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">
                    {username}{"&nbsp;👑" if is_admin else ""}
                </div>
                <div style="font-size:11px;color:#475569;white-space:nowrap;
                            overflow:hidden;text-overflow:ellipsis;">{email}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Navigation
        opts  = ["🛡️ Admin", "📖 Readability"] if is_admin else ["🏠 Home", "📖 Readability"]
        icons = ["shield-lock", "book"]        if is_admin else ["house", "book"]

        # Admin lands on Admin (index 0), users land on Home (index 0)
        default = 0

        selected = option_menu(
            None, opts, icons=icons,
            menu_icon="cast", default_index=default,
            styles={
                "container":         {"background-color":"#080c18","padding":"0"},
                "icon":              {"color":"#6366f1","font-size":"15px"},
                "nav-link":          {"color":"#64748b","font-size":"14px",
                                      "font-family":"Inter","border-radius":"8px",
                                      "margin":"2px 0","padding":"10px 14px"},
                "nav-link-selected": {"background-color":"#1e293b","color":"#e2e8f0",
                                      "font-weight":"600"},
            }
        )

        st.markdown("<div style='flex:1'></div>", unsafe_allow_html=True)
        st.markdown("<hr style='border-color:#1e293b;margin:12px 0;'>", unsafe_allow_html=True)

        if st.button("Sign Out", use_container_width=True):
            st.session_state.token = None
            st.session_state.page  = "login"
            st.rerun()

        st.markdown("""
        <div style="text-align:center;padding:8px 0 0;color:#1e293b;font-size:11px;">
            PolicyNav v1.0 · 2026
        </div>
        """, unsafe_allow_html=True)

    return selected

# ============================================================
# DASHBOARD ROUTER
# ============================================================
def dashboard():
    email = verify_token(st.session_state.token)
    if not email:
        st.session_state.token = None
        st.session_state.page  = "login"
        st.rerun()

    cursor.execute("SELECT username FROM users WHERE email=?", (email,))
    row      = cursor.fetchone()
    username = row[0] if row else email.split("@")[0]
    is_admin = (email == ADMIN_EMAIL)

    selected = render_sidebar(email, username, is_admin)

    if selected == "🛡️ Admin":
        admin_page(email)
    elif selected == "🏠 Home":
        user_home_page(email, username)
    else:
        readability_page(email)
# ============================================================
# PAGE: USER HOME DASHBOARD
# ============================================================
def user_home_page(email, username):
    now_hour = datetime.datetime.now().hour
    if   now_hour < 12: tod = "Good morning"
    elif now_hour < 17: tod = "Good afternoon"
    else:               tod = "Good evening"

    initials = username[:2].upper()

    # ── Hero greeting ──
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#111827 0%,#1a1f35 100%);
                border:1px solid #1e293b;border-radius:16px;padding:28px 32px;
                display:flex;align-items:center;gap:20px;margin-bottom:24px;">
        <div style="background:linear-gradient(135deg,#6366f1,#818cf8);border-radius:50%;
                    width:60px;height:60px;display:flex;align-items:center;
                    justify-content:center;font-size:22px;font-weight:700;
                    color:white;flex-shrink:0;box-shadow:0 0 20px rgba(99,102,241,0.4);">
            {initials}
        </div>
        <div>
            <div style="color:#64748b;font-size:13px;font-weight:500;">{tod} 👋</div>
            <div style="color:#f1f5f9;font-size:22px;font-weight:700;margin:2px 0;">
                {username}
            </div>
            <div style="color:#475569;font-size:13px;">{email}</div>
        </div>
        <div style="margin-left:auto;text-align:right;">
            <div style="color:#475569;font-size:12px;">Session active</div>
            <div style="color:#34d399;font-size:12px;font-weight:600;">● Online</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Pull history ──
    cursor.execute("""SELECT analyzed_at, avg_grade, level, word_count,
                             flesch_ease, fk_grade, smog, gunning_fog, coleman
                      FROM analysis_history WHERE email=?
                      ORDER BY analyzed_at DESC""", (email,))
    history = cursor.fetchall()
    total_analyses = len(history)

    # ── Stats row ──
    avg_ease  = round(sum(r[4] for r in history) / total_analyses, 1) if history else "—"
    avg_grade = round(sum(r[1] for r in history) / total_analyses, 1) if history else "—"
    total_words = sum(r[3] for r in history)

    c1,c2,c3,c4 = st.columns(4)
    def stat_card(col, icon, label, value, sub, accent="#6366f1"):
        col.markdown(f"""
        <div style="background:#111827;border:1px solid #1e293b;border-radius:14px;
                    padding:20px;border-top:3px solid {accent};">
            <div style="font-size:22px;margin-bottom:8px;">{icon}</div>
            <div style="font-size:26px;font-weight:700;color:{accent};font-family:Inter;">
                {value}
            </div>
            <div style="color:#e2e8f0;font-size:13px;font-weight:500;margin-top:4px;">{label}</div>
            <div style="color:#475569;font-size:12px;margin-top:2px;">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

    stat_card(c1,"📊","Texts Analyzed",   total_analyses, "total sessions",         "#6366f1")
    stat_card(c2,"📝","Words Processed",  f"{total_words:,}" if history else "—",
              "across all analyses",                                                  "#0ea5e9")
    stat_card(c3,"📖","Avg Flesch Ease",  avg_ease,       "higher = more readable", "#10b981")
    stat_card(c4,"🎓","Avg Grade Level",  avg_grade,      "School / University / College grade", "#f59e0b")

    st.markdown("<br>", unsafe_allow_html=True)

    col_left, col_right = st.columns([1.6, 1])

    # ── Left: Recent analyses ──
    with col_left:
        st.markdown("""
        <div style="font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:14px;">
            🕐 Recent Analyses
        </div>
        """, unsafe_allow_html=True)

        if not history:
            st.markdown("""
            <div style="background:#111827;border:1px dashed #1e293b;border-radius:14px;
                        padding:40px;text-align:center;">
                <div style="font-size:36px;margin-bottom:12px;">📄</div>
                <div style="color:#475569;font-size:14px;margin-bottom:6px;">No analyses yet</div>
                <div style="color:#334155;font-size:12px;">
                    Go to the Readability tab and analyze your first policy text!
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            level_colors = {
                "Beginner":       "#34d399",
                "Intermediate":   "#38bdf8",
                "Advanced":       "#fbbf24",
                "Expert/Academic":"#f87171",
            }
            for row in history[:5]:
                analyzed_at, avg_g, level, wcount, f_ease, fk_g, smog, fog, col_liau = row
                accent = level_colors.get(level, "#6366f1")
                try:
                    dt = datetime.datetime.strptime(analyzed_at, "%Y-%m-%d %H:%M:%S")
                    dt_str = dt.strftime("%d %b %Y · %H:%M")
                except:
                    dt_str = analyzed_at

                # ── Build metrics grid BEFORE the f-string to avoid nested f-string corruption ──
                metrics_html = ""
                for lbl, val in [
                    ("Flesch", round(f_ease, 1)),
                    ("F-K",    round(fk_g,   1)),
                    ("SMOG",   round(smog,   1)),
                    ("Fog",    round(fog,     1)),
                    ("C-L",    round(col_liau,1)),
                ]:
                    metrics_html += (
                        f'<div style="text-align:center;">'
                        f'<div style="color:#64748b;font-size:11px;margin-bottom:4px;">{lbl}</div>'
                        f'<div style="color:#e2e8f0;font-size:14px;font-weight:600;">{val}</div>'
                        f'</div>'
                    )

                st.markdown(f"""
                <div style="background:#111827;border:1px solid #1e293b;border-radius:12px;
                            padding:16px 18px;margin-bottom:8px;
                            border-left:4px solid {accent};">
                    <div style="display:flex;justify-content:space-between;align-items:center;
                                margin-bottom:12px;">
                        <div>
                            <span style="background:{accent}22;color:{accent};font-size:11px;
                                         font-weight:600;padding:3px 10px;border-radius:20px;">
                                {level}
                            </span>
                            <span style="color:#475569;font-size:12px;margin-left:10px;">
                                {dt_str}
                            </span>
                        </div>
                        <div style="color:#64748b;font-size:12px;">{wcount:,} words</div>
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(5,1fr);
                                gap:8px;padding:10px;background:#0f172a;border-radius:8px;">
                        {metrics_html}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            if total_analyses > 5:
                st.markdown(f"""
                <div style="text-align:center;color:#475569;font-size:12px;padding:8px;">
                    + {total_analyses - 5} older analyses not shown
                </div>
                """, unsafe_allow_html=True)

    # ── Right: Quick tips + CTA ──
    with col_right:
        st.markdown("""
        <div style="font-size:15px;font-weight:600;color:#e2e8f0;margin-bottom:14px;">
            💡 Readability Tips
        </div>
        """, unsafe_allow_html=True)

        tips = [
            ("🟢", "Aim for Flesch Ease above 60 for general public readability."),
            ("🔵", "Keep sentences under 20 words to reduce complexity."),
            ("🟡", "A Gunning Fog score below 12 suits most adult readers."),
            ("🔴", "Avoid jargon — replace complex words with simpler alternatives."),
            ("⚪", "Use active voice to make policy text feel more direct."),
        ]
        for dot, tip in tips:
            st.markdown(f"""
            <div style="background:#111827;border:1px solid #1e293b;border-radius:10px;
                        padding:12px 14px;margin-bottom:8px;display:flex;gap:10px;
                        align-items:flex-start;">
                <span style="font-size:14px;flex-shrink:0;">{dot}</span>
                <span style="color:#94a3b8;font-size:13px;line-height:1.5;">{tip}</span>
            </div>
            """, unsafe_allow_html=True)

        # CTA box
        st.markdown("""
        <div style="background:linear-gradient(135deg,#1e1b4b,#1a1f35);
                    border:1px solid #3730a3;border-radius:12px;
                    padding:20px;margin-top:16px;text-align:center;">
            <div style="font-size:28px;margin-bottom:8px;">📖</div>
            <div style="color:#e2e8f0;font-size:14px;font-weight:600;margin-bottom:6px;">
                Ready to analyze?
            </div>
            <div style="color:#64748b;font-size:12px;">
                Head to the Readability tab to paste or upload your policy text.
            </div>
        </div>
        """, unsafe_allow_html=True)

# ============================================================
# PAGE: ADMIN
# ============================================================
def admin_page(email):
    if email != ADMIN_EMAIL:
        st.error("⛔ Access Denied"); return

    section_header("🛡️", "Admin Control Panel", "Manage users, monitor security & activity")
    st.markdown("---")

    cursor.execute("SELECT id, username, email, created_at FROM users")
    all_users = cursor.fetchall()
    cursor.execute("SELECT email, attempts, last_attempt FROM login_attempts")
    lockout_rows = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM password_history")
    pw_count = cursor.fetchone()[0]

    non_admin   = [u for u in all_users if u[2] != ADMIN_EMAIL]
    locked_now  = sum(1 for _,att,last in lockout_rows
                      if att >= MAX_LOGIN_ATTEMPTS and (time.time()-last) < LOCK_TIME)

    k1,k2,k3,k4 = st.columns(4)
    kpi_card(k1, "👥", "Total Users",           len(all_users), "#6366f1")
    kpi_card(k2, "🙋", "Regular Users",          len(non_admin), "#0ea5e9")
    kpi_card(k3, "🔒", "Locked Accounts",        locked_now,     "#f59e0b")
    kpi_card(k4, "🔑", "Password Changes Logged",pw_count,       "#10b981")

    st.markdown("<br>", unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["👥  User Management", "🔒  Security Monitor", "🔍  Search User"])

    # ── TAB 1: User Management ──
    with tab1:
        st.markdown("<br>", unsafe_allow_html=True)
        # Table header
        st.markdown("""
        <div style="display:grid;grid-template-columns:40px 1fr 1.6fr 1fr 60px;
                    gap:12px;padding:8px 16px;background:#0f172a;border-radius:8px;
                    color:#475569;font-size:12px;font-weight:600;text-transform:uppercase;
                    letter-spacing:0.5px;margin-bottom:6px;">
            <div>#</div><div>Username</div><div>Email</div><div>Joined</div><div>Act</div>
        </div>
        """, unsafe_allow_html=True)

        for uid, uname, uemail, joined in all_users:
            is_adm = (uemail == ADMIN_EMAIL)
            badge  = " <span style='background:#6366f1;color:white;font-size:10px;padding:2px 6px;border-radius:20px;font-weight:600;'>ADMIN</span>" if is_adm else ""
            c1,c2,c3,c4,c5 = st.columns([0.5,1.5,2,1.5,0.7])
            c1.markdown(f"<span style='color:#475569;font-size:13px;'>{uid}</span>", unsafe_allow_html=True)
            c2.markdown(f"<span style='color:#e2e8f0;font-size:13px;font-weight:500;'>{uname}</span>{badge}", unsafe_allow_html=True)
            c3.markdown(f"<span style='color:#94a3b8;font-size:13px;'>{uemail}</span>", unsafe_allow_html=True)
            c4.markdown(f"<span style='color:#475569;font-size:12px;'>{joined if joined and joined!='N/A' else '—'}</span>", unsafe_allow_html=True)
            if not is_adm:
                if c5.button("🗑️", key=f"del_{uemail}", help=f"Delete {uemail}"):
                    cursor.execute("DELETE FROM users WHERE email=?", (uemail,))
                    cursor.execute("DELETE FROM password_history WHERE email=?", (uemail,))
                    cursor.execute("DELETE FROM login_attempts WHERE email=?", (uemail,))
                    conn.commit()
                    st.toast(f"Deleted {uemail}", icon="🗑️")
                    time.sleep(0.4); st.rerun()

    # ── TAB 2: Security Monitor ──
    with tab2:
        st.markdown("<br>", unsafe_allow_html=True)
        if not lockout_rows:
            st.markdown("""
            <div style="text-align:center;padding:40px;color:#475569;">
                <div style="font-size:36px;margin-bottom:12px;">✅</div>
                <div style="font-size:15px;">No suspicious login activity detected</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="display:grid;grid-template-columns:1.8fr 80px 1fr 120px;
                        gap:12px;padding:8px 16px;background:#0f172a;border-radius:8px;
                        color:#475569;font-size:12px;font-weight:600;text-transform:uppercase;
                        letter-spacing:0.5px;margin-bottom:6px;">
                <div>Email</div><div>Attempts</div><div>Last Seen</div><div>Status</div>
            </div>
            """, unsafe_allow_html=True)

            for lemail, att, last in lockout_rows:
                elapsed    = time.time() - last
                locked_acc = att >= MAX_LOGIN_ATTEMPTS and elapsed < LOCK_TIME
                rem        = max(0, int(LOCK_TIME - elapsed))
                last_dt    = datetime.datetime.fromtimestamp(last).strftime("%H:%M  %d %b")
                status_html= (f"<span style='background:#451a03;color:#f59e0b;font-size:11px;"
                              f"padding:3px 10px;border-radius:20px;font-weight:600;'>🔒 Locked ({rem}s)</span>"
                              if locked_acc else
                              "<span style='background:#052e16;color:#34d399;font-size:11px;"
                              "padding:3px 10px;border-radius:20px;font-weight:600;'>✓ Active</span>")
                att_color  = "#f87171" if att >= MAX_LOGIN_ATTEMPTS else "#94a3b8"

                c1,c2,c3,c4 = st.columns([1.8,0.8,1,1.2])
                c1.markdown(f"<span style='color:#94a3b8;font-size:13px;'>{lemail}</span>",unsafe_allow_html=True)
                c2.markdown(f"<span style='color:{att_color};font-weight:700;font-size:14px;'>{att}</span>",unsafe_allow_html=True)
                c3.markdown(f"<span style='color:#475569;font-size:12px;'>{last_dt}</span>",unsafe_allow_html=True)
                c4.markdown(status_html, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔓  Clear All Lockouts", use_container_width=True):
            cursor.execute("DELETE FROM login_attempts")
            conn.commit()
            st.success("All lockouts cleared.")
            time.sleep(0.4); st.rerun()

    # ── TAB 3: Search User ──
    with tab3:
        st.markdown("<br>", unsafe_allow_html=True)
        q = st.text_input("Search by username or email", placeholder="e.g. john or john@example.com")
        if q:
            cursor.execute(
                "SELECT id,username,email,security_question,created_at FROM users "
                "WHERE email LIKE ? OR username LIKE ?",
                (f"%{q}%", f"%{q}%")
            )
            results = cursor.fetchall()
            if not results:
                st.warning("No matching users found.")
            else:
                for r_id, r_name, r_email, r_sq, r_joined in results:
                    cursor.execute("SELECT COUNT(*) FROM password_history WHERE email=?", (r_email,))
                    pw_c = cursor.fetchone()[0]
                    cursor.execute("SELECT attempts,last_attempt FROM login_attempts WHERE email=?", (r_email,))
                    la   = cursor.fetchone()
                    att_n, status_tag = (0, "✓ Active")
                    if la:
                        att_n = la[0]
                        e2    = time.time()-la[1]
                        status_tag = "🔒 Locked" if att_n>=MAX_LOGIN_ATTEMPTS and e2<LOCK_TIME else "✓ Active"
                    initials2 = r_name[:2].upper()
                    is_adm2   = (r_email == ADMIN_EMAIL)

                    st.markdown(f"""
                    <div class="pn-card" style="margin-bottom:12px;">
                        <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
                            <div style="background:#{'6366f1' if is_adm2 else '1e293b'};
                                        border-radius:50%;width:44px;height:44px;
                                        display:flex;align-items:center;justify-content:center;
                                        font-weight:700;font-size:15px;color:white;flex-shrink:0;">
                                {initials2}
                            </div>
                            <div>
                                <div style="font-weight:600;font-size:15px;color:#e2e8f0;">
                                    {r_name} {"👑" if is_adm2 else ""}
                                </div>
                                <div style="color:#475569;font-size:13px;">{r_email}</div>
                            </div>
                            <div style="margin-left:auto;color:#64748b;font-size:12px;">{status_tag}</div>
                        </div>
                        <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;
                                    gap:12px;padding:12px;background:#0f172a;border-radius:10px;">
                            <div style="text-align:center;">
                                <div style="color:#64748b;font-size:11px;">User ID</div>
                                <div style="color:#6366f1;font-weight:700;font-size:16px;">#{r_id}</div>
                            </div>
                            <div style="text-align:center;">
                                <div style="color:#64748b;font-size:11px;">Pw Changes</div>
                                <div style="color:#10b981;font-weight:700;font-size:16px;">{pw_c}</div>
                            </div>
                            <div style="text-align:center;">
                                <div style="color:#64748b;font-size:11px;">Failed Logins</div>
                                <div style="color:#f59e0b;font-weight:700;font-size:16px;">{att_n}</div>
                            </div>
                            <div style="text-align:center;">
                                <div style="color:#64748b;font-size:11px;">Joined</div>
                                <div style="color:#94a3b8;font-weight:600;font-size:13px;">
                                    {r_joined if r_joined and r_joined!='N/A' else '—'}
                                </div>
                            </div>
                        </div>
                        <div style="margin-top:10px;color:#475569;font-size:12px;">
                            🔐 Security Q: {r_sq}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if not is_adm2:
                        if st.button(f"Delete {r_name}", key=f"sdel_{r_email}"):
                            cursor.execute("DELETE FROM users WHERE email=?", (r_email,))
                            cursor.execute("DELETE FROM password_history WHERE email=?", (r_email,))
                            cursor.execute("DELETE FROM login_attempts WHERE email=?", (r_email,))
                            conn.commit()
                            st.toast(f"Deleted {r_email}", icon="🗑️")
                            time.sleep(0.4); st.rerun()

# ============================================================
# PAGE: READABILITY
# ============================================================
def readability_page(email=None):
    section_header("📖", "Readability Analyzer", "Measure how accessible your policy text is")
    st.markdown("---")

    tab1, tab2 = st.tabs(["✍️  Paste Text", "📂  Upload File"])
    text_input = ""

    with tab1:
        raw = st.text_area("Paste your policy text here (minimum 50 characters):", height=200)
        if raw: text_input = raw

    with tab2:
        uploaded = st.file_uploader("Upload a .txt or .pdf file", type=["txt","pdf"])
        if uploaded:
            try:
                if uploaded.type == "application/pdf":
                    reader     = PyPDF2.PdfReader(uploaded)
                    text_input = "\n".join(p.extract_text() or "" for p in reader.pages)
                    st.info(f"✅ Loaded {len(reader.pages)} page(s) from PDF.")
                else:
                    text_input = uploaded.read().decode("utf-8")
                    st.info(f"✅ Loaded: {uploaded.name}")
            except Exception as ex:
                st.error(f"Error reading file: {ex}")

    if st.button("Analyze →", use_container_width=True):
        if len(text_input.strip()) < 50:
            st.error("⚠️ Text too short — minimum 50 characters.")
        else:
            with st.spinner("Analyzing..."):
                scores, stats = get_readability_metrics(text_input)

            avg = (scores["Flesch-Kincaid Grade"]+scores["Gunning Fog"]+
                   scores["SMOG Index"]+scores["Coleman-Liau"])/4

            if   avg<=6:  level,accent = "Beginner",       "#34d399"
            elif avg<=10: level,accent = "Intermediate",    "#38bdf8"
            elif avg<=14: level,accent = "Advanced",        "#fbbf24"
            else:         level,accent = "Expert/Academic", "#f87171"

            # ── Save to history ──
            if email:
                now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""INSERT INTO analysis_history
                    (email,analyzed_at,char_count,word_count,avg_grade,level,
                     flesch_ease,fk_grade,smog,gunning_fog,coleman)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (email, now_str,
                     stats["Characters"], stats["Words"], round(avg,2), level,
                     round(scores["Flesch Reading Ease"],2),
                     round(scores["Flesch-Kincaid Grade"],2),
                     round(scores["SMOG Index"],2),
                     round(scores["Gunning Fog"],2),
                     round(scores["Coleman-Liau"],2))
                )
                conn.commit()

            st.markdown("<br>", unsafe_allow_html=True)

            # Overall banner
            st.markdown(f"""
            <div style="background:#111827;border:1px solid {accent};border-radius:14px;
                        padding:24px;text-align:center;margin-bottom:24px;
                        box-shadow:0 0 30px {accent}18;">
                <div style="color:{accent};font-size:13px;font-weight:600;
                            text-transform:uppercase;letter-spacing:1px;">Overall Readability Level</div>
                <div style="color:{accent};font-size:36px;font-weight:700;margin:8px 0;">{level}</div>
                <div style="color:#475569;font-size:14px;">Approximate Grade Level: {int(avg)}</div>
            </div>
            """, unsafe_allow_html=True)

            # Gauges
            st.markdown("#### Metric Breakdown")
            c1,c2,c3 = st.columns(3)
            gauge_data = [
                (c1, scores["Flesch Reading Ease"],  "Flesch Reading Ease",  0, 100, "#6366f1"),
                (c2, scores["Flesch-Kincaid Grade"], "Flesch-Kincaid Grade", 0, 20,  "#0ea5e9"),
                (c3, scores["SMOG Index"],           "SMOG Index",           0, 20,  "#f59e0b"),
            ]
            for col, val, title, mn, mx, clr in gauge_data:
                col.plotly_chart(create_gauge(val,title,mn,mx,clr), use_container_width=True)

            c4,c5 = st.columns(2)
            for col, val, title, mn, mx, clr in [
                (c4, scores["Gunning Fog"],  "Gunning Fog",  0, 20, "#10b981"),
                (c5, scores["Coleman-Liau"],"Coleman-Liau", 0, 20, "#ec4899"),
            ]:
                col.plotly_chart(create_gauge(val,title,mn,mx,clr), use_container_width=True)

            # Stats row
            st.markdown("#### Text Statistics")
            s1,s2,s3,s4,s5 = st.columns(5)
            for col,label,val in [
                (s1,"Sentences",    stats["Sentences"]),
                (s2,"Words",        stats["Words"]),
                (s3,"Syllables",    stats["Syllables"]),
                (s4,"Complex Words",stats["Complex Words"]),
                (s5,"Characters",   stats["Characters"]),
            ]:
                col.metric(label, val)

# ============================================================
# PAGE: LOGIN
# ============================================================
# ============================================================
# WELCOME SCREEN  (reused by both login and signup)
# ============================================================
def show_welcome_screen(username, is_new=False):
    greeting = "Welcome to PolicyNav," if is_new else "Welcome back,"
    emoji    = "🎉" if is_new else "⚡"
    ph = st.empty()
    ph.markdown(f"""
    <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;
                background:#0a0e1a;z-index:9999;display:flex;
                align-items:center;justify-content:center;">
        <div style="text-align:center;">
            <div style="font-size:52px;margin-bottom:16px;">{emoji}</div>
            <div style="color:#475569;font-size:13px;font-weight:600;
                        text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">
                {greeting}
            </div>
            <div style="color:#f1f5f9;font-size:32px;font-weight:700;margin-bottom:24px;">
                Hello, {username}!
            </div>
            <div style="width:200px;height:3px;background:#1e293b;
                        border-radius:99px;margin:0 auto;overflow:hidden;">
                <div style="height:100%;width:0;background:linear-gradient(90deg,#6366f1,#818cf8);
                            border-radius:99px;animation:bar 2s ease forwards;">
                </div>
            </div>
            <div style="color:#334155;font-size:13px;margin-top:12px;">
                {"Setting up your dashboard..." if is_new else "Loading your dashboard..."}
            </div>
        </div>
    </div>
    <style>
    @keyframes bar {{
        from {{ width: 0; }}
        to   {{ width: 100%; }}
    }}
    </style>
    """, unsafe_allow_html=True)
    time.sleep(2)
    ph.empty()

# ============================================================
# PAGE: LOGIN
# ============================================================
def login_page():
    _, mid, _ = st.columns([1,1.4,1])
    with mid:
        auth_header("Sign in to your account", "Public Policy Navigation Platform")

        email    = st.text_input("Email address", placeholder="you@example.com")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("Sign In →", use_container_width=True):
            locked, wait = is_locked(email)
            if locked:
                st.error(f"⛔ Account locked. Try again in {wait}s.")
                return

            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

            if not user:
                st.error("No account found with that email.")
            elif not bcrypt.checkpw(password.encode(), user[3]):
                record_fail(email)
                cursor.execute("SELECT password FROM password_history WHERE email=?", (email,))
                for (old_hash,) in cursor.fetchall():
                    if bcrypt.checkpw(password.encode(), old_hash):
                        st.warning("⚠️ That's an old password. Please use your current one.")
                        return
                st.error("Incorrect password.")
            else:
                reset_attempts(email)
                st.session_state.token = create_token(email)
                cursor.execute("SELECT username FROM users WHERE email=?", (email,))
                r     = cursor.fetchone()
                uname = r[0] if r else email.split("@")[0]
                show_welcome_screen(uname, is_new=False)
                st.rerun()

        divider_text("or")
        c1,c2 = st.columns(2)
        if c1.button("Create Account", use_container_width=True):
            st.session_state.page = "signup"; st.rerun()
        if c2.button("Forgot Password", use_container_width=True):
            st.session_state.page = "forgot"; st.rerun()

# ============================================================
# PAGE: SIGNUP
# ============================================================
def signup_page():
    _, mid, _ = st.columns([1,1.6,1])
    with mid:
        auth_header("Create an account", "Join PolicyNav today")

        username  = st.text_input("Full name / Username", placeholder="John Doe")
        email     = st.text_input("Email address", placeholder="you@example.com")
        password  = st.text_input("Password", type="password", placeholder="Min. 8 characters")

        if password:
            st.markdown(pw_strength_html(password), unsafe_allow_html=True)

        confirm   = st.text_input("Confirm password", type="password", placeholder="Re-enter password")
        sec_q     = st.selectbox("Security question", [
            "What is your pet name?",
            "What is your mother's maiden name?",
            "What is your favourite teacher?"
        ])
        sec_a     = st.text_input("Your answer", placeholder="Answer to security question")

        st.markdown("<br>", unsafe_allow_html=True)

        if st.button("Create Account →", use_container_width=True):
            u,e,a = username.strip(), email.strip(), sec_a.strip()
            if not u:                       st.error("Username required.")
            elif not e:                     st.error("Email required.")
            elif not valid_email(e):        st.error("Invalid email format.")
            elif not password:              st.error("Password required.")
            elif not confirm:               st.error("Please confirm your password.")
            elif not a:                     st.error("Security answer required.")
            elif password != confirm:       st.error("Passwords do not match.")
            else:
                strength, fb = check_password_strength(password)
                if strength == "Weak":
                    st.error(f"Password too weak — {', '.join(fb)}")
                else:
                    cursor.execute("SELECT 1 FROM users WHERE email=?", (e,))
                    if cursor.fetchone():
                        st.error("An account with that email already exists.")
                    else:
                        ok, msg = send_otp(e)
                        if ok:
                            st.session_state.signup_data = (u,e,password,sec_q,a)
                            st.session_state.otp_stage   = "signup"
                            st.success("Verification code sent to your email!")
                        else:
                            st.error(f"Could not send email: {msg}")

        if st.session_state.get("otp_stage") == "signup":
            divider_text("enter verification code")
            entered = st.text_input("6-digit code", max_chars=6, placeholder="000000")
            if st.button("Verify & Finish →", use_container_width=True):
                valid, vmsg = verify_otp_token(
                    st.session_state.otp_token, entered,
                    st.session_state.signup_data[1]
                )
                if valid:
                    u,e,pwd,sq,sa = st.session_state.signup_data
                    hp = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
                    cursor.execute(
                        "INSERT INTO users (username,email,password,security_question,security_answer) VALUES (?,?,?,?,?)",
                        (u,e,hp,sq,sa)
                    )
                    cursor.execute("INSERT INTO password_history (email,password) VALUES (?,?)", (e,hp))
                    conn.commit()
                    st.session_state.token     = create_token(e)
                    st.session_state.otp_stage = None
                    show_welcome_screen(u, is_new=True)
                    st.rerun()
                else:
                    st.error(f"Verification failed: {vmsg}")

        divider_text("already have an account?")
        if st.button("Back to Sign In", use_container_width=True):
            st.session_state.page = "login"; st.rerun()

# ============================================================
# PAGE: FORGOT PASSWORD
# ============================================================
def forgot_page():
    _, mid, _ = st.columns([1,1.4,1])
    with mid:
        auth_header("Reset your password", "We'll verify your identity first")

        email = st.text_input("Registered email address", placeholder="you@example.com")

        if st.button("Continue →", use_container_width=True):
            cursor.execute("SELECT security_question FROM users WHERE email=?", (email,))
            res = cursor.fetchone()
            if res:
                st.session_state.reset_email       = email
                st.session_state.security_question = res[0]
                st.session_state.otp_stage         = "security"
            else:
                st.error("No account found with that email.")

        if st.session_state.otp_stage == "security":
            divider_text("security question")
            st.markdown(f"""
            <div style="background:#111827;border:1px solid #1e293b;border-radius:10px;
                        padding:14px 16px;color:#94a3b8;font-size:14px;margin-bottom:12px;">
                🔐 {st.session_state.security_question}
            </div>
            """, unsafe_allow_html=True)
            answer = st.text_input("Your answer", placeholder="Enter your answer")
            if st.button("Verify Answer →", use_container_width=True):
                cursor.execute("SELECT security_answer FROM users WHERE email=?", (st.session_state.reset_email,))
                if answer == cursor.fetchone()[0]:
                    ok, msg = send_otp(st.session_state.reset_email)
                    if ok:
                        st.session_state.otp_stage = "otp"
                        st.success("Verification code sent!")
                    else:
                        st.error(f"Could not send email: {msg}")
                else:
                    st.error("Incorrect answer.")

        if st.session_state.otp_stage == "otp":
            divider_text("enter verification code")
            entered = st.text_input("6-digit code", max_chars=6, placeholder="000000")
            if st.button("Verify Code →", use_container_width=True):
                valid, vmsg = verify_otp_token(
                    st.session_state.otp_token, entered, st.session_state.reset_email
                )
                if valid:
                    st.session_state.otp_stage = "reset"
                else:
                    st.error(f"Verification failed: {vmsg}")

        if st.session_state.otp_stage == "reset":
            divider_text("set new password")
            new_pw  = st.text_input("New password", type="password", placeholder="Min. 8 characters")
            if new_pw:
                st.markdown(pw_strength_html(new_pw), unsafe_allow_html=True)
            conf_pw = st.text_input("Confirm new password", type="password", placeholder="Re-enter password")

            if st.button("Update Password →", use_container_width=True):
                if new_pw != conf_pw:
                    st.error("Passwords do not match.")
                else:
                    cursor.execute("SELECT password FROM password_history WHERE email=?",
                                   (st.session_state.reset_email,))
                    for (old_hash,) in cursor.fetchall():
                        if bcrypt.checkpw(new_pw.encode(), old_hash):
                            st.error("⚠️ You cannot reuse a previous password.")
                            st.stop()
                    strength, _ = check_password_strength(new_pw)
                    if strength == "Weak":
                        st.error("Password is too weak.")
                    else:
                        hp = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
                        cursor.execute("UPDATE users SET password=? WHERE email=?",
                                       (hp, st.session_state.reset_email))
                        cursor.execute("INSERT INTO password_history (email,password) VALUES (?,?)",
                                       (st.session_state.reset_email, hp))
                        conn.commit()
                        st.success("✅ Password updated! Redirecting to login...")
                        st.session_state.otp_stage = None
                        st.session_state.page      = "login"
                        time.sleep(1.5); st.rerun()

        divider_text("")
        if st.button("← Back to Sign In", use_container_width=True):
            st.session_state.page      = "login"
            st.session_state.otp_stage = None
            st.rerun()

# ============================================================
# MAIN ROUTER
# ============================================================
if st.session_state.token:
    dashboard()
else:
    if   st.session_state.page == "signup": signup_page()
    elif st.session_state.page == "forgot": forgot_page()
    else:                                   login_page()
