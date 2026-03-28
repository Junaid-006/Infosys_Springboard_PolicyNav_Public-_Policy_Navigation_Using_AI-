import streamlit as st
import sqlite3
import re
import jwt
import datetime
import bcrypt
import time

# ---------------- CONFIG ----------------
SECRET_KEY = "policy_nav_secure_secret_key_123456"
ALGORITHM = "HS256"

st.set_page_config(page_title="PolicyNav", layout="centered")

# ---------------- CLEAN MODERN UI ----------------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #0f172a, #1e293b);
}

.block-container {
    padding-top: 4rem;
}

h1 {
    font-size: 38px !important;
    font-weight: 700 !important;
    color: #f8fafc !important;
    text-align: center;
}

h3 {
    font-size: 22px !important;
    font-weight: 600 !important;
    color: #e2e8f0 !important;
    text-align: center;
}

.stTextInput>div>div>input {
    border-radius: 8px !important;
    padding: 10px !important;
    transition: 0.2s ease !important;
}

.stTextInput>div>div>input:focus {
    border: 1px solid #3b82f6 !important;
    box-shadow: 0 0 6px rgba(59,130,246,0.4) !important;
}

.stButton>button {
    border-radius: 8px;
    padding: 10px;
    font-weight: 600;
    background: linear-gradient(90deg, #3b82f6, #2563eb);
    color: white;
    border: none;
    transition: 0.25s ease;
}

.stButton>button:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 18px rgba(37,99,235,0.4);
}

.stButton>button:active {
    transform: scale(0.96);
}
</style>
""", unsafe_allow_html=True)

# ---------------- DATABASE ----------------
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password BLOB NOT NULL,
    security_question TEXT NOT NULL,
    security_answer TEXT NOT NULL
)
""")
conn.commit()

# ---------------- JWT ----------------
def create_token(email):
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {"email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded["email"]
    except:
        return None

# ---------------- VALIDATION ----------------
def valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.fullmatch(pattern, email))

def valid_password(password):
    return password.isalnum()

# ---------------- SESSION ----------------
if "token" not in st.session_state:
    st.session_state.token = None

if "page" not in st.session_state:
    st.session_state.page = "login"

if "verified" not in st.session_state:
    st.session_state.verified = False

if "allow_reset" not in st.session_state:
    st.session_state.allow_reset = False

# ---------------- DASHBOARD ----------------
def dashboard():
    email = verify_token(st.session_state.token)
    if not email:
        st.session_state.token = None
        st.session_state.page = "login"
        st.rerun()

    cursor.execute("SELECT username FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    st.title("PolicyNav – User Authentication System")
    st.success(f"Welcome {user[0]} 🚀")

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if st.button("Logout", use_container_width=True):
            st.session_state.token = None
            st.session_state.page = "login"
            st.rerun()

# ---------------- LOGIN ----------------
def login_page():
    st.title("PolicyNav – User Authentication System")
    st.subheader("Login")

    email = st.text_input("Email ID")
    password = st.text_input("Password", type="password")

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        login_clicked = st.button("Login", use_container_width=True)

    if login_clicked:
        if not email or not password:
            st.error("Please enter both Email and Password")
        else:
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

            if not user:
                st.error("Email does not exist")
            elif not bcrypt.checkpw(password.encode(), user[3]):
                st.error("Incorrect password")
            else:
                st.session_state.token = create_token(email)
                st.success("Login successful")
                time.sleep(1)
                st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if st.button("Create Account", use_container_width=True):
            st.session_state.page = "signup"
            st.rerun()

        if st.button("Forgot Password", use_container_width=True):
            st.session_state.page = "forgot"
            st.rerun()

# ---------------- SIGNUP ----------------
def signup_page():
    st.title("PolicyNav – User Authentication System")
    st.subheader("Create Account")

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    security_question = st.selectbox(
        "Security Question",
        ["What is your pet name?",
         "What is your mother’s maiden name?",
         "What is your favorite teacher?"]
    )

    security_answer = st.text_input("Security Answer")

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        register_clicked = st.button("Register", use_container_width=True)

    if register_clicked:
        if not username or not email or not password or not confirm_password or not security_answer:
            st.error("All fields mandatory")
        elif not valid_email(email):
            st.error("Invalid email format")
        elif not valid_password(password):
            st.error("Password must be alphanumeric")
        elif password != confirm_password:
            st.error("Passwords do not match")
        else:
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            if cursor.fetchone():
                st.error("Email already exists")
            else:
                hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                cursor.execute("""
                    INSERT INTO users (username,email,password,security_question,security_answer)
                    VALUES (?,?,?,?,?)
                """, (username,email,hashed_pw,security_question,security_answer))
                conn.commit()

                st.session_state.token = create_token(email)
                st.success("Account created successfully")
                time.sleep(1)
                st.rerun()

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if st.button("Back to Login", use_container_width=True):
            st.session_state.page = "login"
            st.rerun()

# ---------------- FORGOT PASSWORD ----------------
def forgot_page():
    st.title("PolicyNav – User Authentication System")
    st.subheader("Reset Password")

    email = st.text_input("Enter your registered Email")

    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        verify_email_clicked = st.button("Verify Email", use_container_width=True)

    if verify_email_clicked:
        cursor.execute("SELECT security_question FROM users WHERE email=?", (email,))
        result = cursor.fetchone()

        if result:
            st.session_state.reset_email = email
            st.session_state.security_question = result[0]
            st.session_state.verified = True
        else:
            st.error("Email not found")

    if st.session_state.get("verified", False):
        st.info(st.session_state.security_question)
        answer = st.text_input("Enter your Answer")

        st.markdown("<br>", unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            verify_answer_clicked = st.button("Verify Answer", use_container_width=True)

        if verify_answer_clicked:
            cursor.execute(
                "SELECT security_answer FROM users WHERE email=?",
                (st.session_state.reset_email,)
            )
            correct_answer = cursor.fetchone()[0]

            if answer == correct_answer:
                st.session_state.allow_reset = True
            else:
                st.error("Incorrect answer")

    if st.session_state.get("allow_reset", False):
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm New Password", type="password")

        st.markdown("<br>", unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1,2,1])
        with col2:
            update_clicked = st.button("Update Password", use_container_width=True)

        if update_clicked:
            if not new_password or not confirm_password:
                st.error("Fill all fields")
            elif new_password != confirm_password:
                st.error("Passwords do not match")
            elif not valid_password(new_password):
                st.error("Password must be alphanumeric")
            else:
                hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                cursor.execute(
                    "UPDATE users SET password=? WHERE email=?",
                    (hashed_pw, st.session_state.reset_email)
                )
                conn.commit()

                st.success("Password updated successfully")
                time.sleep(1)

                st.session_state.verified = False
                st.session_state.allow_reset = False
                st.session_state.page = "login"
                st.rerun()

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        if st.button("Back to Login", use_container_width=True):
            st.session_state.page = "login"
            st.rerun()

# ---------------- MAIN ----------------
if st.session_state.token:
    dashboard()
else:
    if st.session_state.page == "signup":
        signup_page()
    elif st.session_state.page == "forgot":
        forgot_page()
    else:
        login_page()
