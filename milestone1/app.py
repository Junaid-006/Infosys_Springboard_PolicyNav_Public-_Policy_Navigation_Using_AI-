import streamlit as st
import sqlite3
import re
import jwt
import datetime
import bcrypt
import time

# ---------------- CONFIG ----------------
SECRET_KEY = "policy_nav_secret_key"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

st.set_page_config(page_title="PolicyNav", layout="centered")

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
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRE_MINUTES)
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

st.title("PolicyNav – Secure User Authentication System")

# ---------------- DASHBOARD ----------------
def dashboard():
    email = verify_token(st.session_state.token)

    if not email:
        st.session_state.token = None
        st.session_state.page = "login"
        st.rerun()

    cursor.execute("SELECT username FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    st.success("Login Successful")
    st.subheader(f"Welcome {user[0]} 🎉")

    if st.button("Logout"):
        st.session_state.token = None
        st.session_state.page = "login"
        st.rerun()

# ---------------- SIGNUP ----------------
def signup_page():
    st.subheader("Signup")

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

    if st.button("Create Account"):

        if not username or not email or not password or not confirm_password or not security_answer:
            st.error("All fields are mandatory")

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
                st.success("Account created successfully!")
                time.sleep(1)
                st.rerun()

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# ---------------- LOGIN ----------------
def login_page():
    st.subheader("Login")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):

        if not email or not password:
            st.error("Nothing entered")
        else:
            cursor.execute("SELECT * FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode(), user[3]):
                st.session_state.token = create_token(email)
                st.success("Login successful")
                time.sleep(1)
                st.rerun()
            else:
                st.error("Invalid credentials")

    if st.button("Create Account"):
        st.session_state.page = "signup"
        st.rerun()

    if st.button("Forgot Password"):
        st.session_state.page = "forgot"
        st.rerun()

# ---------------- FORGOT PASSWORD ----------------
def forgot_password():
    st.subheader("Forgot Password")

    if "email_verified" not in st.session_state:
        st.session_state.email_verified = False

    email = st.text_input("Enter Email")

    if st.button("Verify Email"):
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()

        if user:
            st.session_state.email_verified = True
            st.session_state.reset_email = email
            st.success("Email verified")
        else:
            st.error("Email not found")

    # 🔵 Show reset section only if verified
    if st.session_state.email_verified:

        cursor.execute("SELECT * FROM users WHERE email=?", (st.session_state.reset_email,))
        user = cursor.fetchone()

        st.info(user[4])  # Show security question

        answer = st.text_input("Security Answer")
        new_password = st.text_input("New Password", type="password")

        if st.button("Reset Password"):

            if answer == user[5] and valid_password(new_password):
                hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                cursor.execute(
                    "UPDATE users SET password=? WHERE email=?",
                    (hashed_pw, st.session_state.reset_email)
                )
                conn.commit()

                st.success("Password updated successfully")

                # Reset flags
                st.session_state.email_verified = False
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error("Incorrect answer or invalid password")

    if st.button("Back to Login"):
        st.session_state.email_verified = False
        st.session_state.page = "login"
        st.rerun()

# ---------------- MAIN ROUTING ----------------
if st.session_state.token:
    dashboard()
else:
    if st.session_state.page == "signup":
        signup_page()
    elif st.session_state.page == "forgot":
        forgot_password()
    else:
        login_page()
