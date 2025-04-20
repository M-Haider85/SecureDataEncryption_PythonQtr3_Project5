import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


# Data information of user

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60


# Login details section

if  "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# If data is load
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# If data is save
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)


def generate_key(passkey):
    key = pbkdf2_hmac(
        "sha256",
        passkey.encode(),
        SALT,
        100000,
    )
    return urlsafe_b64encode(key)


def hash_password(password):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        SALT,
        100000,
    ).hex()


# cryptography.fernet used

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()


def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()


# Navigation bar

st.title("Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the Secure Data Encryption System using Streamlit")
    st.markdown("""
        Develop a Streamlit-based secure data storage and retrieval system where:
        - Users store data with a unique passkey.
        - Users decrypt data by providing the correct passkey.
        - Multiple failed attempts result in a forced reauthorization (login page).
        - The system operates entirely in memory without external databases.
    """)

# user registration

elif choice == "Register":
    st.subheader("Register a New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.error("❌ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Please fill in all fields!")

    elif choice == "Login":
        st.subheader("Login to Your Account")       

        if time.time() < st.session_state.lockout_time:
            remaining =  int(st.session_state.lockout_time - time.time())
            st.error(f"❌ Too many failed attempts! Please wait {remaining} seconds.")
            st.stop()


        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome {username}!")    
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials! {remaining} attempts left.")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error(f"❌ Too many failed attempts! Please wait {LOCKOUT_DURATION} seconds.")
                    st.stop()


# Store data section

elif choice == "Store Data":
     if not st.session_state.authenticated_user:
        st.error("Please log in to store data.")
     else:
        st.subheader("Store Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted & saved successfully!")
            else:
                st.error("Please fill in all fields!")                  


# Retrieve data section
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.error("Please log in to retrieve data.")
    else:
        st.subheader("Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data Found!")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

                encrypted_input = st.text_area("Enter Encrypted text to decrypt")
                passkey = st.text_input("Enter Passkey to Decrypt", type="password")

                if st.button(f"Decrypt Entry"):
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success(f"✅ Decrypted Data: {result}")
                    else:
                        st.error("❌ Decryption failed! Incorrect passkey or corrupted data.")
                
