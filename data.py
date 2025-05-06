import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# ------------------ Setup ------------------ #
st.set_page_config(page_title="Secure Data Vault", page_icon="🛡️")

# Initialize session state variables
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.fernet = Fernet(st.session_state.fernet_key)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# ------------------ Helper Functions ------------------ #
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data):
    return st.session_state.fernet.encrypt(data.encode()).decode()

def decrypt_data(cipher_text):
    return st.session_state.fernet.decrypt(cipher_text.encode()).decode()

def login_page():
    st.markdown("## 🔐 Reauthorization Required")
    st.info("You’ve exceeded the maximum number of allowed attempts. Please log in again.")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if username == "admin" and password == "admin123":
                st.session_state.login_attempts = 0
                st.session_state.authorized = True
                st.success("✅ Login successful. Please go back to the menu.")
            else:
                st.error("❌ Invalid credentials.")

# ------------------ Pages ------------------ #
def home():
    st.markdown("## 🛡️ Welcome to the Secure Data Encryption System")
    st.markdown("Use the sidebar to navigate between pages.")
    st.image("https://cdn-icons-png.flaticon.com/512/942/942833.png", width=150)

def insert_data_page():
    st.markdown("## 📥 Insert New Secure Data")
    st.markdown("Store your sensitive information safely.")

    with st.form("insert_form"):
        key = st.text_input("🔑 Key/Label (unique)")
        data = st.text_area("📝 Data to Encrypt")
        passkey = st.text_input("🔐 Create a Passkey", type="password")
        submitted = st.form_submit_button("Encrypt & Save")

        if submitted:
            if key in st.session_state.stored_data:
                st.warning("⚠️ Key already exists. Choose another.")
            elif key and data and passkey:
                encrypted = encrypt_data(data)
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[key] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed_passkey
                }
                st.success(f"✅ Data securely stored under key: `{key}`")
            else:
                st.error("❌ All fields are required.")

def retrieve_data_page():
    st.markdown("## 🔓 Retrieve Stored Data")
    st.markdown("Access your encrypted data using the correct passkey.")

    if st.session_state.login_attempts >= 3:
        st.session_state.authorized = False
        return login_page()

    with st.form("retrieve_form"):
        key = st.text_input("🔑 Enter your data key")
        passkey = st.text_input("🔐 Enter your passkey", type="password")
        submitted = st.form_submit_button("Retrieve")

        if submitted:
            if key not in st.session_state.stored_data:
                st.error("❌ Key not found.")
            else:
                stored = st.session_state.stored_data[key]
                if hash_passkey(passkey) == stored["passkey"]:
                    decrypted = decrypt_data(stored["encrypted_text"])
                    st.success("✅ Decryption successful!")
                    st.code(decrypted, language="text")
                    st.session_state.login_attempts = 0
                else:
                    st.session_state.login_attempts += 1
                    attempts_left = 3 - st.session_state.login_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")

# ------------------ Main Navigation ------------------ #
def main():
    st.sidebar.title("🔐 Navigation")
    choice = st.sidebar.radio("Go to:", ["Home", "Insert Data", "Retrieve Data"])

    st.sidebar.markdown("---")
    st.sidebar.caption("Secure Data Encryption App • Streamlit")

    if st.session_state.authorized:
        if choice == "Home":
            home()
        elif choice == "Insert Data":
            insert_data_page()
        elif choice == "Retrieve Data":
            retrieve_data_page()
    else:
        login_page()

if __name__ == "__main__":
    main()
