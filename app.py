import streamlit as st
import os
from datetime import datetime
from models import init_db, get_db_session, User, FileKey
from utils import UserManager, FileManager
from crypto import CryptoManager
from config import MAX_FILE_SIZE

# Initialize database session
db_session = init_db()

def format_datetime(dt):
    """Format datetime in UTC to YYYY-MM-DD HH:MM:SS"""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def init_session_state():
    """Initialize Streamlit session state variables"""
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'password' not in st.session_state:
        st.session_state.password = None
    if 'login_time' not in st.session_state:
        st.session_state.login_time = None
    if 'confirm_delete' not in st.session_state:
        st.session_state.confirm_delete = False
    if 'current_datetime' not in st.session_state:
        st.session_state.current_datetime = "2025-02-17 18:26:54"

def clear_user_data(user_id):
    """Clear all user's file data from database"""
    try:
        # Get all user's file keys
        file_keys = db_session.query(FileKey).filter(FileKey.owner_id == user_id).all()
        
        # Delete each file key
        for file_key in file_keys:
            db_session.delete(file_key)
        
        db_session.commit()
        return True
    except Exception as e:
        print(f"Error clearing user data: {str(e)}")
        return False

def render_login():
    """Render the login form"""
    st.subheader("Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            user = UserManager.authenticate_user(db_session, username, password)
            if user:
                st.session_state.user_id = user.id
                st.session_state.username = user.username
                st.session_state.password = password
                st.session_state.login_time = datetime.utcnow()
                st.experimental_rerun()
            else:
                st.error("Invalid credentials!")

def render_register():
    """Render the registration form"""
    st.subheader("Register")
    
    with st.form("register_form"):
        new_username = st.text_input("Choose Username")
        new_password = st.text_input("Choose Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit = st.form_submit_button("Register")
        
        if submit:
            if not new_username or not new_password:
                st.error("Username and password are required!")
            elif new_password != confirm_password:
                st.error("Passwords don't match!")
            else:
                try:
                    UserManager.create_user(db_session, new_username, new_password)
                    st.success("Registration successful! Please login.")
                except ValueError as e:
                    st.error(str(e))
                except Exception as e:
                    st.error(f"Registration failed: {str(e)}")

def render_encrypt_file(current_user):
    """Render the file encryption page"""
    st.header("Encrypt File")
    
    uploaded_file = st.file_uploader("Choose a file to encrypt", key="encrypt_uploader")
    
    if uploaded_file and st.button("Encrypt"):
        if uploaded_file.size > MAX_FILE_SIZE:
            st.error(f"File size exceeds limit of {MAX_FILE_SIZE/1024/1024}MB")
            return
        
        try:
            file_data = uploaded_file.read()
            filename_base = os.path.splitext(uploaded_file.name)[0]
            encrypted_data = CryptoManager.encrypt_file(file_data, current_user.public_key)
            
            st.download_button(
                "Download Encrypted File",
                data=encrypted_data,
                file_name=f"{filename_base}.encrypted",
                mime="application/octet-stream"
            )
            
            FileManager.save_file_key(
                db_session,
                uploaded_file.name,
                encrypted_data,
                None,
                current_user
            )
            
            st.success("File encrypted successfully! Download the encrypted file and keep it safe.")
            
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")

def render_decrypt_file(current_user):
    """Render the file decryption page"""
    st.header("Decrypt File")
    
    uploaded_file = st.file_uploader("Upload encrypted file (*.encrypted)", key="decrypt_uploader")
    
    if uploaded_file and st.button("Decrypt"):
        if not uploaded_file.name.endswith('.encrypted'):
            st.error("Please upload a valid encrypted file (*.encrypted)")
            return
            
        try:
            encrypted_data = uploaded_file.read()
            file_key = FileManager.get_file_key(db_session, encrypted_data, current_user.id)
            
            if not file_key:
                st.error("This file was not encrypted with your key. Unable to decrypt.")
                return
            
            # Decrypt the private key using the stored password
            private_key = CryptoManager.decrypt_private_key(
                current_user.encrypted_private_key,
                st.session_state.password,  # Use the password from session
                current_user.salt
            )
            
            # Decrypt the file using the decrypted private key and password
            decrypted_data = CryptoManager.decrypt_file(
                encrypted_data,
                private_key,
                st.session_state.password  # Pass the password
            )
            
            st.download_button(
                "Download Decrypted File",
                data=decrypted_data,
                file_name=file_key.filename,
                mime="application/octet-stream"
            )
            
            st.success("File decrypted successfully!")
            
        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")

def render_file_list(current_user):
    """Render the list of encrypted files"""
    st.header("Your Encrypted Files")
    
    files = FileManager.get_user_files(db_session, current_user.id)
    if files:
        st.write("Files you have encrypted:")
        for file in files:
            st.write(f"- {file.filename} (Encrypted on {format_datetime(file.created_at)})")
    else:
        st.info("You haven't encrypted any files yet.")

def render_sidebar(current_user):
    """Render sidebar with user options"""
    st.sidebar.markdown(f"""
    **Welcome, {current_user.username}!**
    
    **Current Date and Time:** {st.session_state.current_datetime}
    """)
    
    # Logout button
    if st.sidebar.button("Logout"):
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.password = None
        st.session_state.login_time = None
        st.session_state.confirm_delete = False
        st.experimental_rerun()
    
    # Add space between buttons
    st.sidebar.write("")
    st.sidebar.write("")
    
    # Clear data button with confirmation
    if st.sidebar.button("🗑️ Clear All My Data"):
        st.session_state.confirm_delete = True
    
    if st.session_state.confirm_delete:
        st.sidebar.warning("⚠️ Are you sure you want to clear all your data?\nThis will remove all your file keys but keep your account.")
        col1, col2 = st.sidebar.columns(2)
        
        if col1.button("Yes, Clear Data"):
            if clear_user_data(current_user.id):
                st.sidebar.success("All your data has been cleared!")
                st.session_state.confirm_delete = False
                st.experimental_rerun()
            else:
                st.sidebar.error("Failed to clear data. Please try again.")
        
        if col2.button("No, Cancel"):
            st.session_state.confirm_delete = False
            st.experimental_rerun()

def main():
    st.set_page_config(
        page_title="File Encryption System",
        page_icon="🔒",
        layout="wide"
    )
    
    init_session_state()
    
    st.title("File Encryption System")
    
    if not st.session_state.user_id:
        tab1, tab2 = st.tabs(["Login", "Register"])
        with tab1:
            render_login()
        with tab2:
            render_register()
    else:
        current_user = db_session.query(User).get(st.session_state.user_id)
        
        if not current_user:
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.password = None
            st.session_state.login_time = None
            st.session_state.confirm_delete = False
            st.experimental_rerun()
            return
        
        # Show main interface
        tab1, tab2, tab3 = st.tabs(["Encrypt File", "Decrypt File", "File List"])
        
        with tab1:
            render_encrypt_file(current_user)
        with tab2:
            render_decrypt_file(current_user)
        with tab3:
            render_file_list(current_user)
        
        # Render sidebar with user options
        render_sidebar(current_user)

if __name__ == "__main__":
    main()