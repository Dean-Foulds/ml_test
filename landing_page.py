import streamlit as st
import mysql.connector
import bcrypt
import streamlit as st
from google.oauth2 import id_token
from google.auth.transport import requests
import webbrowser
import os
import google_auth_oauthlib.flow
from googleapiclient.discovery import build

st.set_page_config(
    page_title="",  # Change the tab wording
    page_icon="favicon.ico",  # Change the favicon, use an icon file or a URL
)

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        database="bhutan_users",
        user="dean",  # Replace with your database username
        password="password",  # Replace with your database password
        charset='utf8mb4',  # Explicitly set the charset to utf8mb4
        collation='utf8mb4_general_ci',  # Use a compatible collation
    )

# Register User Function
def register_user(username, password, email):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        query = "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_pw, email))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        st.error(f"Error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

# Verify User Function (for login)
def verify_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        query = "SELECT username, password FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            stored_hashed_password = user[1]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                return True
        return False
    except mysql.connector.Error as err:
        st.error(f"Error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

# AI Agent Function (dummy response for now)
def ai_response(question):
    return f"AI Agent: I have received your question - '{question}'. This is a placeholder response."
redirect_uri = os.environ.get("REDIRECT_URI", "http://localhost:8501/")

def auth_flow():
    st.write("Welcome to My App!")
    auth_code = st.query_params.get("code")
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        "client_secret.json", # replace with you json credentials from your google auth app
        scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=redirect_uri,
    )
    if auth_code:
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        st.write("Login Done")
        user_info_service = build(
            serviceName="oauth2",
            version="v2",
            credentials=credentials,
        )
        user_info = user_info_service.userinfo().get().execute()
        assert user_info.get("email"), "Email not found in infos"
        st.session_state["google_auth_code"] = auth_code
        st.session_state["user_info"] = user_info
    else:
        if st.button("Sign in with Google"):
            authorization_url, state = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
            )
            webbrowser.open_new_tab(authorization_url)



# Streamlit UI
def main():
    if "google_auth_code" not in st.session_state:
        auth_flow()

    if "google_auth_code" in st.session_state:
        email = st.session_state["user_info"].get("email")
        st.write(f"Hello {email}")
    # Initialize session state variables if not already set
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.username = ""

    # Check if user is logged in
    if st.session_state.logged_in:
        # Show the logged-in page
        show_logged_in_page(st.session_state.username)
    else:
        # Show the login/register forms
        st.title("Start planning your personalized bhutan trip - create your account")
        menu = ["Login", "Register"]
        choice = st.sidebar.selectbox("Select Activity", menu)

        if choice == "Register":
            st.subheader("Create an Account")

            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            email = st.text_input("Email")

            if st.button("Register"):
                if username and password and email:
                    if register_user(username, password, email):
                        st.success(f"Account created for {username}!")
                else:
                    st.error("Please fill all fields.")

        elif choice == "Login":
            st.subheader("Login to Your Account")

            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Login"):
                if username and password:
                    if verify_user(username, password):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        # Update session state to trigger a page rerun naturally
                        st.session_state["page"] = "logged_in"
                    else:
                        st.error("Invalid username or password.")
                else:
                    st.error("Please fill in both fields.")

# Display page for logged-in users
def show_logged_in_page(username):
    # Greeting Section
    html_content = f"""
    <style>
        .multicolor-text {{
            font-family: Arial, sans-serif;
            font-size: 36px;
            font-weight: bold;
            text-align: center;
            margin-top: 20px;
            background: linear-gradient(90deg, #BC6B9B, #D56675, #9773CC, #D96570, #34A853, #6B92EF);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: rainbow 3s ease infinite;
        }}
        @keyframes rainbow {{
            0% {{ background-position: 0%; }}
            50% {{ background-position: 100%; }}
            100% {{ background-position: 0%; }}
        }}
    </style>
    <div class="multicolor-text">
        Hello, {username}!
    </div>
    <div class="multicolor-text">
        你好, {username}!
    </div>
    """
    st.markdown(html_content, unsafe_allow_html=True)

    # Back to Home button
    if st.button("Logout"):
        st.session_state.logged_in = False  # Set logged_in to False
        st.session_state.username = ""  # Clear username
        st.session_state["page"] = "login"  # Track page change

    # AI Question Input Section
    question = st.text_input("Enter your question here:")

    if st.button("Submit Question"):
        if question:
            response = ai_response(question)
            st.markdown(f"**{response}**")
        else:
            st.error("Please enter a question.")

if __name__ == "__main__":
    main()
