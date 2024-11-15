# Test
import streamlit as st
from streamlit_oauth import OAuth2Component
from streamlit_cookies_manager import EncryptedCookieManager
import os
from dotenv import load_dotenv
import json
import base64

load_dotenv()

# Initialize cookies
cookies = EncryptedCookieManager(
    prefix="chapi-dev/cookie-manager", password=st.secrets["COOKIE_ENCRYPTION"]
)

if not cookies.ready():
    st.spinner("Loading session cookies")
    st.stop()


# create an OAuth2Component instance
# CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
# CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
CLIENT_ID = st.secrets["GOOGLE_CLIENT_ID"]
CLIENT_SECRET = st.secrets["GOOGLE_CLIENT_SECRET"]
AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

st.title("CHAPI Dev Build")

tab1, tab2 = st.tabs(["Login", "Matching Algorithm"])

with tab1:
    if "auth" not in cookies or "token" not in cookies:
        st.subheader("Please sign in to view app content.")
        # create a button to start the OAuth2 flow
        oauth2 = OAuth2Component(
            CLIENT_ID,
            CLIENT_SECRET,
            AUTHORIZE_ENDPOINT,
            TOKEN_ENDPOINT,
            TOKEN_ENDPOINT,
            REVOKE_ENDPOINT,
        )
        result = oauth2.authorize_button(
            name="Continue with Google",
            icon="https://www.google.com.tw/favicon.ico",
            redirect_uri="https://chapi-dev.streamlit.app",
            scope="openid email profile",
            key="google",
            extras_params={"prompt": "consent", "access_type": "offline"},
            use_container_width=True,
            pkce="S256",
        )

        if result:
            # st.write(result)
            # decode the id_token jwt and get the user's email address
            id_token = result["token"]["id_token"]
            # verify the signature is an optional step for security
            payload = id_token.split(".")[1]
            # add padding to the payload if needed
            payload += "=" * (-len(payload) % 4)
            payload = json.loads(base64.b64decode(payload))
            email = payload["email"]
            if email in st.secrets["allowed_emails"]:
                cookies["auth"] = email
                cookies["token"] = "123"
                st.write(result["token"])
                cookies.save()
                st.rerun()
            else:
                st.write("ERROR: Unauthorized User - Sign in with authorized account.")
    else:
        st.write(f"Welcome back! {cookies["auth"]}")
        if st.button("Sign out"):
            del cookies["auth"]
            del cookies["token"]
            cookies.save()
            st.rerun()

with tab2:
    if "auth" in cookies and "token" in cookies:
        st.write("App content")

    else:
        st.subheader("Please sign in to view app content.")
