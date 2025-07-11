import streamlit as st
import time

# MVC imports
import models
import views

# Feature imports
from streamlit_cookies_manager import EncryptedCookieManager

# --- 1. PAGE CONFIGURATION & INITIALIZATION ---
st.set_page_config(
    page_title="Student Management System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Cookie manager for persistent sessions
cookies = EncryptedCookieManager(
    password=st.secrets.get("COOKIE_PASSWORD", "a_default_strong_password_for_local_dev"),
)

# --- HELPER FUNCTIONS FOR CONTROLLER ---
def handle_logout():
    """Handles the user logout process."""
    models.delete_user_session(cookies.get('session_token'))
    del cookies['session_token']
    cookies.save()
    # Clear the entire session state to start fresh
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.success("You have been logged out.")
    time.sleep(1)
    st.rerun()

def handle_login(username, is_admin=False):
    """Handles the user login process."""
    token = models.create_user_session(username, is_admin=is_admin)
    cookies['session_token'] = token
    cookies.save()
    st.rerun()

# --- MAIN PAGE HANDLERS ---
def handle_logged_in_user():
    """Handles the UI and logic for a logged-in user (Admin or Student)."""
    is_admin = st.session_state.is_admin
    username = st.session_state.username
    student_data = {} if is_admin else models.get_student_details(username)

    sidebar_action = views.show_sidebar(username, is_admin, student_data)
    
    # Handle actions from the sidebar
    if sidebar_action.get('action') == "logout":
        handle_logout()
    
    if sidebar_action.get('action') == "update_profile":
        success, message = models.update_student_profile(username, **sidebar_action['data'])
        if success:
            st.success("Profile updated!")
        else:
            st.error(message) # e.g., "Email is already in use"
        time.sleep(1)
        st.rerun()

    # Display the correct dashboard based on user role
    if is_admin:
        stats = models.get_admin_dashboard_stats()
        all_students = models.get_all_students_details()
        for student in all_students:
            student['todays_activity'] = models.get_todays_activity(student['username'])
        admin_action = views.show_admin_dashboard(stats, all_students)

        action = admin_action.get('action')
        if action == "broadcast":
            models.broadcast_message_to_all(admin_action['data']['message'])
            st.success("Broadcast message sent!"); st.rerun()
        elif action == "send_message":
            models.send_message_to_student(**admin_action['data'])
            st.success("Message sent!"); st.rerun()
        elif action == "delete_student":
            if models.delete_student_data(admin_action['data']['username']):
                st.success(f"Successfully deleted {admin_action['data']['full_name']}.")
            else:
                st.error("Failed to delete student.")
            time.sleep(1); st.rerun()
    else:
        # Display student dashboard and handle its actions
        messages = models.get_messages_for_student(username)
        activities = models.get_student_activities(username)
        todays_activity = models.get_todays_activity(username)
        student_action = views.show_student_dashboard(username, messages, activities, todays_activity)

        action = student_action.get('action')
        if action == "check_in":
            models.check_in_student(username, **student_action['data']); st.success("Checked in!"); time.sleep(1); st.rerun()
        elif action == "check_out":
            models.check_out_student(username, **student_action['data']); st.success("Checked out!"); st.balloons(); time.sleep(2); st.rerun()

def handle_logged_out_user():
    """Handles the UI and logic for a logged-out user (Login, Register, Forgot Password with OTP)."""
    with st.sidebar.expander("🔑 Admin Login"):
        with st.form("AdminForm"):
            admin_user = st.text_input("Admin Username"); admin_pass = st.text_input("Password", type="password")
            if st.form_submit_button("Login as Admin"):
                if admin_user == st.secrets["ADMIN_USER"] and admin_pass == st.secrets["ADMIN_PASS"]:
                    handle_login("Admin", is_admin=True)
                else:
                    st.error("Invalid Admin credentials.")
    
    form_result = views.show_login_page()
    form_name = form_result.get("form_name")

    if form_name == 'login':
        data = form_result['data']
        if models.verify_student_credentials(**data):
            handle_login(data['username'])
        else:
            st.error("Invalid username or password.")
    
    elif form_name == 'register':
        success, message = models.register_student(**form_result['data'])
        if success:
            st.success(message + " Please log in.")
        else:
            st.error(message)

    # --- UPDATED LOGIC FOR OTP ---
    elif form_name == 'send_otp':
        email = form_result['data']['email']
        success, message = models.create_and_send_otp(email)
        if success:
            st.session_state.otp_step = 2 # Go to the next step in the view
            st.rerun()
        else:
            st.error(message)

    elif form_name == 'verify_otp':
        success, message = models.verify_otp_and_reset_password(**form_result['data'])
        if success:
            st.success(message)
            st.info("You can now log in with your new password.")
            # Reset the OTP flow state
            del st.session_state.otp_step
            del st.session_state.reset_email
            time.sleep(2)
            st.rerun()
        else:
            st.error(message)

# --- MAIN APP LOGIC ---
def main():
    """The main function that controls the app's flow."""
    st.title("👨‍🎓 Student Management System")
    
    if st.session_state.get('logged_in'):
        handle_logged_in_user()
    else:
        handle_logged_out_user()

if __name__ == "__main__":
    # Wait for cookies to be ready (Permanent Fix)
    if 'cookie_init_run' not in st.session_state:
        st.session_state.cookie_init_run = True
        time.sleep(0.5)
        st.rerun()

    # Initialize session state if it doesn't exist
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Try to auto-login from cookie
    if not st.session_state.logged_in:
        session_token = cookies.get('session_token')
        if session_token:
            session_data = models.verify_user_session(session_token)
            if session_data:
                st.session_state.logged_in = True
                st.session_state.username = session_data['username']
                st.session_state.is_admin = session_data['is_admin']
                st.rerun()

    # Run the main application
    main()