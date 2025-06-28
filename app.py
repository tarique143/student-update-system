import streamlit as st
import pymongo
import bcrypt
import pandas as pd
from datetime import datetime, time

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Student Update System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. DATABASE & ADMIN CREDENTIALS ---
MONGO_CONNECTION_STRING = "mongodb+srv://Student:student123@studentmgmtcluster.hn1j5la.mongodb.net/?retryWrites=true&w=majority&appName=StudentMgmtCluster"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

# --- 3. DATABASE CONNECTION ---
@st.cache_resource
def init_connection():
    try:
        client = pymongo.MongoClient(MONGO_CONNECTION_STRING)
        client.admin.command('ping')
        return client
    except Exception as e:
        st.error(f"Error connecting to the database: {e}")
        return None

client = init_connection()
if client is None: st.stop()

db = client.student_db
students_collection = db.students
activities_collection = db.activities
messages_collection = db.messages

# --- 4. UTILITY FUNCTIONS ---
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def format_duration(check_in_str: str, check_out_str: str) -> str:
    try:
        check_in = time.fromisoformat(check_in_str)
        check_out = time.fromisoformat(check_out_str)
        dummy_date = datetime.now().date()
        delta = datetime.combine(dummy_date, check_out) - datetime.combine(dummy_date, check_in)
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        return f"{hours}h {minutes}m"
    except (ValueError, TypeError): return "N/A"

# --- 5. DATABASE OPERATIONS (UPDATED WORKFLOW) ---
def get_todays_activity(username: str):
    """Fetches the activity record for the current day for a given student."""
    today_str = datetime.now().date().isoformat()
    return activities_collection.find_one({"username": username, "date": today_str})

def check_in_student(username: str, check_in_time: time):
    """Creates a check-in record for the student."""
    today_str = datetime.now().date().isoformat()
    activity_doc = {
        "username": username,
        "date": today_str,
        "check_in": check_in_time.isoformat(),
        "recorded_at": datetime.now()
    }
    activities_collection.update_one(
        {"username": username, "date": today_str},
        {"$set": activity_doc},
        upsert=True
    )

def check_out_student(username: str, task: str, doubt: str):
    """Updates the daily record with check-out time, task, and doubt."""
    today_str = datetime.now().date().isoformat()
    update_data = {
        "check_out": datetime.now().time().isoformat(),
        "task_description": task,
        "doubt": doubt
    }
    activities_collection.update_one(
        {"username": username, "date": today_str},
        {"$set": update_data}
    )

def register_student(username, password, full_name, student_class, phone, address, reference):
    if students_collection.find_one({"username": username}):
        return False, "Username already exists."
    hashed_pass = hash_password(password)
    student_data = {"username": username, "password": hashed_pass, "full_name": full_name, "student_class": student_class, "phone": phone, "address": address, "reference": reference, "registered_on": datetime.now()}
    students_collection.insert_one(student_data)
    return True, "Registration successful! You can now log in."

def login_student(username, password):
    student = students_collection.find_one({"username": username})
    if student and verify_password(password, student.get('password')):
        return True, "Login successful!"
    return False, "Invalid username or password."

def get_student_activities(username):
    return list(activities_collection.find({"username": username}).sort("date", -1))

def get_all_students_details():
    return list(students_collection.find({}, {"password": 0}))

def delete_student_data(username: str):
    activities_collection.delete_many({"username": username})
    messages_collection.delete_many({"to_username": username})
    students_collection.delete_one({"username": username})
    return True

def send_message_to_student(to_username: str, message_text: str):
    message_doc = {"to_username": to_username, "from_user": "Admin", "message": message_text, "sent_at": datetime.now()}
    messages_collection.insert_one(message_doc)
    return True

def get_messages_for_student(username: str):
    return list(messages_collection.find({"to_username": username}).sort("sent_at", -1))

# --- 6. STREAMLIT UI ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.is_admin = False

st.title("👨‍🎓 Student Daily Update System")

if st.session_state.logged_in:
    st.sidebar.success(f"Welcome, {st.session_state.username}!")
    if st.sidebar.button("Log Out", use_container_width=True, type="primary"):
        for key in list(st.session_state.keys()): del st.session_state[key]
        st.rerun()

    # --- ADMIN PANEL UI ---
    if st.session_state.is_admin:
        st.header("🔑 Admin Panel: Student Details")
        all_students = get_all_students_details()
        if not all_students:
            st.info("No students have registered yet.")
        else:
            for student in all_students:
                todays_activity = get_todays_activity(student['username'])
                is_checked_in = todays_activity and 'check_out' not in todays_activity
                status_icon = "🟢" if is_checked_in else "⚪️"
                
                with st.expander(f"{status_icon} **{student['full_name']}** (@{student['username']})"):
                    # ... (Admin panel details remain the same)
                    st.subheader("Personal Information")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Class:** {student.get('student_class', 'N/A')}")
                        st.markdown(f"**Phone:** {student.get('phone', 'N/A')}")
                    with col2:
                        reg_date = student.get('registered_on')
                        st.markdown(f"**Registered On:** {reg_date.strftime('%d-%b-%Y') if reg_date else 'N/A'}")
                        st.markdown(f"**Reference:** {student.get('reference', 'N/A')}")
                    st.markdown(f"**Address:** {student.get('address', 'N/A')}")
                    
                    st.markdown("---")
                    
                    st.subheader("Activity Log")
                    activities = get_student_activities(student['username'])
                    if activities:
                        df_activities = pd.DataFrame([{
                            "Date": a.get('date'), "Check-in": time.fromisoformat(a.get('check_in')).strftime('%I:%M %p'),
                            "Check-out": time.fromisoformat(a.get('check_out')).strftime('%I:%M %p') if a.get('check_out') else 'Active',
                            "Duration": format_duration(a.get('check_in'), a.get('check_out')) if a.get('check_out') else '-',
                            "Task": a.get('task_description', 'N/A'), "Doubts": a.get('doubt', '')
                        } for a in activities])
                        st.dataframe(df_activities, use_container_width=True, hide_index=True)
                    else: st.info("No activities recorded.")

                    st.markdown("---")
                    st.subheader("Admin Actions")
                    # ... (Admin actions remain the same)
                    action_col1, action_col2 = st.columns(2)
                    with action_col1:
                        with st.form(key=f"msg_{student['username']}"):
                            st.write(f"**Send Message to {student['full_name']}**")
                            message_text = st.text_area("Message", height=100, label_visibility="collapsed")
                            if st.form_submit_button("Send"):
                                if message_text:
                                    send_message_to_student(student['username'], message_text)
                                    st.success("Message sent!")
                                else: st.warning("Message cannot be empty.")
                    with action_col2:
                        st.write("**Danger Zone**")
                        if st.checkbox("I want to delete this student", key=f"del_check_{student['username']}"):
                            if st.button("🔴 PERMANENTLY DELETE STUDENT", key=f"del_btn_{student['username']}"):
                                delete_student_data(student['username'])
                                st.success(f"Successfully deleted {student['full_name']}.")
                                st.rerun()

    # --- STUDENT DASHBOARD UI (Completely Redesigned) ---
    else:
        messages = get_messages_for_student(st.session_state.username)
        if messages:
            with st.expander("📬 You have new messages from the Admin!", expanded=True):
                for msg in messages:
                    st.info(f"**{msg['sent_at'].strftime('%d-%b-%Y %I:%M %p')}:** {msg['message']}")

        st.header("📅 My Dashboard")
        
        todays_activity = get_todays_activity(st.session_state.username)
        is_checked_in = todays_activity and 'check_out' not in todays_activity
        
        col1, col2 = st.columns((1, 2))

        with col1:
            st.subheader("Today's Status")
            if is_checked_in:
                check_in_time = time.fromisoformat(todays_activity['check_in']).strftime('%I:%M %p')
                st.metric(label="Current Status", value="Checked-In", delta=f"at {check_in_time}")
                with st.form("CheckOutForm"):
                    st.write("**Complete Your Session**")
                    task = st.text_area("Task Description for Today", key="task_out")
                    doubt = st.text_area("Any Doubts or Questions? (Optional)", key="doubt_out")
                    if st.form_submit_button("CHECK OUT NOW", use_container_width=True, type="primary"):
                        if task:
                            check_out_student(st.session_state.username, task, doubt)
                            st.success("You have been checked out successfully!")
                            st.balloons()
                            st.rerun()
                        else:
                            st.warning("Please describe your task before checking out.")
            
            elif todays_activity and 'check_out' in todays_activity:
                st.metric(label="Today's Status", value="Completed")
                st.success("You have completed your session for the day. Great work!")
                
            else: # Not checked in at all
                st.metric(label="Current Status", value="Checked-Out")
                with st.form("CheckInForm"):
                    st.write("**Start Your Session**")
                    check_in_time_input = st.time_input("Check-in Time")
                    if st.form_submit_button("CHECK IN", use_container_width=True):
                        check_in_student(st.session_state.username, check_in_time_input)
                        st.success(f"You are checked in at {check_in_time_input.strftime('%I:%M %p')}")
                        st.rerun()

        with col2:
            st.subheader("📜 My Past Activities")
            my_activities = get_student_activities(st.session_state.username)
            if my_activities:
                df = pd.DataFrame([{
                    "Date": a.get('date'), "Check-in": time.fromisoformat(a.get('check_in')).strftime('%I:%M %p'),
                    "Check-out": time.fromisoformat(a.get('check_out')).strftime('%I:%M %p') if a.get('check_out') else 'Active',
                    "Duration": format_duration(a.get('check_in'), a.get('check_out')) if a.get('check_out') else '-',
                    "Task": a.get('task_description', 'N/A'), "Doubts": a.get('doubt', '')
                } for a in my_activities])
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("You have not recorded any activities yet.")

# --- UI for Logged-Out Users ---
else:
    # ... (Login/Register/Admin Login UI remains the same)
    login_tab, register_tab = st.tabs(["👨‍🎓 Student Login", "✍️ Register"])
    with register_tab:
        st.subheader("Create a New Student Account")
        with st.form("RegisterForm", border=False):
            full_name = st.text_input("Full Name")
            student_class = st.text_input("Class with Year (e.g., B.Tech 2nd Year)")
            phone = st.text_input("Phone Number")
            address = st.text_area("Address")
            reference = st.text_input("Reference (Optional)")
            st.markdown("---")
            reg_username = st.text_input("Username (you will use this to log in)")
            reg_password = st.text_input("Password", type="password")
            if st.form_submit_button("Register", use_container_width=True):
                if all([full_name, student_class, phone, address, reg_username, reg_password]):
                    success, message = register_student(reg_username, reg_password, full_name, student_class, phone, address, reference)
                    if success: st.success(message)
                    else: st.error(message)
                else: st.warning("Please fill out all required fields (Reference is optional).")
    with login_tab:
        st.subheader("Login to Your Student Account")
        with st.form("LoginForm", border=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login", use_container_width=True):
                if username == ADMIN_USER:
                    st.error("Please use the Admin Login in the sidebar.")
                else:
                    success, message = login_student(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.is_admin = False
                        st.rerun()
                    else: st.error(message)
    with st.sidebar.expander("🔑 Admin Login", expanded=False):
        with st.form("AdminForm"):
            admin_username = st.text_input("Admin Username")
            admin_password = st.text_input("Admin Password", type="password")
            if st.form_submit_button("Login as Admin"):
                if admin_username == ADMIN_USER and admin_password == ADMIN_PASS:
                    st.session_state.logged_in = True
                    st.session_state.username = "Admin"
                    st.session_state.is_admin = True
                    st.rerun()
                else: st.error("Invalid Admin credentials.")