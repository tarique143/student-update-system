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
    """Initializes and returns a connection to the MongoDB database."""
    try:
        client = pymongo.MongoClient(MONGO_CONNECTION_STRING)
        client.admin.command('ping')
        return client
    except Exception as e:
        st.error(f"Error connecting to the database: {e}")
        st.info("Please ensure your connection string is correct and your IP address is whitelisted on MongoDB Atlas.")
        return None

client = init_connection()

if client is None:
    st.stop()

db = client.student_db
students_collection = db.students
activities_collection = db.activities

# --- 4. UTILITY FUNCTIONS ---
def hash_password(password: str) -> bytes:
    """Hashes a password for secure storage."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """Verifies a plain password against a hashed one."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def format_duration(check_in_str: str, check_out_str: str) -> str:
    """Calculates and formats the duration between check-in and check-out times."""
    try:
        check_in_time = time.fromisoformat(check_in_str)
        check_out_time = time.fromisoformat(check_out_str)
        dummy_date = datetime.now().date()
        check_in_dt = datetime.combine(dummy_date, check_in_time)
        check_out_dt = datetime.combine(dummy_date, check_out_time)

        if check_out_dt < check_in_dt:
            return "Invalid Times"

        duration_delta = check_out_dt - check_in_dt
        total_seconds = duration_delta.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        
        return f"{hours}h {minutes}m"
    except (ValueError, TypeError):
        return "N/A"

def generate_shareable_report(student: dict, activities: list) -> str:
    """Generates a plain text report for a student that can be easily copied and shared."""
    report_parts = []
    report_parts.append(f"--- Student Activity Report ---")
    report_parts.append(f"Name: {student.get('full_name', 'N/A')}")
    report_parts.append(f"Username: @{student.get('username', 'N/A')}")
    report_parts.append(f"Class: {student.get('student_class', 'N/A')}")
    report_parts.append(f"Phone: {student.get('phone', 'N/A')}")
    report_parts.append("\n--- Activity Log ---\n")

    if not activities:
        report_parts.append("No activities recorded.")
    else:
        # Sort activities by date before creating the report
        sorted_activities = sorted(activities, key=lambda x: x['date'], reverse=True)
        for activity in sorted_activities:
            check_in_time_str = time.fromisoformat(activity['check_in']).strftime('%I:%M %p')
            check_out_time_str = time.fromisoformat(activity['check_out']).strftime('%I:%M %p')
            duration = format_duration(activity['check_in'], activity['check_out'])
            
            report_parts.append(f"Date: {activity['date']}")
            report_parts.append(f"  - Time: {check_in_time_str} to {check_out_time_str} (Duration: {duration})")
            report_parts.append(f"  - Task: {activity['task_description']}")
            if activity.get('doubt'):
                report_parts.append(f"  - Doubts: {activity['doubt']}")
            report_parts.append("-" * 20)
            
    return "\n".join(report_parts)

# --- 5. DATABASE OPERATIONS ---
def register_student(username, password, full_name, student_class, phone, address, reference):
    if students_collection.find_one({"username": username}):
        return False, "Username already exists."
    
    hashed_pass = hash_password(password)
    student_data = {
        "username": username, "password": hashed_pass, "full_name": full_name,
        "student_class": student_class, "phone": phone, "address": address,
        "reference": reference, "registered_on": datetime.now()
    }
    students_collection.insert_one(student_data)
    return True, "Registration successful! You can now log in."

def login_student(username, password):
    student = students_collection.find_one({"username": username})
    if student and verify_password(password, student.get('password')):
        return True, "Login successful!"
    return False, "Invalid username or password."

def add_activity(username, check_in, check_out, task, doubt):
    today_str = datetime.now().date().isoformat()
    activity_data = {
        "check_in": check_in.isoformat(), "check_out": check_out.isoformat(),
        "task_description": task, "doubt": doubt, "recorded_at": datetime.now()
    }
    activities_collection.update_one(
        {"username": username, "date": today_str},
        {"$set": activity_data, "$setOnInsert": {"username": username, "date": today_str}},
        upsert=True
    )

def get_student_activities(username):
    return list(activities_collection.find({"username": username}).sort("date", -1))

def get_all_students_details():
    return list(students_collection.find({}, {"password": 0}))

# --- 6. STREAMLIT UI ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.is_admin = False

st.title("👨‍🎓 Student Daily Update System")

# --- UI for Logged-In Users ---
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
            st.write(f"Total Registered Students: **{len(all_students)}**")
            for student in all_students:
                with st.expander(f"**{student['full_name']}** (@{student['username']})"):
                    activities = get_student_activities(student['username'])
                    
                    # Share button at the top of the expander
                    if st.button(f"Share {student['full_name']}'s Report", key=f"share_{student['username']}"):
                        report_text = generate_shareable_report(student, activities)
                        st.text_area("Copy and Share this Report:", value=report_text, height=300)

                    # Student's personal details
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

                    # Student's activity log as a table
                    st.subheader("Activity Log")
                    if activities:
                        processed_activities = [{
                            "Date": activity['date'],
                            "Check-in": time.fromisoformat(activity['check_in']).strftime('%I:%M %p'),
                            "Check-out": time.fromisoformat(activity['check_out']).strftime('%I:%M %p'),
                            "Duration": format_duration(activity['check_in'], activity['check_out']),
                            "Task": activity['task_description'],
                            "Doubts": activity.get('doubt', '')
                        } for activity in activities]
                        df = pd.DataFrame(processed_activities)
                        st.dataframe(df, use_container_width=True, hide_index=True)
                    else:
                        st.info("No activities recorded for this student.")

    # --- STUDENT DASHBOARD UI ---
    else:
        st.header("📅 My Dashboard")
        col1, col2 = st.columns([1.2, 1])
        with col1:
            st.subheader("📝 Daily Update Form")
            with st.form("ActivityForm"):
                check_in = st.time_input("Check-in Time", value=datetime.now().time())
                check_out = st.time_input("Check-out Time", value=datetime.now().time())
                task = st.text_area("Task Description for Today")
                doubt = st.text_area("Any Doubts or Questions? (Optional)")
                submitted = st.form_submit_button("Submit Today's Update", use_container_width=True)
                if submitted:
                    if task:
                        add_activity(st.session_state.username, check_in, check_out, task, doubt)
                        st.success("Your activity has been updated!")
                        st.toast("Updated!", icon="✅")
                    else:
                        st.warning("Please describe your task.")
        with col2:
            st.subheader("📜 My Past Activities")
            my_activities = get_student_activities(st.session_state.username)
            if my_activities:
                processed_activities = [{
                    "Date": activity['date'],
                    "Check-in": time.fromisoformat(activity['check_in']).strftime('%I:%M %p'),
                    "Check-out": time.fromisoformat(activity['check_out']).strftime('%I:%M %p'),
                    "Duration": format_duration(activity['check_in'], activity['check_out']),
                    "Task": activity['task_description'],
                    "Doubts": activity.get('doubt', '')
                } for activity in my_activities]
                df = pd.DataFrame(processed_activities)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("You have not recorded any activities yet.")

# --- UI for Logged-Out Users ---
else:
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
            submitted = st.form_submit_button("Register", use_container_width=True)
            if submitted:
                if all([full_name, student_class, phone, address, reg_username, reg_password]):
                    success, message = register_student(reg_username, reg_password, full_name, student_class, phone, address, reference)
                    if success: st.success(message)
                    else: st.error(message)
                else:
                    st.warning("Please fill out all required fields (Reference is optional).")

    with login_tab:
        st.subheader("Login to Your Student Account")
        with st.form("LoginForm", border=False):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login", use_container_width=True)
            if submitted:
                if username == ADMIN_USER:
                    st.error("Please use the Admin Login in the sidebar.")
                else:
                    success, message = login_student(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.is_admin = False
                        st.rerun()
                    else:
                        st.error(message)

    with st.sidebar.expander("🔑 Admin Login", expanded=False):
        with st.form("AdminForm"):
            admin_username = st.text_input("Admin Username")
            admin_password = st.text_input("Admin Password", type="password")
            submitted = st.form_submit_button("Login as Admin")
            if submitted:
                if admin_username == ADMIN_USER and admin_password == ADMIN_PASS:
                    st.session_state.logged_in = True
                    st.session_state.username = "Admin"
                    st.session_state.is_admin = True
                    st.rerun()
                else:
                    st.error("Invalid Admin credentials.")