import streamlit as st
import pymongo
import bcrypt
import pandas as pd
from datetime import datetime, time, date
from dateutil.relativedelta import relativedelta
import time as py_time
import subprocess
import platform
import re
from fpdf import FPDF, XPos, YPos
from zoneinfo import ZoneInfo # <-- TIMEZONE FIX: Import ZoneInfo

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Student Management System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- TIMEZONE CONSTANT ---
# TIMEZONE FIX: Apne timezone ko ek variable me set karein
IST = ZoneInfo("Asia/Kolkata")

# --- 2. SECRETS MANAGEMENT ---
try:
    MONGO_CONNECTION_STRING = st.secrets["MONGO_CONNECTION_STRING"]
    ADMIN_USER = st.secrets["ADMIN_USER"]
    ADMIN_PASS = st.secrets["ADMIN_PASS"]
    ALLOWED_WIFI_SSID = st.secrets["ALLOWED_WIFI_SSID"]
except (KeyError, FileNotFoundError):
    st.error("ERROR: Critical application secrets are not set.")
    st.info("Please ensure MONGO_CONNECTION_STRING, ADMIN_USER, ADMIN_PASS, and ALLOWED_WIFI_SSID are set in your secrets.")
    st.stop()

# --- 3. DATABASE CONNECTION ---
@st.cache_resource
def init_connection():
    try:
        client = pymongo.MongoClient(MONGO_CONNECTION_STRING)
        client.admin.command('ping')
        return client
    except Exception as e:
        st.error(f"Database connection failed: {e}")
        return None

client = init_connection()
if client is None: st.stop()

db = client.student_db
students_collection = db.students
activities_collection = db.activities
messages_collection = db.messages

# --- 4. UTILITY FUNCTIONS ---
@st.cache_data(ttl=10)
def get_current_ssid():
    # ... (Is function me koi badlav nahi)
    current_os = platform.system()
    try:
        if current_os == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            ssid_match = re.search(r"SSID\s+:\s(.+)", output)
            return ssid_match.group(1).strip() if ssid_match else None
        elif current_os == "Darwin":
            output = subprocess.check_output("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I", shell=True, stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
            ssid_match = re.search(r"^\s*SSID: (.+)", output, re.MULTILINE)
            return ssid_match.group(1).strip() if ssid_match else None
        elif current_os == "Linux":
            ssid = subprocess.check_output("iwgetid -r", shell=True, stderr=subprocess.DEVNULL).decode().strip()
            return ssid if ssid else None
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def hash_password(password: str) -> bytes: return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
def verify_password(plain_password: str, hashed_password: bytes) -> bool: return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
def calculate_duration(check_in_str, check_out_str):
    try:
        check_in, check_out = time.fromisoformat(check_in_str), time.fromisoformat(check_out_str)
        delta = datetime.combine(date.today(), check_out) - datetime.combine(date.today(), check_in)
        return delta.total_seconds() / 3600
    except (ValueError, TypeError): return 0.0
def format_duration(hours_float):
    if not isinstance(hours_float, (int, float)) or hours_float < 0: return "N/A"
    hours, minutes = int(hours_float), int((hours_float * 60) % 60)
    return f"{hours}h {minutes}m"
def format_to_12hr(time_str):
    if not time_str: return "N/A"
    try: return time.fromisoformat(time_str).strftime('%I:%M %p')
    except (ValueError, TypeError): return "Invalid Time"

def generate_pdf_report(student: dict, activities: list) -> bytes:
    # ... (Is function me koi badlav nahi)
    pdf = FPDF(); pdf.add_page(); pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(0, 10, 'Student Activity Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C'); pdf.ln(10)
    pdf.set_font("Helvetica", 'B', 12); pdf.cell(40, 8, 'Student Name:'); pdf.set_font("Helvetica", '', 12); pdf.cell(0, 8, student.get('full_name', 'N/A'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", 'B', 12); pdf.cell(40, 8, 'Username:'); pdf.set_font("Helvetica", '', 12); pdf.cell(0, 8, f"@{student.get('username', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", 'B', 12); pdf.cell(40, 8, 'Class:'); pdf.set_font("Helvetica", '', 12); pdf.cell(0, 8, student.get('student_class', 'N/A'), new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.ln(10)
    pdf.set_font("Helvetica", 'B', 14); pdf.cell(0, 10, 'Activity Log', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L'); pdf.line(10, pdf.get_y(), 200, pdf.get_y()); pdf.ln(5)
    if not activities: pdf.set_font("Helvetica", 'I', 12); pdf.cell(0, 10, 'No activities recorded.', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for activity in activities:
            pdf.set_font("Helvetica", 'B', 12); pdf.cell(0, 8, f"Date: {activity.get('date', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", '', 11); duration = format_duration(calculate_duration(activity['check_in'], activity.get('check_out', activity['check_in']))); check_out_time = format_to_12hr(activity.get('check_out')) if activity.get('check_out') else 'Active'
            pdf.cell(0, 6, f"    Time: {format_to_12hr(activity['check_in'])} to {check_out_time}  (Duration: {duration})", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", 'B', 11); pdf.cell(0, 6, "    Task:", new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.set_font("Helvetica", '', 11); pdf.set_x(20); pdf.multi_cell(0, 6, activity.get('task_description', 'N/A'), align='L')
            if activity.get('doubt'): pdf.set_font("Helvetica", 'B', 11); pdf.cell(0, 6, "    Doubts:", new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.set_font("Helvetica", '', 11); pdf.set_x(20); pdf.multi_cell(0, 6, activity.get('doubt'), align='L')
            pdf.ln(4)
    return bytes(pdf.output())

# --- 5. DATABASE OPERATIONS ---
def register_student(username, password, full_name, student_class, phone, address, reference):
    if students_collection.find_one({"username": username}): return False, "Username already exists."
    # TIMEZONE FIX: Use datetime.now(IST)
    hashed_pass = hash_password(password); student_data = {"username": username, "password": hashed_pass, "full_name": full_name, "student_class": student_class, "phone": phone, "address": address, "reference": reference, "registered_on": datetime.now(IST)}; students_collection.insert_one(student_data)
    return True, "Registration successful! Redirecting..."
def login_student(username, password):
    student = students_collection.find_one({"username": username});
    if student and verify_password(password, student.get('password')): return True, "Login successful!"
    return False, "Invalid username or password."
def get_student_details(username): return students_collection.find_one({"username": username})
def update_student_profile(username, full_name, student_class, address): students_collection.update_one({"username": username}, {"$set": {"full_name": full_name, "student_class": student_class, "address": address}})
def get_todays_activity(username):
    # TIMEZONE FIX: Use datetime.now(IST).date()
    today_date_str = datetime.now(IST).date().isoformat()
    return activities_collection.find_one({"username": username, "date": today_date_str})
def check_in_student(username, check_in_time):
    # TIMEZONE FIX: Use datetime.now(IST).date() and datetime.now(IST)
    today_date_str = datetime.now(IST).date().isoformat()
    activities_collection.update_one(
        {"username": username, "date": today_date_str},
        {"$set": {
            "username": username,
            "date": today_date_str,
            "check_in": check_in_time.isoformat(),
            "recorded_at": datetime.now(IST)
        }},
        upsert=True
    )
def check_out_student(username, check_out_time, task, doubt):
    # TIMEZONE FIX: Use datetime.now(IST).date()
    today_date_str = datetime.now(IST).date().isoformat()
    activities_collection.update_one(
        {"username": username, "date": today_date_str},
        {"$set": {
            "check_out": check_out_time.isoformat(),
            "task_description": task,
            "doubt": doubt
        }}
    )
def get_student_activities(username, start_date=None, end_date=None):
    query = {"username": username};
    if start_date and end_date: query["date"] = {"$gte": start_date.isoformat(), "$lte": end_date.isoformat()}
    return list(activities_collection.find(query).sort("date", -1))
def get_all_students_details(): return list(students_collection.find({}, {"password": 0}))
def delete_student_data(username): activities_collection.delete_many({"username": username}); messages_collection.delete_many({"to_username": username}); students_collection.delete_one({"username": username})
def send_message_to_student(to_username, message_text):
    # TIMEZONE FIX: Use datetime.now(IST)
    messages_collection.insert_one({"to_username": to_username, "from_user": "Admin", "message": message_text, "sent_at": datetime.now(IST)})
def broadcast_message_to_all(message_text):
    for student in get_all_students_details(): send_message_to_student(student['username'], message_text)
def get_messages_for_student(username): return list(messages_collection.find({"to_username": username}).sort("sent_at", -1))
def get_admin_dashboard_stats():
    # TIMEZONE FIX: Use datetime.now(IST).date()
    total = students_collection.count_documents({}); today_str = datetime.now(IST).date().isoformat();
    active = activities_collection.count_documents({"date": today_str, "check_out": {"$exists": False}})
    completed = activities_collection.find({"date": today_str, "check_out": {"$exists": True}});
    hours = sum(calculate_duration(a['check_in'], a['check_out']) for a in completed);
    return total, active, hours

# --- 6. STREAMLIT UI ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False; st.session_state.username = ""; st.session_state.is_admin = False

st.title("👨‍🎓 Student Management System")

if st.session_state.logged_in:
    # ... (Is hisse me koi badlav nahi)
    st.sidebar.success(f"Welcome, {st.session_state.username}!")
    if not st.session_state.is_admin:
        with st.sidebar.expander("✏️ My Profile", expanded=False):
            student_data = get_student_details(st.session_state.username)
            with st.form("ProfileForm"):
                new_full_name = st.text_input("Full Name", value=student_data.get('full_name')); new_class = st.text_input("Class", value=student_data.get('student_class')); new_address = st.text_area("Address", value=student_data.get('address'))
                if st.form_submit_button("Update Profile"): update_student_profile(st.session_state.username, new_full_name, new_class, new_address); st.success("Profile updated!")
    if st.sidebar.button("Log Out", use_container_width=True, type="primary"):
        st.session_state.logged_in = False; st.session_state.username = ""; st.session_state.is_admin = False; st.rerun()

    if st.session_state.is_admin:
        st.header("🔑 Admin Dashboard")
        total, active, hours = get_admin_dashboard_stats(); col1, col2, col3 = st.columns(3);
        col1.metric("Total Students", total); col2.metric("Currently Active", active); col3.metric("Total Hours Today", format_duration(hours));
        st.markdown("---");
        with st.expander("📢 Broadcast a Message to All Students"):
            with st.form("BroadcastForm"):
                broadcast_msg = st.text_area("Enter your message here:");
                if st.form_submit_button("Send Broadcast"):
                    if broadcast_msg: broadcast_message_to_all(broadcast_msg); st.success("Broadcast message sent!");
                    else: st.warning("Message cannot be empty.");
        st.subheader("Student Details & Management");
        search_query = st.text_input("Search Students (by name or username)", placeholder="Type here to filter...")
        filt_col1, filt_col2 = st.columns(2);
        
        # TIMEZONE FIX: Use datetime.now(IST).date() for default date inputs
        today_ist = datetime.now(IST).date()
        start_date_input = filt_col1.date_input("Start Date", today_ist - relativedelta(months=1)); 
        end_date_input = filt_col2.date_input("End Date", today_ist);
        
        all_students = get_all_students_details()
        if not all_students: st.info("No students have registered yet.")
        filtered_students = [s for s in all_students if search_query.lower() in s['full_name'].lower() or search_query.lower() in s['username'].lower()] if search_query else all_students
        for student in filtered_students:
            todays_activity = get_todays_activity(student['username']); is_checked_in = todays_activity and 'check_out' not in todays_activity; status_icon = "🟢" if is_checked_in else "⚪️";
            with st.expander(f"{status_icon} **{student['full_name']}** (@{student['username']})"):
                st.subheader("Personal Information"); info_col1, info_col2 = st.columns(2)
                with info_col1: st.markdown(f"**Class:** {student.get('student_class', 'N/A')}"); st.markdown(f"**Phone:** {student.get('phone', 'N/A')}")
                with info_col2: reg_date = student.get('registered_on'); st.markdown(f"**Registered On:** {reg_date.strftime('%d-%b-%Y') if reg_date else 'N/A'}"); st.markdown(f"**Reference:** {student.get('reference', 'N/A')}")
                st.markdown(f"**Address:** {student.get('address', 'N/A')}"); st.markdown("---")
                tab1, tab2, tab3 = st.tabs(["Activity Log", "Send Message", "Danger Zone"])
                with tab1:
                    activities = get_student_activities(student['username'], start_date_input, end_date_input)
                    if activities:
                        df = pd.DataFrame([{"Date": a.get('date'), "Check-in": format_to_12hr(a['check_in']), "Check-out": format_to_12hr(a.get('check_out')) if a.get('check_out') else 'Active', "Duration": format_duration(calculate_duration(a['check_in'], a.get('check_out', a['check_in']))), "Task": a.get('task_description', 'N/A'), "Doubts": a.get('doubt', '')} for a in activities])
                        st.dataframe(df, use_container_width=True, hide_index=True)
                        pdf_data = generate_pdf_report(student, activities); st.download_button(label="Download Report as PDF", data=pdf_data, file_name=f"{student['username']}_report.pdf", mime="application/pdf")
                    else: st.info("No activities recorded in the selected date range.")
                with tab2:
                    with st.form(key=f"msg_{student['username']}"):
                        message_text = st.text_area("Message", height=100)
                        if st.form_submit_button("Send"):
                            if message_text: send_message_to_student(student['username'], message_text); st.success("Message sent!")
                with tab3:
                    if st.checkbox("I understand and want to delete this student", key=f"del_check_{student['username']}"):
                        if st.button("🔴 PERMANENTLY DELETE", key=f"del_btn_{student['username']}"): delete_student_data(student['username']); st.success(f"Successfully deleted {student['full_name']}."); st.rerun()
    else:
        # --- STUDENT DASHBOARD ---
        is_deployed = st.secrets.get("IS_DEPLOYED", "false").lower() == "true"
        if not is_deployed:
            current_ssid = get_current_ssid()
            allowed_ssids_list = [ssid.strip().lower() for ssid in ALLOWED_WIFI_SSID.split(',')]
            is_on_correct_network = (current_ssid and current_ssid.lower() in allowed_ssids_list)
        else:
            is_on_correct_network = True

        if not is_on_correct_network:
            st.error("**Security Alert: You are not on the designated network.**", icon="🔒")
            st.warning(f"Please connect to one of the authorized Wi-Fi networks: **{', '.join([s.upper() for s in ALLOWED_WIFI_SSID.split(',')])}**")
            st.info(f"**Your Current SSID:** `{current_ssid or 'Not Connected'}`")
            if st.button("Refresh Connection"): st.rerun()
        else:
            st.header(f"📅 Welcome to Your Dashboard, {st.session_state.username}")
            messages = get_messages_for_student(st.session_state.username)
            if messages:
                with st.expander("📬 You have new messages from the Admin!", expanded=True):
                    for msg in messages: st.info(f"**{msg['sent_at'].astimezone(IST).strftime('%d-%b-%Y %I:%M %p')}:** {msg['message']}")
            all_my_activities = get_student_activities(st.session_state.username)
            if all_my_activities:
                df_stats = pd.DataFrame(all_my_activities); df_stats['duration_hours'] = df_stats.apply(lambda row: calculate_duration(row['check_in'], row.get('check_out', row['check_in'])), axis=1)
                # TIMEZONE FIX: Use datetime.now(IST).date()
                this_month_start = datetime.now(IST).date().replace(day=1).isoformat(); monthly_hours = df_stats[df_stats['date'] >= this_month_start]['duration_hours'].sum()
                avg_hours = df_stats[df_stats['duration_hours'] > 0]['duration_hours'].mean(); longest_session = df_stats['duration_hours'].max()
                stat_col1, stat_col2, stat_col3 = st.columns(3); stat_col1.metric("Hours This Month", format_duration(monthly_hours)); stat_col2.metric("Avg. Daily Hours", format_duration(avg_hours) if pd.notna(avg_hours) else "N/A"); stat_col3.metric("Longest Session", format_duration(longest_session)); st.markdown("---")
            
            todays_activity = get_todays_activity(st.session_state.username)
            is_checked_in = todays_activity and 'check_out' not in todays_activity
            
            col1, col2 = st.columns((1, 2))
            with col1:
                st.subheader("Today's Action")
                if is_checked_in:
                    st.metric(label="Status", value="Checked-In", delta=f"at {format_to_12hr(todays_activity['check_in'])}")
                    with st.form("CheckOutForm"):
                        # TIMEZONE FIX: Set default time for checkout to current IST time
                        check_out_time_input = st.time_input("Check-out Time", value=datetime.now(IST).time())
                        task = st.text_area("Task Description for Today")
                        doubt = st.text_area("Any Doubts? (Optional)")
                        if st.form_submit_button("CHECK OUT NOW", use_container_width=True, type="primary"):
                            check_in_time_obj = time.fromisoformat(todays_activity['check_in'])
                            if check_out_time_input < check_in_time_obj: st.error("Validation Error: Check-out time cannot be earlier than check-in time.")
                            elif not task: st.warning("Please describe your task before checking out.")
                            else:
                                check_out_student(st.session_state.username, check_out_time_input, task, doubt)
                                st.success("Checked out successfully!"); py_time.sleep(1); st.balloons(); st.rerun()
                elif todays_activity and 'check_out' in todays_activity:
                    st.metric(label="Status", value="Completed"); st.success("Session for today is complete. Well done!")
                else:
                    st.metric(label="Status", value="Ready to Start")
                    with st.form("CheckInForm"):
                        st.success(f"Connected to '{get_current_ssid()}'. You can now check-in.", icon="✅")
                        # TIMEZONE FIX: Set default time for checkin to current IST time
                        check_in_time_input = st.time_input("Check-in Time", value=datetime.now(IST).time())
                        if st.form_submit_button("CHECK IN", use_container_width=True):
                            check_in_student(st.session_state.username, check_in_time_input)
                            st.success(f"Checked in at {check_in_time_input.strftime('%I:%M %p')}!")
                            py_time.sleep(1); st.rerun()
            with col2:
                st.subheader("📜 My Full Activity Log")
                if all_my_activities:
                    df_display = pd.DataFrame([{"Date": a.get('date'), "Check-in": format_to_12hr(a.get('check_in')), "Check-out": format_to_12hr(a.get('check_out')) if a.get('check_out') else 'Active', "Duration": format_duration(calculate_duration(a['check_in'], a.get('check_out', a['check_in']))), "Task": a.get('task_description', 'N/A'), "Doubts": a.get('doubt', '')} for a in all_my_activities])
                    st.dataframe(df_display, use_container_width=True, hide_index=True)
                else: st.info("You have no recorded activities yet.")
else:
    # ... (Login/Register page me koi khaas badlav nahi, kyonki wahan time ka display nahi hai)
    with st.sidebar.expander("🔑 Admin Login", expanded=False):
        with st.form("AdminForm"):
            admin_username = st.text_input("Admin Username"); admin_password = st.text_input("Admin Password", type="password")
            if st.form_submit_button("Login as Admin"):
                if admin_username == ADMIN_USER and admin_password == ADMIN_PASS:
                    st.session_state.logged_in = True; st.session_state.username = "Admin"; st.session_state.is_admin = True; st.rerun()
                else: st.error("Invalid Admin credentials.")
    
    is_deployed = st.secrets.get("IS_DEPLOYED", "false").lower() == "true"
    if not is_deployed:
        st.subheader("Network Security Check")
        current_ssid = get_current_ssid()
        allowed_ssids_list = [ssid.strip().lower() for ssid in ALLOWED_WIFI_SSID.split(',')]
        is_on_correct_network = (current_ssid and current_ssid.lower() in allowed_ssids_list)
    else: is_on_correct_network = True
    
    if not is_on_correct_network:
        st.error("**Access Denied: You are not on the required network.**", icon="🚫")
        st.warning(f"Please connect to one of the authorized Wi-Fi networks: **{', '.join([s.upper() for s in ALLOWED_WIFI_SSID.split(',')])}**")
        st.info(f"**Your Current SSID:** `{current_ssid or 'Not Connected'}`")
        if st.button("Retry Connection Check"): st.rerun()
    else:
        if is_deployed: st.info("Welcome! Please log in or register to continue.")
        else: st.success(f"Secure network '{current_ssid}' detected. You can proceed.", icon="✅")
        
        login_tab, register_tab = st.tabs(["👨‍🎓 Student Login", "✍️ Register"])
        with register_tab:
            st.subheader("Create a New Student Account")
            with st.form("RegisterForm", border=False):
                full_name = st.text_input("Full Name"); student_class = st.text_input("Class with Year"); phone = st.text_input("Phone Number"); address = st.text_area("Address"); reference = st.text_input("Reference (Optional)"); st.markdown("---")
                reg_username = st.text_input("Username"); reg_password = st.text_input("Password", type="password")
                if st.form_submit_button("Register", use_container_width=True):
                    if all([full_name, student_class, phone, address, reg_username, reg_password]):
                        success, message = register_student(reg_username, reg_password, full_name, student_class, phone, address, reference)
                        if success: st.success(message); py_time.sleep(1); st.session_state.logged_in = True; st.session_state.username = reg_username; st.session_state.is_admin = False; st.rerun()
                        else: st.error(message)
                    else: st.warning("Please fill out all required fields.")
        with login_tab:
            st.subheader("Login to Your Student Account")
            with st.form("LoginForm", border=False):
                username = st.text_input("Username"); password = st.text_input("Password", type="password")
                if st.form_submit_button("Login", use_container_width=True):
                    success, message = login_student(username, password)
                    if success: st.session_state.logged_in = True; st.session_state.username = username; st.session_state.is_admin = False; st.rerun()
                    else: st.error(message)
