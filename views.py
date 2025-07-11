import streamlit as st
import pandas as pd
from datetime import datetime, time, date
from dateutil.relativedelta import relativedelta
from io import BytesIO
from fpdf import FPDF, XPos, YPos
import models
import re # Email validation ke liye

# --- UTILITY FUNCTIONS FOR VIEW ---
def calculate_duration(check_in_str, check_out_str):
    if not all([check_in_str, check_out_str]): return 0.0
    try:
        check_in = time.fromisoformat(check_in_str); check_out = time.fromisoformat(check_out_str)
        if check_out < check_in: return 0.0
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

def is_valid_email(email):
    """Simple email format validation."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def generate_pdf_report(student: dict, activities: list) -> BytesIO:
    # ... PDF generation logic (yeh pehle se hi kaafi aaccha hai, ismein badlav nahi) ...
    pdf = FPDF()
    try:
        pdf.add_font('DejaVu', '', 'fonts/DejaVuSans.ttf', uni=True)
        pdf.add_font('DejaVu', 'B', 'fonts/DejaVuSans.ttf', uni=True)
        font_family = 'DejaVu'
    except RuntimeError: font_family = 'Arial'
    
    pdf.add_page(); pdf.set_font(font_family, 'B', 16); pdf.cell(0, 10, 'Student Activity Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C'); pdf.ln(5)
    pdf.set_font(font_family, 'B', 12); pdf.cell(0, 8, f"Student: {student.get('full_name', 'N/A')} (@{student.get('username', 'N/A')})", new_x=XPos.LMARGIN, new_y=YPos.NEXT); pdf.ln(10)
    
    if not activities: pdf.set_font(font_family, '', 12); pdf.cell(0, 10, "No activities recorded.")
    else:
        pdf.set_font(font_family, 'B', 10); col_widths = { "date": 25, "check_in": 30, "check_out": 30, "duration": 25 }; page_width = pdf.w - pdf.l_margin - pdf.r_margin; task_col_width = page_width - sum(col_widths.values())
        pdf.cell(col_widths["date"], 8, 'Date', 1, 0, 'C'); pdf.cell(col_widths["check_in"], 8, 'Check-in', 1, 0, 'C'); pdf.cell(col_widths["check_out"], 8, 'Check-out', 1, 0, 'C'); pdf.cell(col_widths["duration"], 8, 'Duration', 1, 0, 'C'); pdf.cell(task_col_width, 8, 'Task', 1, 1, 'C')
        pdf.set_font(font_family, '', 9)
        for act in activities:
            x_start, y_start = pdf.get_x(), pdf.get_y(); pdf.cell(col_widths["date"], 8, str(act.get('date', '')), 1, 0); pdf.cell(col_widths["check_in"], 8, format_to_12hr(act.get('check_in')), 1, 0); pdf.cell(col_widths["check_out"], 8, format_to_12hr(act.get('check_out')), 1, 0); pdf.cell(col_widths["duration"], 8, format_duration(calculate_duration(act.get('check_in'), act.get('check_out'))), 1, 0); pdf.set_xy(x_start + sum(col_widths.values()), y_start); pdf.multi_cell(task_col_width, 8, str(act.get('task_description', 'N/A')), 1, 'L')
    return BytesIO(pdf.output())

# --- MAIN VIEW FUNCTIONS ---
def show_login_page():
    st.info("Welcome! Please log in, register, or use the 'Forgot Password' option if needed.")
    login_tab, register_tab, forgot_tab = st.tabs(["👨‍🎓 Student Login", "✍️ Register", "🔑 Forgot Password"])
    result = {}

    with login_tab:
        with st.form("LoginForm"):
            username = st.text_input("Username"); password = st.text_input("Password", type="password")
            if st.form_submit_button("Login", use_container_width=True): result = {"form_name": "login", "data": {"username": username, "password": password}}

    with register_tab:
        with st.form("RegisterForm"):
            full_name = st.text_input("Full Name"); email = st.text_input("Email Address"); student_class = st.text_input("Class"); phone = st.text_input("Phone Number"); address = st.text_area("Address"); reference = st.text_input("Reference (Optional)"); st.markdown("---")
            reg_username = st.text_input("Choose a Username"); reg_password = st.text_input("Choose a Password", type="password")
            if st.form_submit_button("Register", use_container_width=True):
                data = {"full_name": full_name, "email": email, "student_class": student_class, "phone": phone, "address": address, "reference": reference, "username": reg_username, "password": reg_password}
                if not all(v for k, v in data.items() if k not in ['reference', 'password']): st.warning("Please fill all required fields.")
                elif not is_valid_email(email): st.error("Please enter a valid email address.")
                else: result = {"form_name": "register", "data": data}

    with forgot_tab:
        if 'otp_step' not in st.session_state: st.session_state.otp_step = 1
        if st.session_state.otp_step == 1:
            st.info("Enter your registered email to receive a One-Time Password (OTP).")
            with st.form("SendOTPForm"):
                email = st.text_input("Email Address")
                if st.form_submit_button("Send OTP", use_container_width=True):
                    if not is_valid_email(email): st.error("Please enter a valid email format.")
                    else: st.session_state.reset_email = email; result = {"form_name": "send_otp", "data": {"email": email}}
        elif st.session_state.otp_step == 2:
            st.success(f"An OTP was sent to {st.session_state.get('reset_email')}."); st.write("Please check your inbox and enter the OTP below.")
            with st.form("VerifyOTPForm"):
                otp = st.text_input("6-digit OTP", max_chars=6); new_password = st.text_input("New Password", type="password"); confirm_password = st.text_input("Confirm New Password", type="password")
                if st.form_submit_button("Reset Password", use_container_width=True):
                    if not new_password or new_password != confirm_password: st.error("Passwords do not match or are empty.")
                    elif not otp: st.warning("Please enter the OTP.")
                    else: result = {"form_name": "verify_otp", "data": {"email": st.session_state.reset_email, "otp": otp, "new_password": new_password}}
            if st.button("Go Back"): del st.session_state.otp_step; st.rerun()
    return result

def show_sidebar(username, is_admin, student_data):
    st.sidebar.title(f"Welcome, {username.capitalize()}!"); result = {}
    if not is_admin:
        with st.sidebar.expander("✏️ My Profile"):
            with st.form("ProfileForm"):
                new_full_name = st.text_input("Full Name", value=student_data.get('full_name', '')); current_email = student_data.get('email', '')
                if not current_email: st.warning("Please add your email to enable features like password reset.")
                new_email = st.text_input("Email Address", value=current_email); new_class = st.text_input("Class", value=student_data.get('student_class', '')); new_address = st.text_area("Address", value=student_data.get('address', ''))
                if st.form_submit_button("Update Profile", use_container_width=True):
                    if not is_valid_email(new_email): st.error("Please enter a valid email address.")
                    else: result = {"action": "update_profile", "data": {"full_name": new_full_name, "email": new_email, "student_class": new_class, "address": new_address}}
    if st.sidebar.button("Log Out", use_container_width=True, type="primary"): result = {"action": "logout"}
    return result

def show_student_dashboard(username, messages, activities, todays_activity):
    st.header(f"📅 Welcome, {username.capitalize()}!");
    if messages:
        with st.expander(f"📬 You have {len(messages)} new message(s)!", expanded=True):
            for msg in messages: st.info(f"**{msg['sent_at'].strftime('%d-%b %I:%M %p')}:** {msg['message']}")
    
    # --- STUDENT STATS ---
    if activities:
        df = pd.DataFrame(activities)
        df['duration'] = df.apply(lambda row: calculate_duration(row['check_in'], row.get('check_out')), axis=1)
        total_sessions = len(df)
        total_hours = df['duration'].sum()
        avg_hours = df['duration'].mean()
        
        stat1, stat2, stat3 = st.columns(3)
        stat1.metric("Total Hours Logged", format_duration(total_hours))
        stat2.metric("Total Sessions", total_sessions)
        stat3.metric("Average Session", format_duration(avg_hours))
        st.divider()

    result = {}; col1, col2 = st.columns((1, 2)); is_checked_in = todays_activity and 'check_out' not in todays_activity
    with col1:
        st.subheader("Today's Action")
        if is_checked_in:
            st.metric("Status", "Checked-In", f"at {format_to_12hr(todays_activity['check_in'])}")
            with st.form("CheckOutForm"):
                task = st.text_area("Task Description"); doubt = st.text_area("Doubts?")
                if st.form_submit_button("CHECK OUT", use_container_width=True, type="primary"):
                    if task: result = {"action": "check_out", "data": {"task": task, "doubt": doubt, "check_out_time": datetime.now().time()}}
                    else: st.warning("Please describe your task.")
        elif todays_activity and 'check_out' in todays_activity:
             st.metric("Status", "Completed for Today"); st.success("Well done! See you tomorrow.")
        else:
            st.metric("Status", "Ready to Start")
            if st.button("CHECK IN", use_container_width=True, type="primary"): result = {"action": "check_in", "data": {"check_in_time": datetime.now().time()}}
    with col2:
        st.subheader("📜 My Full Activity Log")
        if activities:
            df_display = pd.DataFrame([{"Date": a.get('date'), "In": format_to_12hr(a.get('check_in')), "Out": format_to_12hr(a.get('check_out')), "Duration": format_duration(calculate_duration(a.get('check_in'), a.get('check_out'))), "Task": a.get('task_description'), "Doubts": a.get('doubt')} for a in activities])
            st.dataframe(df_display, use_container_width=True, hide_index=True)
        else: st.info("You have no recorded activities yet. Click 'CHECK IN' to start!")
    return result

# Is poore function ko copy-paste kar lein

def show_admin_dashboard(stats, all_students):
    st.header("🔑 Admin Dashboard");
    if st.button("🔄 Refresh Data", use_container_width=True): st.rerun()
    total, active, hours = stats; col1, col2 = st.columns(2)
    col1.metric("Total Students", total); col2.metric("Currently Active", active)
    result = {}
    with st.expander("📢 Broadcast Message"):
        with st.form("BroadcastForm"):
            msg = st.text_area("Message")
            if st.form_submit_button("Send Broadcast", use_container_width=True):
                if msg: result = {"action": "broadcast", "data": {"message": msg}}
    st.subheader("Student Details & Management"); search = st.text_input("Search Students (by name or username)")
    filtered_students = [s for s in all_students if not search or search.lower() in s.get('full_name','').lower() or search.lower() in s.get('username','').lower()]
    
    for student in filtered_students:
        status = "🟢" if student.get('todays_activity', {}).get('check_in') and not student.get('todays_activity', {}).get('check_out') else "⚪️"
        with st.expander(f"{status} **{student.get('full_name')}** (@{student.get('username')})"):
            
            # === YAHAN BADLAAV KIYA GAYA HAI ===
            st.markdown(f"**Class:** {student.get('student_class', 'N/A')}")
            st.markdown(f"**Phone:** {student.get('phone', 'N/A')}")
            st.markdown(f"**Address:** {student.get('address', 'N/A')}")
            st.markdown(f"**Reference:** {student.get('reference', 'N/A')}")
            # === BADLAAV KHATM ===
            # Is line ko add karein 👇
            st.markdown(f"**Email:** {student.get('email', 'N/A')}")

            activities = models.get_student_activities(student['username'])
            tab1, tab2, tab3 = st.tabs(["📊 Activity Log", "✉️ Send Message", "🗑️ Delete"])
            with tab1:
                if activities:
                    df = pd.DataFrame([{"Date": a.get('date'), "In": format_to_12hr(a.get('check_in')), "Out": format_to_12hr(a.get('check_out')), "Duration": format_duration(calculate_duration(a.get('check_in'), a.get('check_out'))), "Task": a.get('task_description')} for a in activities])
                    st.dataframe(df, hide_index=True)
                    st.download_button("Download Report (PDF)", generate_pdf_report(student, activities), f"{student['username']}_report.pdf", "application/pdf", key=f"pdf_{student['username']}", use_container_width=True)
                else: st.info("No activities recorded for this student.")
            with tab2:
                with st.form(f"msg_{student['username']}"):
                    msg = st.text_area("Your Message", key=f"mt_{student['username']}")
                    if st.form_submit_button("Send Message", use_container_width=True):
                        if msg: result = {"action": "send_message", "data": {"to_username": student['username'], "message": msg}}
            with tab3:
                st.error("DANGER: This action is permanent and cannot be undone.")
                if st.checkbox("I understand I am about to delete all data for this student.", key=f"dc_{student['username']}"):
                    if st.button("🔴 PERMANENTLY DELETE", key=f"db_{student['username']}", use_container_width=True): result = {"action": "delete_student", "data": {"username": student['username'], "full_name": student['full_name']}}
    return result