import pymongo
import bcrypt
import streamlit as st
from datetime import datetime, date, time
from dateutil.relativedelta import relativedelta
import uuid
import smtplib
from email.mime.text import MIMEText
import random # OTP ke liye zaroori import

# --- DATABASE CONNECTION ---
@st.cache_resource
def init_connection():
    try:
        client = pymongo.MongoClient(st.secrets["MONGO_CONNECTION_STRING"])
        client.admin.command('ping') 
        return client
    except Exception as e:
        st.error(f"Database connection failed: {e}"); return None

client = init_connection()

if client:
    db = client.student_db
    students_collection = db.students
    activities_collection = db.activities
    messages_collection = db.messages
    sessions_collection = db.sessions
else:
    st.info("App stopped. Please check DB connection."); st.stop()


# --- UTILITY FUNCTIONS ---
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

# --- USER & AUTHENTICATION MODELS ---
def register_student(username, password, full_name, email, student_class, phone, address, reference):
    if students_collection.find_one({"username": username}):
        return False, "This username is already taken."
    if students_collection.find_one({"email": email}):
        return False, "This email address is already registered."
    
    hashed_pass = hash_password(password)
    students_collection.insert_one({
        "username": username, "password": hashed_pass, "full_name": full_name,
        "email": email, "student_class": student_class, "phone": phone, 
        "address": address, "reference": reference, "registered_on": datetime.now()
    })
    return True, "Registration successful!"

def verify_student_credentials(username, password):
    student = students_collection.find_one({"username": username})
    return bool(student and verify_password(password, student.get('password')))


# --- NAYA OTP-BASED PASSWORD RESET LOGIC ---
# Purane token wale functions ko isse replace kiya gaya hai

def create_and_send_otp(email):
    """OTP banata hai, database mein save karta hai, aur email bhejta hai."""
    student = students_collection.find_one({"email": email})
    if not student:
        return False, "No account found with this email address."
    
    otp = str(random.randint(100000, 999999)) # 6-digit OTP
    expiry_date = datetime.now() + relativedelta(minutes=10) # 10 minute ki expiry

    students_collection.update_one(
        {"email": email},
        {"$set": {"otp": otp, "otp_expiry": expiry_date}}
    )
    
    # OTP email bhejein
    sender_email = st.secrets["EMAIL_SENDER"]
    receiver_email = email
    body = (
        f"Hello {student.get('full_name')},\n\n"
        f"Your One-Time Password (OTP) to reset your password is: {otp}\n\n"
        "This OTP is valid for 10 minutes.\n"
        "If you did not request this, please ignore this email."
    )
    message = MIMEText(body)
    message['Subject'] = "Your OTP for Password Reset"
    message['From'] = sender_email
    message['To'] = receiver_email
    
    try:
        with smtplib.SMTP(st.secrets["EMAIL_HOST"], st.secrets["EMAIL_PORT"]) as server:
            server.starttls()
            server.login(sender_email, st.secrets["EMAIL_PASSWORD"])
            server.sendmail(sender_email, receiver_email, message.as_string())
        return True, "An OTP has been sent to your email address."
    except Exception as e:
        st.error(f"Email Error: {e}")
        return False, "Failed to send OTP. Please contact the administrator."

def verify_otp_and_reset_password(email, otp, new_password):
    """OTP ko verify karta hai aur password reset karta hai."""
    student = students_collection.find_one({
        "email": email,
        "otp": otp,
        "otp_expiry": {"$gt": datetime.now()}
    })

    if not student:
        return False, "Invalid or expired OTP. Please request a new one."
    
    hashed_pass = hash_password(new_password)
    students_collection.update_one(
        {"_id": student["_id"]},
        {"$set": {"password": hashed_pass}, "$unset": {"otp": "", "otp_expiry": ""}}
    )
    return True, "Your password has been updated successfully!"


# --- SESSION MODELS ---
def create_user_session(username, is_admin=False):
    session_token = str(uuid.uuid4())
    expiry_date = datetime.now() + relativedelta(days=30)
    sessions_collection.insert_one({"session_token": session_token, "username": username, "is_admin": is_admin, "expires_at": expiry_date})
    return session_token

def verify_user_session(token):
    if not token: return None
    session_data = sessions_collection.find_one({"session_token": token})
    if session_data and session_data.get('expires_at') > datetime.now():
        return session_data
    if session_data: sessions_collection.delete_one({"session_token": token})
    return None

def delete_user_session(token):
    if token: sessions_collection.delete_one({"session_token": token})

# --- DATA RETRIEVAL MODELS ---
def get_student_details(username):
    return students_collection.find_one({"username": username}, {"password": 0})

def get_all_students_details():
    return list(students_collection.find({}, {"password": 0}))

def get_todays_activity(username):
    activity = activities_collection.find_one({"username": username, "date": date.today().isoformat()})
    return activity if activity else {}

def get_student_activities(username, start_date=None, end_date=None):
    query = {"username": username}
    if start_date and end_date:
        query["date"] = {"$gte": start_date.isoformat(), "$lte": end_date.isoformat()}
    return list(activities_collection.find(query).sort("date", -1))

def get_messages_for_student(username):
    return list(messages_collection.find({"to_username": username}).sort("sent_at", -1))

def get_admin_dashboard_stats():
    total = students_collection.count_documents({})
    today_str = date.today().isoformat()
    active = activities_collection.count_documents({"date": today_str, "check_out": {"$exists": False}})
    completed_activities = activities_collection.find({"date": today_str, "check_out": {"$exists": True}})
    total_seconds = 0
    for a in completed_activities:
        try:
            check_in, check_out = time.fromisoformat(a['check_in']), time.fromisoformat(a['check_out'])
            delta = datetime.combine(date.today(), check_out) - datetime.combine(date.today(), check_in)
            if delta.total_seconds() > 0:
                total_seconds += delta.total_seconds()
        except (ValueError, TypeError): continue
    return total, active, (total_seconds / 3600)

# --- DATA MODIFICATION MODELS ---
def update_student_profile(username, full_name, email, student_class, address):
    existing_user = students_collection.find_one({"email": email})
    if existing_user and existing_user.get('username') != username:
        return False, "This email is already registered to another account."
        
    students_collection.update_one(
        {"username": username}, 
        {"$set": {"full_name": full_name, "email": email, "student_class": student_class, "address": address}}
    )
    return True, "Profile updated successfully."

def check_in_student(username, check_in_time):
    activities_collection.update_one({"username": username, "date": date.today().isoformat()}, {"$set": {"username": username, "date": date.today().isoformat(), "check_in": check_in_time.isoformat(), "recorded_at": datetime.now()}}, upsert=True)

def check_out_student(username, check_out_time, task, doubt):
    activities_collection.update_one({"username": username, "date": date.today().isoformat()}, {"$set": {"check_out": check_out_time.isoformat(), "task_description": task, "doubt": doubt}})

def delete_student_data(username):
    try:
        students_collection.delete_one({"username": username})
        activities_collection.delete_many({"username": username})
        messages_collection.delete_many({"to_username": username})
        return True
    except Exception as e:
        st.error(f"Error deleting data: {e}"); return False

def send_message_to_student(to_username, message_text):
    messages_collection.insert_one({"to_username": to_username, "from_user": "Admin", "message": message_text, "sent_at": datetime.now()})

def broadcast_message_to_all(message_text):
    for student in get_all_students_details():
        send_message_to_student(student['username'], message_text)