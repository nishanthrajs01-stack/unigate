import os
import io
import random
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
from collections import Counter
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth

# --- CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'unigate-mega-key-2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# --- EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'unigateadmission1@gmail.com'
app.config['MAIL_PASSWORD'] = 'hiux aufg tktp rgnl' 
app.config['MAIL_DEFAULT_SENDER'] = ('Unigate Security', 'unigateadmission1@gmail.com')

# --- GOOGLE CREDENTIALS ---
app.config['GOOGLE_CLIENT_ID'] = '1052305437274-u61jeaaukuqbbplcq4k66larpkb5t19g.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'

mail = Mail(app)
oauth = OAuth(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- GOOGLE REGISTRATION ---
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100))
    course = db.Column(db.String(50))
    
    # Status: 0=Rejected, 1=Pending, 2=Verified, 3=Review, 4=Admitted
    application_status = db.Column(db.Integer, default=1)
    rejection_reason = db.Column(db.String(500)) # NEW COLUMN FOR REASON

    student_phone = db.Column(db.String(20))
    parent_phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    marks_12th = db.Column(db.String(20))
    marks_10th_file = db.Column(db.String(100))
    marks_12th_file = db.Column(db.String(100))
    auth_provider = db.Column(db.String(20), default='email')

class College(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(50), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    fees = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    image_file = db.Column(db.String(100), nullable=False, default='default.jpg')
    fee_file = db.Column(db.String(100))

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- FORMS ---
class NoticeForm(FlaskForm):
    message = StringField('New Notice Message', validators=[DataRequired()])
    submit = SubmitField('Post Notice')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Enter your Registered Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send OTP')

class OTPForm(FlaskForm):
    otp = StringField('Enter 6-Digit OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    course = SelectField('Interested Course', choices=[('BCA', 'BCA'), ('BBA', 'BBA'), ('BTech', 'B.Tech'), ('Nursing', 'Nursing'), ('MBA', 'MBA')])
    student_phone = StringField('Student Phone', validators=[DataRequired(), Length(min=10)])
    parent_phone = StringField('Parent Phone', validators=[DataRequired(), Length(min=10)])
    address = TextAreaField('Permanent Address', validators=[DataRequired()])
    marks_12th = StringField('12th Grade Percentage / CGPA', validators=[DataRequired()])
    marks_10th_file = FileField('Upload 10th Marks Card', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'pdf'])])
    marks_12th_file = FileField('Upload 12th Marks Card', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'pdf'])])
    submit = SubmitField('Submit Application')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class UpdateProfileForm(FlaskForm):
    course = SelectField('Select Course', choices=[('BCA', 'BCA'), ('BBA', 'BBA'), ('BTech', 'B.Tech'), ('Nursing', 'Nursing'), ('MBA', 'MBA')])
    marks_12th = StringField('12th Grade % / CGPA', validators=[DataRequired()])
    student_phone = StringField('Student Phone', validators=[DataRequired(), Length(min=10)])
    parent_phone = StringField('Parent Phone', validators=[DataRequired(), Length(min=10)])
    address = TextAreaField('Permanent Address', validators=[DataRequired()])
    marks_10th_file = FileField('Upload 10th Marks Card', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'pdf'])])
    marks_12th_file = FileField('Upload 12th Marks Card', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'pdf'])])
    submit = SubmitField('Complete Registration')

class CollegeForm(FlaskForm):
    name = StringField('College Name', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    course = SelectField('Course', choices=[('BCA', 'BCA'), ('BBA', 'BBA'), ('BTech', 'B.Tech'), ('Nursing', 'Nursing')])
    fees = StringField('Total Package', validators=[DataRequired()])
    description = TextAreaField('Key Highlights')
    image_file = FileField('College Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    fee_file = FileField('Brochure PDF', validators=[FileAllowed(['pdf'])])
    submit = SubmitField('Save College')

class MentorForm(FlaskForm):
    topic = SelectField('Topic', choices=[('Course Details', 'Course Details'), ('Hostel Life', 'Hostel Life'), ('Placements', 'Placements')])
    message = TextAreaField('What do you want to ask?')
    submit = SubmitField('Request Call')

# --- EMAIL LOGIC ---
def send_otp_email(email, otp):
    try:
        msg = Message("Password Reset OTP - Unigate", recipients=[email])
        msg.body = f"Your OTP for password reset is: {otp}\n\nDo not share this code with anyone."
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

def send_confirmation_email(user):
    try:
        msg = Message(f"Application Received - Ref ID: 2026-{user.id}", recipients=[user.email])
        msg.body = f"Dear {user.name},\n\nWe have received your application for {user.course}.\n\nAPP ID: {user.id}\nStatus: Pending Verification\n\nRegards,\nUnigate Team"
        mail.send(msg)
    except Exception as e:
        print(f"Error sending confirmation email: {e}")

def send_status_update_email(user, status_code):
    try:
        subject = "Update on your Admission Application"
        body = f"Dear {user.name},\n\nYour application status has been updated.\n\n"
        if status_code == 2:
            body += "NEW STATUS: DOCUMENTS VERIFIED\nWe have successfully verified your 10th and 12th marks cards."
        elif status_code == 3:
            body += "NEW STATUS: UNDER REVIEW\nYour profile has been shortlisted and is being reviewed by the college board."
        elif status_code == 4:
            subject = "Congratulations! Admission Offer Inside"
            body += "NEW STATUS: ADMITTED\n\nCongratulations! You have been selected. Please login to download your Offer Letter."
        body += "\n\nLogin here: http://127.0.0.1:5007/login\n\nRegards,\nUnigate Admissions Team"
        msg = Message(subject, recipients=[user.email])
        msg.body = body
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending status email: {e}")
        return False

# NEW: SPECIFIC FUNCTION FOR REJECTION EMAIL
def send_rejection_email(user, reason):
    try:
        msg = Message("Important: Update on your Admission Application", recipients=[user.email])
        msg.body = f"""Dear {user.name},

We regret to inform you that your application for {user.course} has been REJECTED.

REASON FOR REJECTION:
{reason}

If you believe this is an error, please contact the admin via the Mentorship portal or reply to this email.

Regards,
Unigate Admissions Team
"""
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending rejection email: {e}")
        return False

def send_admin_alert_email(student_name, topic, message):
    try:
        msg = Message(f"New Mentorship Request: {topic}", recipients=['unigateadmission1@gmail.com'])
        msg.body = f"ADMIN ALERT\n\nStudent: {student_name}\nTopic: {topic}\n\nMessage:\n{message}\n\nPlease contact them back."
        mail.send(msg)
    except Exception as e:
        print(f"Error sending admin alert: {e}")

# --- ROUTES ---
@app.route('/')
def home():
    all_colleges = College.query.all()
    locations = sorted(list(set([c.location for c in all_colleges])))
    return render_template('index.html', colleges=all_colleges, locations=locations)

@app.route('/tools', methods=['GET', 'POST'])
def tools():
    recommendation = None
    if request.method == 'POST':
        interest = request.form.get('interest')
        if interest == 'coding': recommendation = "BCA or B.Tech (CSE)"
        elif interest == 'management': recommendation = "BBA or MBA"
        elif interest == 'medical': recommendation = "B.Sc Nursing"
        elif interest == 'arts': recommendation = "B.Des or Mass Comm"
        else: recommendation = "BCA - Versatile Choice"
    return render_template('tools.html', recommendation=recommendation)

@app.route('/mentorship', methods=['GET', 'POST'])
@login_required
def mentorship():
    form = MentorForm()
    if form.validate_on_submit():
        send_admin_alert_email(current_user.name, form.topic.data, form.message.data)
        flash('Request sent! We have emailed the admin.', 'success')
        return redirect(url_for('mentorship'))
    return render_template('mentorship.html', form=form)

@app.route('/login/google')
def google_login():
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = google.userinfo()
    email = user_info['email']
    name = user_info['name']
    user = User.query.filter_by(email=email).first()
    if not user:
        dummy_pw = generate_password_hash("google_oauth_user_secure")
        user = User(
            email=email, name=name, password_hash=dummy_pw, 
            auth_provider='google', course='Not Selected', application_status=1
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created via Google! Please complete your profile.', 'info')
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Account exists.', 'info')
            return redirect(url_for('login'))
        filename_10th = None
        if form.marks_10th_file.data:
            f = form.marks_10th_file.data
            filename_10th = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_10th))
        filename_12th = None
        if form.marks_12th_file.data:
            f = form.marks_12th_file.data
            filename_12th = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_12th))
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(
            email=form.email.data, password_hash=hashed_pw, name=form.name.data, 
            course=form.course.data, student_phone=form.student_phone.data,
            parent_phone=form.parent_phone.data, address=form.address.data,
            marks_12th=form.marks_12th.data, marks_10th_file=filename_10th,
            marks_12th_file=filename_12th, auth_provider='email'
        )
        db.session.add(new_user)
        db.session.commit()
        send_confirmation_email(new_user)
        flash('Application submitted!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            if user.email == "unigateadmission1@gmail.com":
                return redirect(url_for('admin'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_otp'] = otp
            session['reset_email'] = form.email.data
            send_otp_email(form.email.data, otp)
            flash('OTP sent to your email.', 'info')
            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found in our system.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if form.validate_on_submit():
        if 'reset_otp' in session and form.otp.data == session['reset_otp']:
            flash('OTP Verified! Set your new password.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid OTP. Try again.', 'danger')
    return render_template('verify_otp.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=session['reset_email']).first()
        if user:
            hashed_pw = generate_password_hash(form.password.data)
            user.password_hash = hashed_pw
            db.session.commit()
            session.pop('reset_otp', None)
            session.pop('reset_email', None)
            flash('Password reset successfully! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error resetting password.', 'danger')
    return render_template('reset_password.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.course == 'Not Selected' or current_user.course is None:
        flash('Please complete your registration details.', 'warning')
        return redirect(url_for('complete_registration'))
    latest_notice = Notice.query.order_by(Notice.date_posted.desc()).first()
    return render_template('dashboard.html', user=current_user, notice=latest_notice)

@app.route('/complete_registration', methods=['GET', 'POST'])
@login_required
def complete_registration():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.student_phone = form.student_phone.data
        current_user.parent_phone = form.parent_phone.data
        current_user.address = form.address.data
        current_user.course = form.course.data
        current_user.marks_12th = form.marks_12th.data
        
        if form.marks_10th_file.data:
            f = form.marks_10th_file.data
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.marks_10th_file = filename
            
        if form.marks_12th_file.data:
            f = form.marks_12th_file.data
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.marks_12th_file = filename
            
        send_confirmation_email(current_user)
        db.session.commit()
        flash('Registration Completed!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('complete_registration.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.email != "unigateadmission1@gmail.com": return redirect(url_for('dashboard'))
    all_students = User.query.filter(User.email != "unigateadmission1@gmail.com").all()
    courses = [s.course for s in all_students if s.course]
    course_counts = dict(Counter(courses))
    statuses = [s.application_status for s in all_students]
    status_counts = dict(Counter(statuses))
    
    notice_form = NoticeForm()
    if notice_form.validate_on_submit():
        new_notice = Notice(message=notice_form.message.data)
        db.session.add(new_notice)
        db.session.commit()
        flash('Notice Updated Successfully!', 'success')
        return redirect(url_for('admin'))

    form = CollegeForm()
    if form.validate_on_submit():
        image_filename = 'default.jpg'
        if form.image_file.data:
            img = form.image_file.data
            image_filename = secure_filename(img.filename)
            img.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        pdf_filename = None
        if form.fee_file.data:
            pdf = form.fee_file.data
            pdf_filename = secure_filename(pdf.filename)
            pdf.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))
        new_college = College(
            name=form.name.data, location=form.location.data, course=form.course.data,
            fees=form.fees.data, description=form.description.data, image_file=image_filename, fee_file=pdf_filename
        )
        db.session.add(new_college)
        db.session.commit()
        flash('College added.', 'success')
        return redirect(url_for('admin'))
    
    colleges = College.query.all()
    return render_template('admin.html', students=all_students, colleges=colleges, form=form, notice_form=notice_form, course_counts=course_counts, status_counts=status_counts)

# NEW: ROUTE TO REJECT STUDENT
@app.route('/reject_student/<int:user_id>', methods=['POST'])
@login_required
def reject_student(user_id):
    if current_user.email != "unigateadmission1@gmail.com": return redirect(url_for('dashboard'))
    
    reason = request.form.get('rejection_reason')
    user = User.query.get_or_404(user_id)
    
    user.application_status = 0 # 0 means Rejected
    user.rejection_reason = reason
    
    # Send the custom email
    send_rejection_email(user, reason)
    
    db.session.commit()
    flash(f'Student Rejected. Email sent with reason: "{reason}"', 'danger')
    return redirect(url_for('admin'))

@app.route('/offer_letter/<int:user_id>')
@login_required
def offer_letter(user_id):
    if current_user.email != "unigateadmission1@gmail.com" and current_user.id != user_id:
        flash('Unauthorized Access!', 'danger')
        return redirect(url_for('dashboard'))
    student = User.query.get_or_404(user_id)
    if student.application_status != 4:
        flash('Admission Pending.', 'warning')
        return redirect(url_for('dashboard'))
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 24)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(0, 20, txt="UNIGATE CONSULTANCY", ln=1, align='C')
    pdf.set_font("Arial", '', 10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 5, txt="Registered Office: #45, 2nd Floor, MG Road, Bangalore - 560001", ln=1, align='C')
    pdf.cell(0, 5, txt="Email: admissions@unigate.com | Phone: +91 98765 43210", ln=1, align='C')
    pdf.ln(10)
    pdf.line(10, 35, 200, 35)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(100, 10, txt=f"Ref No: UNIGATE/2026/ADM/{student.id}", ln=0)
    pdf.cell(90, 10, txt="Date: 29th January 2026", ln=1, align='R')
    pdf.ln(10)
    pdf.set_font("Arial", '', 11)
    pdf.cell(0, 6, txt="To,", ln=1)
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 6, txt=f"Mr./Ms. {student.name}", ln=1)
    pdf.set_font("Arial", '', 11)
    pdf.cell(0, 6, txt=f"Email: {student.email}", ln=1)
    if student.address:
        pdf.multi_cell(0, 6, txt=f"Address: {student.address}")
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(0, 10, txt=f"Subject: PROVISIONAL ADMISSION OFFER FOR {student.course.upper()} - 2026 BATCH", ln=1, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", '', 11)
    body_text = (
        f"Dear {student.name},\n\n"
        f"We are pleased to inform you that based on your academic performance in the 12th Grade "
        f"({student.marks_12th}) and the subsequent verification of your documents, the Admissions Committee "
        f"has selected you for the {student.course} program for the academic year 2026-2027.\n\n"
        "This offer is provisional and subject to the following terms and conditions:\n"
    )
    pdf.multi_cell(0, 6, body_text)
    pdf.ln(5)
    terms = [
        "1. You must submit your original 10th and 12th marks cards within 15 days.",
        "2. The first semester fee must be paid before February 15th, 2026.",
        "3. Admission is subject to approval by the University Board.",
        "4. Ragging is strictly prohibited on campus."
    ]
    for term in terms:
        pdf.cell(0, 6, txt=term, ln=1)
    pdf.ln(25)
    pdf.set_font("Arial", 'B', 11)
    pdf.cell(100, 6, txt="For Unigate Consultancy,", ln=0)
    pdf.ln(15) 
    pdf.cell(100, 6, txt="Authorized Signatory", ln=1)
    pdf.set_font("Arial", '', 10)
    pdf.cell(100, 6, txt="(Director of Admissions)", ln=1)
    pdf.set_y(-30)
    pdf.set_font("Arial", 'I', 8)
    pdf.cell(0, 10, txt="This is a computer-generated document.", align='C')
    return send_file(io.BytesIO(pdf.output(dest='S').encode('latin-1')), mimetype='application/pdf', as_attachment=True, download_name=f'Offer_Letter_{student.name}.pdf')

@app.route('/edit_college/<int:college_id>', methods=['GET', 'POST'])
@login_required
def edit_college(college_id):
    if current_user.email != "unigateadmission1@gmail.com": return redirect(url_for('dashboard'))
    college = College.query.get_or_404(college_id)
    form = CollegeForm()
    if form.validate_on_submit():
        college.name = form.name.data
        college.location = form.location.data
        college.course = form.course.data
        college.fees = form.fees.data
        college.description = form.description.data
        if form.image_file.data:
            img = form.image_file.data
            filename = secure_filename(img.filename)
            img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            college.image_file = filename
        if form.fee_file.data:
            pdf = form.fee_file.data
            filename = secure_filename(pdf.filename)
            pdf.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            college.fee_file = filename
        db.session.commit()
        return redirect(url_for('admin'))
    elif request.method == 'GET':
        form.name.data = college.name
        form.location.data = college.location
        form.course.data = college.course
        form.fees.data = college.fees
        form.description.data = college.description
    return render_template('edit_college.html', form=form, college=college)

@app.route('/delete_college/<int:college_id>')
@login_required
def delete_college(college_id):
    if current_user.email != "unigateadmission1@gmail.com": return redirect(url_for('dashboard'))
    college = College.query.get_or_404(college_id)
    db.session.delete(college)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/update_status/<int:user_id>/<int:status>')
@login_required
def update_status(user_id, status):
    if current_user.email != "unigateadmission1@gmail.com": return redirect(url_for('dashboard'))
    user = User.query.get(user_id)
    user.application_status = status
    email_success = send_status_update_email(user, status)
    if email_success:
        flash(f'Status updated to {status} and Email Sent!', 'success')
    else:
        flash(f'Status updated to {status} BUT Email Failed!', 'warning')
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/test_email')
def test_email_connection():
    try:
        msg = Message("Test Email from Unigate", recipients=['unigateadmission1@gmail.com'])
        msg.body = "If you are reading this, the email system is working perfectly!"
        mail.send(msg)
        return "<h1>Success! Email sent. Check your inbox.</h1>"
    except Exception as e:
        return f"<h1>Error:</h1> <p>{str(e)}</p>"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5007, use_reloader=False)