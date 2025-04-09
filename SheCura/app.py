from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from flask import abort
from datetime import datetime, timedelta
from flask_wtf.file import FileAllowed, FileField
from werkzeug.utils import secure_filename
from flask import send_from_directory
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from io import StringIO
import csv
from flask import Response

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize database & migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static/uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Load chatbot model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")
model = AutoModelForCausalLM.from_pretrained("microsoft/DialoGPT-medium")
chat_history_ids = None

def get_Chat_response(text):
    global chat_history_ids
    new_user_input_ids = tokenizer.encode(str(text) + tokenizer.eos_token, return_tensors="pt")
    bot_input_ids = torch.cat([chat_history_ids, new_user_input_ids], dim=-1) if chat_history_ids is not None else new_user_input_ids
    chat_history_ids = model.generate(bot_input_ids, max_length=1000, pad_token_id=tokenizer.eos_token_id)
    return tokenizer.decode(chat_history_ids[:, bot_input_ids.shape[-1]:][0], skip_special_tokens=True)

@app.route("/chatbot")
def chat():
    return render_template('chat.html')

@app.route("/get", methods=["GET", "POST"])
def chat_get():
    msg = request.form.get("msg") or request.args.get("msg")
    if msg:
        return jsonify(get_Chat_response(msg))
    return jsonify("Error: Empty message received")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    items = db.relationship('Item', backref='owner', lazy=True)
    profile_pic = db.Column(db.String(255), nullable=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database if it doesn't exist
with app.app_context():
    if not os.path.exists("database.db"):
        db.create_all()
        print("Database Created!")

# Forms
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    profile_pic = FileField('Upload Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField("Register")
    

# Workout Log Model
class WorkoutLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workout_type = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    daily_goal = db.Column(db.Integer, nullable=True)  # Store user daily goal

    user = db.relationship('User', backref=db.backref('workout_logs', lazy=True))

# ✅ Get workout logs for the current user
@app.route('/get_workout_logs', methods=['GET'])
@login_required
def get_workout_logs():
    logs = WorkoutLog.query.filter_by(user_id=current_user.id).all()
    
    logs_data = [
        {
            "id": log.id,
            "type": log.workout_type,
            "duration": log.duration,
            "date": log.date.strftime("%Y-%m-%d"),
            "goal": log.daily_goal
        }
        for log in logs
    ]
    
    return jsonify(logs_data)

# ✅ Add a new workout log
@app.route('/add_workout', methods=['POST'])
@login_required
def add_workout():
    data = request.get_json()

    # Convert date string to Date object
    try:
        workout_date = datetime.strptime(data['date'], "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"error": "Invalid date format"}), 400

    new_log = WorkoutLog(
        user_id=current_user.id,
        workout_type=data['workoutType'],
        duration=data['duration'],
        date=workout_date,
        daily_goal=data['dailyGoal']
    )

    db.session.add(new_log)
    db.session.commit()

    return jsonify({"message": "Workout logged successfully!"})

# ✅ Delete a workout log
@app.route('/delete_workout/<int:log_id>', methods=['DELETE'])
@login_required
def delete_workout(log_id):
    log = WorkoutLog.query.filter_by(id=log_id, user_id=current_user.id).first()

    if log:
        db.session.delete(log)
        db.session.commit()
        return jsonify({"message": "Workout log deleted!"})

    return jsonify({"error": "Log not found"}), 404

# Routes
@app.route("/")
def home():
    return render_template("base.html")

@app.route("/EmpowerFit")
def EmpowerFit():
    return render_template("EmpowerFit.html")

@app.route("/AuraPlay")
def AuraPlay():
    return render_template("AuraPlay.html")

@app.route("/ZenMode")
def ZenMode():
    return render_template("ZenMode.html")

@app.route("/NourishWell")
def NourishWell():
    return render_template("NourishWell.html")

@app.route("/premium")
def premium():
    return render_template("premium.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/team")
def team():
    return render_template("team.html")

# Define the Feedback model
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.Text, nullable=False)

# Route to display the feedback form
@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

# Route to handle form submission
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    name = request.form['name']
    email = request.form['email']
    rating = request.form['rating']
    feedback_text = request.form['feedback']

    # Store feedback in the database
    new_feedback = Feedback(name=name, email=email, rating=rating, feedback=feedback_text)
    db.session.add(new_feedback)
    db.session.commit()

    return redirect('/admin')

# Route to delete feedback
@app.route('/delete-feedback/<int:feedback_id>', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    return redirect(url_for('admin'))

class CycleMonitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, unique=True)
    last_menstruation = db.Column(db.Date, nullable=False)

@app.route('/cycle_monitor', methods=['GET', 'POST'])
@login_required
def cycle_monitor():
    # Fetch cycle data ONLY for the logged-in user
    cycle_data = CycleMonitor.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        last_menstruation = request.form.get('last_menstruation')
        if last_menstruation:
            last_menstruation_date = datetime.strptime(last_menstruation, '%Y-%m-%d').date()

            if cycle_data:
                cycle_data.last_menstruation = last_menstruation_date  # Update existing entry
            else:
                new_cycle = CycleMonitor(user_id=current_user.id, last_menstruation=last_menstruation_date)
                db.session.add(new_cycle)

            db.session.commit()
            return redirect(url_for('cycle_monitor'))

    # Ensure only current user's data is shown
    last_menstruation = cycle_data.last_menstruation if cycle_data else None
    next_due_date = (last_menstruation + timedelta(days=28)) if last_menstruation else None

    return render_template('cycle_monitor.html', last_menstruation=last_menstruation, next_due_date=next_due_date)


@app.route("/her_health_answers")
@login_required
def her_health_answers():
    return render_template("her_health_answers.html")

@app.route("/maternity_centers")
@login_required
def maternity_centers():
    return render_template("maternity_centers.html")

@app.route('/symptom_checker', methods=['GET', 'POST'])
def symptom_checker():
    if request.method == 'POST':
        # Retrieve form data
        cycle = int(request.form['cycle'])
        irregular_periods = request.form['irregularPeriods']
        heavy_bleeding = request.form['heavyBleeding']
        severe_cramps = request.form['severeCramps']
        spotting = request.form['spotting']
        bloating = request.form['bloating']
        missed_period = request.form['missedPeriod']
        mood_swings = request.form['moodSwings']
        vaginal_discharge = request.form['vaginalDischarge']
        fatigue = request.form['fatigue']

        if irregular_periods == "yes" and heavy_bleeding == "yes" and severe_cramps == "yes":
         result_text = ("Your symptoms suggest you may be experiencing a hormonal imbalance or polycystic ovary syndrome (PCOS). PCOS is a condition that affects hormone levels, often leading to irregular periods, excessive hair growth, acne, and weight gain. It can also cause fertility issues if left untreated. We strongly recommend consulting a gynecologist to assess your symptoms further and discuss possible treatment options.")

        elif missed_period == "yes" and fatigue == "yes":
         result_text = ("Your symptoms could be indicative of pregnancy or another underlying health condition. Missed periods, nausea, fatigue, and other hormonal changes are common signs of pregnancy, but they can also be linked to stress, hormonal imbalance, or other medical concerns. To confirm, consider taking a pregnancy test and consulting a healthcare professional for a detailed evaluation.")

        elif mood_swings == "yes" and bloating == "yes" and fatigue == "yes":
         result_text = ("These symptoms align with premenstrual syndrome (PMS), a condition that affects many women before their menstrual cycle. PMS can cause mood swings, bloating, fatigue, headaches, and breast tenderness. While it's common, severe symptoms might indicate premenstrual dysphoric disorder (PMDD), a more intense form of PMS. A doctor can help you manage these symptoms through lifestyle changes, dietary adjustments, or medication.")

        elif severe_cramps == "yes" and heavy_bleeding == "yes" and spotting == "yes":
         result_text = ("Your symptoms might be related to endometriosis, a condition in which tissue similar to the lining of the uterus grows outside the uterus. Endometriosis can cause severe pain, heavy menstrual bleeding, and fertility issues. If you experience prolonged discomfort and irregular cycles, it is essential to visit a gynecologist for proper diagnosis and management.")

        elif fatigue == "yes" and mood_swings == "yes" and bloating == "yes":
         result_text = ("These symptoms might indicate thyroid dysfunction, a condition that affects metabolism, energy levels, and overall hormonal balance. Hypothyroidism (underactive thyroid) and hyperthyroidism (overactive thyroid) can both impact your menstrual cycle, mood, and weight. A simple blood test measuring thyroid hormone levels can help diagnose this issue, and a doctor can recommend appropriate treatment.")

        elif heavy_bleeding == "yes" and severe_cramps == "yes" and spotting == "yes":
         result_text = ("Uterine fibroids might be the cause of your symptoms. These are noncancerous growths in the uterus that can lead to heavy or prolonged menstrual periods, pelvic pain, and discomfort. While some fibroids do not require treatment, others may need medication or surgical intervention. Consulting a gynecologist can help determine the best course of action based on the severity of your symptoms.")

        elif fatigue == "yes" and heavy_bleeding == "yes":
         result_text = ("Your symptoms suggest a possibility of anemia, a condition caused by a lack of healthy red blood cells. Anemia can lead to fatigue, dizziness, pale skin, and irregular menstrual cycles. Iron-deficiency anemia is common in women due to menstrual blood loss, and it can be managed through dietary changes, supplements, or medical treatment. We recommend checking your iron levels through a blood test.")

        elif mood_swings == "yes" and irregular_periods == "yes":
         result_text = ("Your symptoms could be linked to stress or lifestyle factors affecting your menstrual cycle. High levels of stress, poor diet, lack of sleep, and excessive exercise can disrupt hormone levels, leading to irregular periods and mood changes. Adopting a balanced lifestyle with proper nutrition, relaxation techniques, and exercise may help regulate your cycle. However, if your symptoms persist, consider consulting a doctor for further evaluation.")

        elif missed_period == "yes" and irregular_periods == "yes":
         result_text = ("Your symptoms might be related to ovulation issues or hormonal imbalances. Irregular ovulation can affect fertility and menstrual cycle consistency. Conditions like PCOS or thyroid disorders can contribute to ovulation problems. A doctor may suggest hormone level testing or ultrasound scans to determine the cause and recommend suitable treatments.")

        elif missed_period == "yes" and vaginal_discharge == "yes":
         result_text = ("Your symptoms might indicate uterine polyps, which are small growths in the uterus that can cause irregular bleeding, heavy periods, and discomfort. Though they are usually benign, they can sometimes lead to fertility issues or other complications. A gynecologist can perform an ultrasound or biopsy to diagnose and suggest treatment options if necessary.")

        elif spotting == "yes" and heavy_bleeding == "yes":
         result_text = ("PCOS or another hormonal imbalance might be the cause of your symptoms. PCOS affects ovulation, leading to irregular periods, weight gain, and acne. It is essential to consult a specialist to confirm the diagnosis and explore lifestyle or medical interventions to manage symptoms effectively.")

        elif irregular_periods == "yes" and vaginal_discharge == "yes":
         result_text = ("These symptoms might indicate a vaginal infection or other reproductive health concerns. Vaginal infections, including bacterial or yeast infections, can cause unusual discharge, itching, and discomfort. Getting tested by a healthcare provider can help determine the cause and provide appropriate treatment.")

        elif irregular_periods == "yes" and fatigue == "yes" and mood_swings == "yes":
         result_text = ("Your symptoms could be linked to early menopause or perimenopause. This transition phase can cause changes in menstrual cycles, mood swings, hot flashes, and sleep disturbances. A doctor can assess hormone levels and suggest treatments to help manage symptoms.")

        elif bloating == "yes" and fatigue == "yes":
         result_text = ("Your symptoms might indicate digestive issues or gastrointestinal conditions, such as irritable bowel syndrome (IBS) or food intolerances. Hormonal fluctuations can also affect digestion and bloating. A doctor can evaluate your symptoms and suggest dietary adjustments or medical tests if necessary.")

        elif fatigue == "yes" and severe_cramps == "no":
         result_text = ("Chronic fatigue syndrome (CFS) could be a potential cause of your symptoms. CFS is a long-term condition characterized by extreme tiredness, muscle pain, and cognitive difficulties. While its exact cause is unclear, lifestyle modifications, stress management, and medical interventions can help alleviate symptoms. A consultation with a doctor can provide further insights and possible treatment options.")

        else:
         result_text = ("Based on your symptoms, it is best to consult a healthcare provider for a thorough diagnosis. Women's health issues can be complex and require medical attention for an accurate assessment. We recommend booking an appointment with a specialist to discuss your concerns and find the best approach to your well-being.")


        # Redirect to result page
        return render_template('result.html', result_text=result_text)
    
    return render_template('symptom_checker.html')


@app.route("/dashboard")
@login_required
def dashboard():
    user_items = Item.query.filter_by(user_id=current_user.id).all()  # Fetch only user's items
    return render_template("dashboard.html", items=user_items)



@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

# class HealthReminder(db.Model):
#     _tablename_ = 'health_reminder'
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
#     title = db.Column(db.String(100))
#     description = db.Column(db.String(500))
#     date = db.Column(db.DateTime)
#     added_date = db.Column(db.DateTime)  # Ensure this column is defined
#     added_time = db.Column(db.Time)
#     added_time = db.Column(db.String(20))
   
# # Route to display reminders
# @app.route('/health_reminders')
# @login_required
# def health_reminders():
#     reminders = HealthReminder.query.filter_by(user_id=current_user.id).all()
#     return render_template("health_reminders.html", reminders=reminders)

# # Route to add reminders
# @app.route('/add_reminder', methods=['POST'])
# @login_required
# def add_reminder():
#     title = request.form['title']
#     description = request.form['description']
#     date = datetime.strptime(request.form['date'], "%Y-%m-%d").date()
#     added_date = datetime.now().strftime('%Y-%m-%d')
#     added_time = datetime.now().strftime('%H:%M:%S')

#     # Save the new reminder with the time field
#     new_reminder = HealthReminder(
#         user_id=current_user.id, 
#         title=title, 
#         description=description, 
#         date=date, 
#         added_date=added_date, 
#         added_time=added_time
#     )
#     db.session.add(new_reminder)
#     db.session.commit()

#     return redirect(url_for('health_reminders'))

# # Route to delete reminders
# @app.route('/delete_reminder/<int:reminder_id>', methods=['POST'])
# @login_required
# def delete_reminder(reminder_id):
#     reminder = HealthReminder.query.get_or_404(reminder_id)
#     if reminder.user_id == current_user.id:
#         db.session.delete(reminder)
#         db.session.commit()
#     return redirect(url_for('health_reminders'))


# # Reminder model
# class Reminder(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     title = db.Column(db.String(100), nullable=False)
#     description = db.Column(db.String(500), nullable=True)
#     reminder_time = db.Column(db.DateTime, nullable=False)
#     added_date = db.Column(db.DateTime, default=datetime.utcnow)  # New column added
#     # Add user_id as a foreign key linking to the User model
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add user_id

# # Route to display reminders
# @app.route('/health/reminders', methods=['GET'])
# def health_reminders():
#     reminders = Reminder.query.all()  # Fetch all reminders
#     return render_template('health_reminders.html', reminders=reminders)

# # Route to add a reminder
# @app.route('/add', methods=['GET', 'POST'])
# def add_reminder():
#     if request.method == 'POST':
#         title = request.form['title']
#         description = request.form['description']
#         date_str = request.form.get('date')
#         time_str = request.form.get('time')

#         if date_str and time_str:
#             reminder_time = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')

#             new_reminder = Reminder(
#                 title=title,
#                 description=description,
#                 reminder_time=reminder_time
#             )

#             # Debugging: print new reminder details before inserting into DB
#             print(f"Adding reminder: {new_reminder.title}, {new_reminder.description}, {new_reminder.reminder_time}")

#             try:
#                 db.session.add(new_reminder)
#                 db.session.commit()
#                 flash('Reminder added successfully!', 'success')
#                 return redirect(url_for('health_reminders'))  # Redirect to health reminders page
#             except Exception as e:
#                 flash(f'Error adding reminder: {str(e)}', 'danger')
#                 return redirect(url_for('health_reminders'))
#         else:
#             flash('Please provide both date and time for the reminder.', 'danger')
#             return redirect(url_for('add_reminder'))
        
#     return render_template('health_reminders.html')

# # Route to delete a reminder
# @app.route('/delete/<int:id>', methods=['POST'])
# def delete_reminder(id):
#     reminder_to_delete = Reminder.query.get_or_404(id)

#     try:
#         db.session.delete(reminder_to_delete)
#         db.session.commit()
#         flash('Reminder deleted successfully!', 'success')
#     except Exception as e:
#         flash(f'Error deleting reminder: {str(e)}', 'danger')

#     return redirect(url_for('health_reminders'))  # Redirect to health reminders page

@app.route('/health_reminders')
def health_reminders():
    return render_template('health_reminders.html')

@app.route('/catch-falling')
def catch_falling():
    return render_template("catch-falling.html")

@app.route('/tic-tac-toe')
def tic_tac_toe():
    return render_template("tic-tac-toe.html")

@app.route('/typing-speed-test')
def typing_speed_test():
    return render_template("typing-speed-test.html")

@app.route('/Word-Scramble')
def Word_Scramble():
    return render_template("Word-Scramble.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.role == 'admin':
                flash("Admin logged in successfully!", "success")
            else:
                flash("Logged in successfully!", "success")
            next_page = request.args.get("next")  # Redirect to original page if available
            return redirect(next_page) if next_page else redirect(url_for("dashboard"))
        flash("Invalid credentials!", "danger")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Person already registered', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        role = 'admin' if form.email.data == 'khushboo@shecura.com' else 'user'
        
        # Handle profile picture upload
        profile_pic_filename = None
        if form.profile_pic.data:
            pic_file = secure_filename(form.profile_pic.data.filename)
            profile_pic_filename = pic_file  # Store in DB
            pic_path = os.path.join(app.config['UPLOAD_FOLDER'], pic_file)
            form.profile_pic.data.save(pic_path)

        # Create new user with profile pic
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=role, profile_pic=profile_pic_filename)
        db.session.add(user)
        db.session.commit()
        
        flash("Registration successful!", "success")
        return redirect(url_for("profile", username=user.username))
    
    return render_template("register.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/add_item", methods=["POST"])
@login_required
def add_item():
    item_name = request.form.get("item_name")
    if item_name:
        new_item = Item(name=item_name, user_id=current_user.id)
        db.session.add(new_item)
        db.session.commit()
        flash("Item added successfully!", "success")
    return redirect(url_for("dashboard"))

# REST API for Users
@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.all()
    return jsonify([{"id": user.id, "username": user.username, "email": user.email} for user in users])


# Admin panel route (shows all feedback)
@app.route('/admin')
def admin():
    users = User.query.all()  # Fetch all users from the database
    feedback_list = Feedback.query.all()  # Get all feedback from the database
    return render_template('admin.html', users=users, feedback_list=feedback_list)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        return redirect(url_for('admin'))  # Redirect back to admin panel

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully!", "success")
    else:
        flash("User not found!", "error")
    return redirect(url_for('admin'))




@app.route('/download_myhealth_data')
@login_required
def download_myhealth_data():
    # Fetch cycle data for the logged-in user
    cycle_data = CycleMonitor.query.filter_by(user_id=current_user.id).first()

    # Fetch workout logs for the logged-in user
    workout_logs = WorkoutLog.query.filter_by(user_id=current_user.id).all()

    # Prepare the user data for the file content
    output = StringIO()
    writer = csv.writer(output)

    # Writing user information
    writer.writerow(["User Info"])
    writer.writerow(["ID", current_user.id])
    writer.writerow(["Username", current_user.username])
    writer.writerow(["Email", current_user.email])
    writer.writerow([])  # Empty line

    # Writing menstrual cycle information
    writer.writerow(["Menstrual Cycle Info"])
    if cycle_data:
        writer.writerow(["Last Menstruation", cycle_data.last_menstruation.strftime("%Y-%m-%d")])
        writer.writerow(["Next Due Date", (cycle_data.last_menstruation + timedelta(days=28)).strftime("%Y-%m-%d")])
    else:
        writer.writerow(["Last Menstruation", "N/A"])
        writer.writerow(["Next Due Date", "N/A"])
    writer.writerow([])  # Empty line

    # Writing workout logs
    writer.writerow(["Workout Logs"])
    if workout_logs:
        writer.writerow(["Date", "Workout Type", "Duration", "Daily Goal"])
        for log in workout_logs:
            writer.writerow([log.date.strftime("%Y-%m-%d"), log.workout_type, log.duration, log.daily_goal])
    else:
        writer.writerow(["No workout logs available"])
    writer.writerow([])  # Empty line

    # Preparing response for download
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=myhealth_data.csv"}  # Updated to .csv extension
    )

@app.route("/MyHealth", methods=['GET', 'POST'])
@login_required
def MyHealth():
    # Fetch cycle data for the logged-in user
    cycle_data = CycleMonitor.query.filter_by(user_id=current_user.id).first()

    # Fetch workout logs for the logged-in user
    workout_logs = WorkoutLog.query.filter_by(user_id=current_user.id).all()

    # Debugging: Check if data is fetched
    print("Cycle Data:", cycle_data)
    print("Workout Logs:", workout_logs)

    if request.method == 'POST':
        # Ensure that last_menstruation is not empty or None
        last_menstruation = request.form.get('last_menstruation')
        
        # Validate the form input
        if last_menstruation:
            try:
                last_menstruation_date = datetime.strptime(last_menstruation, '%Y-%m-%d').date()

                if cycle_data:
                    cycle_data.last_menstruation = last_menstruation_date  # Update existing entry
                else:
                    new_cycle = CycleMonitor(user_id=current_user.id, last_menstruation=last_menstruation_date)
                    db.session.add(new_cycle)

                db.session.commit()
                return redirect(url_for('MyHealth'))
            except ValueError:
                # Handle invalid date format
                flash("Invalid date format. Please use YYYY-MM-DD.", "error")
        else:
            flash("Please enter a valid last menstruation date.", "error")

    # Ensure only current user's data is shown
    last_menstruation = cycle_data.last_menstruation if cycle_data else None
    next_due_date = (last_menstruation + timedelta(days=28)) if last_menstruation else None

    return render_template("MyHealth.html", user=current_user, cycle_data=cycle_data, 
                           last_menstruation=last_menstruation, next_due_date=next_due_date,
                           workout_logs=workout_logs)
    
    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(email='khushboo@shecura.com').first():
            admin_user = User(
                username='admin',
                email='khushboo@shecura.com',
                password=generate_password_hash('khushboo', method='pbkdf2:sha256'),
                role='admin',
                profile_pic='khushboo.jpg'  # Set the admin profile picture
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created!")
  
    app.run(debug=True)