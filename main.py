from flask import Flask, render_template, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rooms.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Модели данных
class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    available = db.Column(db.Boolean, default=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_admin = db.Column(db.Boolean, default=False)

class OwnerApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    additional_info = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')

# Маршруты и функции представления
@app.route('/')
def index():
    if 'username' in session:
        rooms = Room.query.all()
        return render_template('index.html', rooms=rooms)
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if request.method == 'POST':
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if check_password_hash(user.password, old_password):
                if new_password == confirm_password:
                    user.password = generate_password_hash(new_password)
                    db.session.commit()
                    return redirect(url_for('index'))
                else:
                    error = "Пароли не совпадают!."
            else:
                error = "Неправильный старый пароль."
            return render_template('profile.html', user=user, error=error)
        return render_template('profile.html', user=user)
    return redirect(url_for('login'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password)
        existing_user = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_user:
            error = "Такой пользователь уже существует!"
            return render_template('register.html', error=error)
        elif existing_email:
            error = "Такая почта уже зарегестрирована!"
            return render_template('register.html', error=error)
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('index'))
        else:
            error = "Неправильное имя или пароль."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/book', methods=['POST'])
def book():
    if 'username' not in session:
        return redirect(url_for('login'))
    room_id = int(request.form['room_id'])
    room = Room.query.get(room_id)
    if room.available:
        room.available = False
        db.session.commit()
        return f"Room {room_id} has been booked successfully!"
    else:
        return "Sorry, the selected room is not available."


@app.route('/notifications')
def notifications():
    # Логика для получения уведомлений из базы данных
    notifications = []  # Здесь должна быть логика для получения уведомлений
    return render_template('notifications.html', notifications=notifications)


@app.route('/search')
def search():
    return render_template('search.html')


@app.route('/support_chat')
def support_chat():
    return render_template('support_chat.html')


@app.route('/apply_for_owner', methods=['GET', 'POST'])
def apply_for_owner():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        additional_info = request.form['additional_info']

        new_application = OwnerApplication(name=name, email=email, phone=phone, address=address,
                                           additional_info=additional_info)
        db.session.add(new_application)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('apply_for_owner.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user.is_admin:
            applications = OwnerApplication.query.all()
            if request.method == 'POST':
                action = request.form['action']
                application_id = request.form['application_id']
                application = OwnerApplication.query.get_or_404(application_id)
                if action == 'accept':
                    application.status = 'accepted'
                elif action == 'reject':
                    application.status = 'rejected'
                db.session.commit()
            return render_template('admin_dashboard.html', user=user, applications=applications)
        else:
            return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))


@app.route('/admin/process_application/<int:application_id>/<action>')
def process_application(application_id, action):
    application = OwnerApplication.query.get_or_404(application_id)

    if action == 'accept':
        application.status = 'accepted'
    elif action == 'reject':
        application.status = 'rejected'

    db.session.commit()
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
