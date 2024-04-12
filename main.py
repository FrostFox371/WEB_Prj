from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from collections import defaultdict

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rooms.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)


# Модели данных
class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    available = db.Column(db.Boolean, default=True)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_admin = db.Column(db.Boolean, default=False)
    # Добавляем связь с таблицей администраторов
    admin_relation = db.relationship('Admin', backref='user_rel', uselist=False)


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


@app.route('/get_all_hotels', methods=['GET'])
def get_all_hotels():
    url = 'https://overpass-api.de/api/interpreter'
    query = """
    [out:json];
    node["tourism"="hotel"];
    out;
    """
    response = requests.post(url, data=query)
    if response.status_code == 200:
        hotels_data = response.json()
        hotels = hotels_data.get('elements', [])

        # Организация отелей по странам и городам
        hotels_by_country = defaultdict(lambda: defaultdict(list))
        for hotel in hotels:
            country = hotel.get('tags', {}).get('addr:country', 'Неизвестно')
            city = hotel.get('tags', {}).get('addr:city', 'Неизвестно')
            hotels_by_country[country][city].append(hotel)

        return render_template('hotels_list.html', hotels_by_country=hotels_by_country)
    else:
        return "Ошибка при получении данных об отелях"


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if request.method == 'POST':
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if not check_password_hash(user.password, old_password):
                flash("Неправильный старый пароль.")
            elif new_password != confirm_password:
                flash("Пароли не совпадают!")
            else:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash("Пароль успешно изменен!")
                return redirect(url_for('index'))
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
            flash("Такой пользователь уже существует!")
            return render_template('register.html')
        elif existing_email:
            flash("Такая почта уже зарегистрирована!")
            return render_template('register.html')
        else:
            new_user = User(username=username, password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash("Регистрация успешно завершена! Теперь вы можете войти.")
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


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Неправильное имя или пароль для администратора."
    return render_template('admin_login.html', error=error)


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
        admin = Admin.query.filter_by(username=username).first()
        if admin:
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
            return render_template('admin_dashboard.html', user=admin, applications=applications)
        else:
            return redirect(url_for('admin_login'))
    else:
        return redirect(url_for('admin_login'))


@app.route('/admin/process_application/<int:application_id>/<action>', methods=['POST'])
def process_application(application_id, action):
    if request.method == 'POST':
        application = OwnerApplication.query.get_or_404(application_id)
        if action == 'accept':
            application.status = 'accepted'
        elif action == 'reject':
            application.status = 'rejected'
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    else:
        # Если запрос не является POST, вернуть ошибку
        return "Метод не поддерживается", 405


# Обработчики ошибок
@app.errorhandler(400)
def bad_request_error(error):
    return render_template('error.html', error_code=400, error_message="Bad Request"), 400


@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('error.html', error_code=401, error_message="Unauthorized"), 401


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, error_message="Forbidden"), 403


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500


@app.errorhandler(502)
def bad_gateway_error(error):
    return render_template('error.html', error_code=502, error_message="Bad Gateway"), 502


@app.errorhandler(503)
def service_unavailable_error(error):
    return render_template('error.html', error_code=503, error_message="Service Unavailable"), 503


@app.errorhandler(505)
def http_version_not_supported_error(error):
    return render_template('error.html', error_code=505, error_message="HTTP Version Not Supported"), 505


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
