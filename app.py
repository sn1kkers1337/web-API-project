from flask import Flask, request, jsonify, redirect, url_for, render_template, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from datetime import datetime
import csv
import io
import os
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'percol-private-key-2026'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'collection.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ============ МОДЕЛИ БД ============
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))

    # Новые поля для профиля
    nickname = db.Column(db.String(80))
    bio = db.Column(db.String(200))
    avatar_url = db.Column(db.String(500))
    pref_type = db.Column(db.String(50), default='all')  # Фактор предпочтения

    items = db.relationship('Item', backref='user', lazy=True, cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    item_type = db.Column(db.String(50), nullable=False, default='other')
    author = db.Column(db.String(200), nullable=True)
    genre = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='not_started')
    rating = db.Column(db.Float, nullable=True, default=0)
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id, 'title': self.title, 'item_type': self.item_type,
            'author': self.author, 'genre': self.genre, 'status': self.status,
            'rating': self.rating, 'notes': self.notes
        }


# ============ ФОРМЫ ============
class LoginForm(FlaskForm):
    login_id = StringField('Email или Никнейм', validators=[
        DataRequired(message="Введите email или логин")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Введите пароль")
    ])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[
        DataRequired(message="Придумайте логин"),
        Length(min=3, max=20, message="Логин должен быть от 3 до 20 символов")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Введите почту"),
        Email(message="Некорректный формат почты (пример: user@mail.ru)")
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message="Придумайте пароль"),
        Length(min=6, message="Пароль должен быть не менее 6 символов")
    ])
    password_confirm = PasswordField('Повтор пароля', validators=[
        DataRequired(message="Подтвердите пароль"),
        EqualTo('password', message="Пароли не совпадают")
    ])
    submit = SubmitField('Создать аккаунт')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Этот логин уже занят, выберите другой.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Эта почта уже зарегистрирована.')

class ProfileForm(FlaskForm):
    nickname = StringField('Никнейм', validators=[
        Length(max=80, message="Никнейм слишком длинный")
    ])
    avatar_url = StringField('URL аватарки', validators=[
        Length(max=500, message="Ссылка слишком длинная")
    ])
    bio = TextAreaField('Коротко о себе', validators=[
        Length(max=200, message="Описание не должно превышать 200 символов")
    ])
    pref_type = SelectField('Приоритет в коллекции', choices=[
        ('all', 'Всё подряд'),
        ('books', 'Книги'),
        ('games', 'Игры'),
        ('movies', 'Фильмы')
    ])
    submit = SubmitField('Сохранить профиль')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()

# ============ МАРШРУТЫ ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    message = ""
    if form.validate_on_submit():
        # Ищем пользователя либо по email, либо по username
        user = User.query.filter(
            (User.email == form.login_id.data) | (User.username == form.login_id.data)
        ).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect(url_for('index'))
        message = "Неверные данные для входа"
    return render_template('login.html', form=form, message=message)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.nickname = form.nickname.data
        current_user.avatar_url = form.avatar_url.data
        current_user.bio = form.bio.data
        current_user.pref_type = form.pref_type.data
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)


# ============ ГЛАВНЫЙ МАРШРУТ ============
@app.route('/')
def index():
    return render_template('index.html', current_user=current_user)


# ============ API МАРШРУТЫ ============
@app.route('/api/items', methods=['GET'])
def get_items():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Доступ запрещен'}), 401

    search = request.args.get('search', '').lower()
    item_type = request.args.get('type', '')
    query = Item.query.filter_by(user_id=current_user.id)

    if search:
        query = query.filter(Item.title.ilike(f'%{search}%') | Item.author.ilike(f'%{search}%'))

    if item_type:
        query = query.filter(Item.item_type == item_type)

    items = query.all()
    return jsonify([item.to_dict() for item in items]), 200


@app.route('/api/items/<int:item_id>', methods=['GET'])
def get_item(item_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Доступ запрещен'}), 401

    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return jsonify({'error': 'Предмет не найден'}), 404
    return jsonify(item.to_dict()), 200


@app.route('/api/items', methods=['POST'])
def create_item():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Доступ запрещен'}), 401

    data = request.get_json()
    if not data or 'title' not in data:
        return jsonify({'error': 'Название обязательно'}), 400

    item = Item(
        title=data.get('title'),
        item_type=data.get('item_type', 'other'),
        author=data.get('author'),
        genre=data.get('genre'),
        status=data.get('status', 'not_started'),
        rating=float(data.get('rating', 0)),
        notes=data.get('notes'),
        user_id=current_user.id
    )

    db.session.add(item)
    db.session.commit()
    return jsonify(item.to_dict()), 201


@app.route('/api/items/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Доступ запрещен'}), 401

    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return jsonify({'error': 'Предмет не найден'}), 404

    data = request.get_json()
    if 'title' in data: item.title = data['title']
    if 'item_type' in data: item.item_type = data['item_type']
    if 'author' in data: item.author = data['author']
    if 'genre' in data: item.genre = data['genre']
    if 'status' in data: item.status = data['status']
    if 'rating' in data: item.rating = float(data['rating'])
    if 'notes' in data: item.notes = data['notes']

    db.session.commit()
    return jsonify(item.to_dict()), 200


@app.route('/api/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    if not current_user.is_authenticated:
        return jsonify({'error': 'Доступ запрещен'}), 401

    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
    if not item:
        return jsonify({'error': 'Предмет не найден'}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Предмет успешно удален'}), 204

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Не найдено'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Внутренняя ошибка сервера'}), 500


# ============ ЭКСПОРТ ДАННЫХ ============

@app.route('/api/export/json')
@login_required
def export_json():
    items = Item.query.filter_by(user_id=current_user.id).all()
    data = [i.to_dict() for i in items]

    # Создаем JSON-ответ
    response = make_response(jsonify(data))
    response.headers["Content-Disposition"] = "attachment; filename=my_collection.json"
    response.headers["Content-Type"] = "application/json"
    return response


@app.route('/api/export/csv')
@login_required
def export_csv():
    items = Item.query.filter_by(user_id=current_user.id).all()

    # Используем StringIO для записи CSV в память
    output = io.StringIO()
    # Указываем заголовки (колонки)
    fieldnames = ['id', 'title', 'item_type', 'author', 'genre', 'status', 'rating', 'notes']
    writer = csv.DictWriter(output, fieldnames=fieldnames)

    writer.writeheader()
    for item in items:
        # dict_row = item.to_dict() — это вернет словарь
        writer.writerow(item.to_dict())

    # Создаем ответ с правильными заголовками для скачивания
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=my_collection.csv"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    items = Item.query.filter_by(user_id=current_user.id).all()
    total = len(items)

    # Распределение по типам и статусам
    by_type = {"book": 0, "game": 0, "movie": 0, "other": 0}
    by_status = {"not_started": 0, "in_progress": 0, "completed": 0}
    total_rating = 0

    for item in items:
        by_type[item.item_type] = by_type.get(item.item_type, 0) + 1
        by_status[item.status] = by_status.get(item.status, 0) + 1
        total_rating += (item.rating or 0)

    avg_rating = round(total_rating / total, 2) if total > 0 else 0

    return jsonify({
        'total_items': total,
        'average_rating': avg_rating,
        'by_type': by_type,
        'by_status': by_status,
        # Данные для Chart.js
        'chart_labels': list(by_type.keys()),
        'chart_values': list(by_type.values())
    })


@app.route('/api/import/json', methods=['POST'])
@login_required
def import_json():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        data = json.load(file)
        if not isinstance(data, list):
            return jsonify({"error": "JSON must be a list of items"}), 400

        for d in data:
            new_item = Item(
                title=d.get('title', 'Imported Item'),
                item_type=d.get('item_type', 'other'),
                author=d.get('author'),
                genre=d.get('genre'),
                status=d.get('status', 'not_started'),
                rating=float(d.get('rating', 0)),
                notes=d.get('notes'),
                user_id=current_user.id
            )
            db.session.add(new_item)
        db.session.commit()
        return jsonify({"message": "Import successful"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/items/<int:item_id>', methods=['PUT', 'DELETE'])
@login_required
def item_detail(item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()

    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted successfully'}), 204

    if request.method == 'PUT':
        data = request.get_json()
        item.title = data.get('title', item.title)
        item.item_type = data.get('item_type', item.item_type)
        item.author = data.get('author', item.author)
        item.genre = data.get('genre', item.genre)
        item.status = data.get('status', item.status)
        item.rating = float(data.get('rating', item.rating))
        item.notes = data.get('notes', item.notes)

        db.session.commit()
        return jsonify(item.to_dict())


# ============ API ЭНДПОИНТЫ ============

@app.route('/api/items', methods=['GET', 'POST'])
@login_required
def manage_items():
    if request.method == 'GET':
        # --- ФУНКЦИЯ 4: ПРОДВИНУТАЯ ФИЛЬТРАЦИЯ И СОРТИРОВКА ---
        sort_by = request.args.get('sort', 'id_desc')
        filter_type = request.args.get('type', 'all')
        search_query = request.args.get('q', '').lower()

        query = Item.query.filter_by(user_id=current_user.id)

        # Фильтрация по типу
        if filter_type != 'all':
            query = query.filter_by(item_type=filter_type)

        # Поиск (по названию или автору)
        if search_query:
            query = query.filter((Item.title.ilike(f'%{search_query}%')) | (Item.author.ilike(f'%{search_query}%')))

        # Сортировка
        if sort_by == 'rating_desc':
            query = query.order_by(Item.rating.desc())
        elif sort_by == 'rating_asc':
            query = query.order_by(Item.rating.asc())
        elif sort_by == 'title_asc':
            query = query.order_by(Item.title.asc())
        else:
            query = query.order_by(Item.id.desc())

        items = query.all()
        return jsonify([i.to_dict() for i in items])

    data = request.get_json()
    new_item = Item(
        title=data['title'],
        item_type=data.get('item_type', 'other'),
        author=data.get('author'),
        genre=data.get('genre'),
        status=data.get('status', 'not_started'),
        rating=float(data.get('rating', 0)),
        notes=data.get('notes'),
        user_id=current_user.id
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify(new_item.to_dict()), 201


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)