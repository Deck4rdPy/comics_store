from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'star_wars_comics_secret_2025'


def init_db():
    # Всегда подключаемся к БД — даже если файла нет
    conn = sqlite3.connect('comics.db')
    cursor = conn.cursor()

    # Проверяем, существует ли таблица users
    cursor.execute("""
        SELECT name FROM sqlite_master WHERE type='table' AND name='users';
    """)
    table_exists = cursor.fetchone()

    # Если таблицы нет — создаём её
    if not table_exists:
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        print("✅ Таблица 'users' создана.")
    else:
        print("ℹ️ Таблица 'users' уже существует.")

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('comics.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        try:
            password_hash = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            conn.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Логин уже занят! <a href='/register'>Назад</a>"
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect('/comics')
        else:
            return "Неверный логин или пароль! <a href='/login'>Попробовать снова</a>"
    return render_template('login.html')


@app.route('/comics')
def comics():
    if 'username' not in session:
        return redirect('/login')

    # Список комиксов с обложками
    comics_list = [
        {
            "title": "Darth Vader #1",
            "description": "Тайны тёмной стороны",
            "cover": "darth_vader.jpg"
        },
        {
            "title": "Yoda: Masters of the Force",
            "description": "Мудрость древнего джедая",
            "cover": "yoda.jpg"
        },
        {
            "title": "Rebels: Rise of the Phoenix",
            "description": "Борьба повстанцев",
            "cover": "rebels.jpg"
        },
        {
            "title": "The High Republic",
            "description": "Эпоха величия",
            "cover": "high_republic.jpg"
        }
    ]

    return render_template('comics.html', username=session['username'], comics=comics_list)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# Создаём БД при запуске
init_db()

if __name__ == '__main__':
    app.run(debug=True)