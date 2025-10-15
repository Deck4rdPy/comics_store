from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'star_wars_comics_secret_2025'

# Инициализация базы данных
def init_db():
    if not os.path.exists('comics.db'):
        conn = sqlite3.connect('comics.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
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
    return render_template('comics.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# Создаём БД при запуске
init_db()

if __name__ == '__main__':
    app.run(debug=True)