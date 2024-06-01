from flask import Flask, request, render_template, flash, redirect, url_for, session
import sqlite3
import re
import bcrypt
import validators
from flask_limiter import Limiter, get_remote_address

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def is_password_match(entered_password, stored_hash):
    return bcrypt.checkpw(entered_password.encode(), stored_hash.encode())

def is_strong_password(password):
    min_length = 8
    require_uppercase = True
    require_lowercase = True
    require_digit = True
    require_special_char = True

    if len(password) < min_length:
        return False

    if (require_uppercase and not any(char.isupper() for char in password)) or \
       (require_lowercase and not any(char.islower() for char in password)) or \
       (require_digit and not any(char.isdigit() for char in password)) or \
       (require_special_char and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False

    return True

app = Flask(__name__)
app.secret_key = "SUPER-key"
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["10 per minute"])

def init_db():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0.0
        )
    ''')

    connection.commit()

def add_user(username, password):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    hashed_password = hash_password(password)
    query = '''INSERT INTO users (username , password)  VALUES(?, ?)'''
    cursor.execute(query , (username, hashed_password) )
    connection.commit()

def get_user(username):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = 'SELECT * FROM USERS WHERE USERNAME = ?'
    cursor.execute(query, (username,))
    return cursor.fetchone()

def get_user_by_username(username):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = f'SELECT * FROM USERS WHERE USERNAME = "{username}"'
    cursor.execute(query)
    return cursor.fetchone()

def get_all_users():
    cursor = connection.cursor()
    query = 'SELECT * FROM users'
    cursor.execute(query)
    return cursor.fetchall()

def init_movies_table():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS movies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            descreption TEXT,
            price REAL NOT NULL,
            image_url TEXT,
            is_sold BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    connection.commit()

def add_movie(user_id, title, descreption, price, image_url=None):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = '''INSERT INTO movies (user_id, title, descreption, price, image_url) VALUES (?, ?, ?, ?, ?)'''
    cursor.execute(query, (user_id, title, descreption, price, image_url))
    connection.commit()

def get_movie(movie_id):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = 'SELECT * FROM movies WHERE id = ?'
    cursor.execute(query, (movie_id,))
    return cursor.fetchone()

def get_user_movie(user_id):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = 'SELECT * FROM movies WHERE user_id = ?'
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def get_all_movies():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = 'SELECT * FROM movies'
    cursor.execute(query)
    return cursor.fetchall()

def is_movie_sold(movie_id):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = 'SELECT is_sold FROM movies WHERE id = ?'
    cursor.execute(query, (movie_id,))
    return cursor.fetchone()[0]

def mark_movie_as_sold(movie_id):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    movie_query = 'SELECT price, user_id FROM movies WHERE id = ?'
    cursor.execute(movie_query, (movie_id,))
    movie_data = cursor.fetchone()

    if movie_data:
        movie_price, user_id = movie_data
        update_query = 'UPDATE movies SET is_sold = 1 WHERE id = ?'
        cursor.execute(update_query, (movie_id,))
        connection.commit()
        update_balance_query = 'UPDATE users SET balance = balance + ? WHERE id = ?'
        cursor.execute(update_balance_query, (movie_price, user_id))
        connection.commit()

def init_comments_table():
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            movie_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (movie_id) REFERENCES movies (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    connection.commit()

def add_comment(movie_id, user_id, text):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = '''INSERT INTO comments (movie_id, user_id, text) VALUES (?, ?, ?)'''
    cursor.execute(query, (movie_id, user_id, text))
    connection.commit()

def get_comments_for_movie(movie_id):
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()
    query = '''
        SELECT users.username, comments.text, comments.timestamp
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.movie_id = ?
    '''
    cursor.execute(query, (movie_id,))
    return cursor.fetchall()

@app.route('/')
def index():
    if 'username' in session:
        if session['username'] == 'admin':
            return list(get_all_users())
        return render_template("index.html", movies=get_all_movies())
    return "You are not logged in."

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user(username)

        if user:
            if is_password_match(password, user[2]):
                session['username'] = user[1]
                session['user_id'] = user[0]
                return redirect(url_for('uploadMovie'))
            else:
                flash("Wrong password", "danger")
                return render_template("login.html")
        else:
            flash("User not found", "danger")
            return render_template("login.html")

    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_strong_password(password):
            flash("Please choose a strong password", "danger")
            return render_template("register.html")

        if get_user(username):
            flash("User already exists", "danger")
            return render_template("register.html")

        add_user(username, password)
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route('/uploadMovie', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def uploadMovie():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        movieImage = request.files['image']
        title = request.form['title']
        descreption = request.form['description']
        price = request.form['price']

        if not movieImage:
            flash("Image is required", "danger")
            return render_template("upload-movie.html")

        if not validators.allowed_file(movieImage.filename) or not validators.allowed_file_size(movieImage):
            flash("Invalid file is uploaded", "danger")
            return render_template("upload-movie.html")

        image_url = f"uploads/{movieImage.filename}"
        movieImage.save("static/" + image_url)
        add_movie(session['user_id'], title, descreption, price, image_url)
        return redirect(url_for('index'))

    return render_template("upload-movie.html")

@app.route('/movie/<movie_id>')
def getMovie(movie_id):
    movie = get_movie(movie_id)
    if not movie:
        return "Movie not found", 404

    comments = get_comments_for_movie(movie_id)
    return render_template('movie.html', movie=movie, comments=comments)

@app.route('/add_comment/<movie_id>', methods=['POST'])
def addComment(movie_id):
    text = request.form['comment']
    if not text:
        return "Comment is required", 400

    if 'user_id' not in session:
        return "Please login first", 401

    movie_id = int(movie_id)
    add_comment(movie_id, session['user_id'], text)
    return redirect(url_for("getMovie", movie_id=movie_id))

@app.route('/buy_movie/<movie_id>', methods=['POST'])
def buy_movie(movie_id):
    if 'user_id' not in session:
        return "Please login first", 401

    movie = get_movie(movie_id)
    if not movie or movie.is_sold:
        return "Movie not found or already sold", 404

    mark_movie_as_sold(movie_id)
    flash("Movie purchased successfully!", "success")
    return redirect(url_for("getMovie", movie_id=movie_id))

@app.route("/hello")
def hello():
    name = request.args.get("name")
    return f"hello, {name}" if name else "hello"

if __name__ == "__main__":
    init_db()
    init_movies_table()
    init_comments_table()
    app.run(debug=True)
