# Movie Store Application

This is a secure web application for managing and selling movies. Users can register, log in, upload movies, view movie details, leave comments, and purchase movies. The application has been developed with a strong focus on security, including various measures to protect against common vulnerabilities.

## Main Concept

### Secure Web Application

- **Backend Development**: Developed using Flask.
- **Security Measures**:
  - **Password Hashing**: Implemented Bcrypt for secure password storage.
  - **File Upload Security**: Restricted file types and sizes to prevent unrestricted file upload vulnerabilities.
  - **Cross-Site Scripting (XSS) Protection**: Applied measures to mitigate XSS attacks.
  - **Insecure Direct Object References (IDOR) Prevention**: Implemented checks to prevent unauthorized access to resources.
  - **SQL Injection Protection**: Used parameterized queries to safeguard against SQL injection.
  - **Cookie Security**: Set secure attributes on cookies to prevent cookie-based attacks.
  - **Brute Force Attack Countermeasures**: Applied rate limiting to login attempts to mitigate brute force attacks.
  - **Price Manipulation Prevention**: Implemented checks to ensure the integrity of transaction prices.

## Features

- **User Registration and Login**: Users can create an account and log in to the application.
- **Movie Upload**: Authenticated users can upload movies with details such as title, description, price, and image.
- **Movie Listing**: Users can view a list of all movies available for sale.
- **Movie Details and Comments**: Users can view the details of a movie and read or add comments.
- **Purchase Movies**: Users can buy movies, and the movie's owner will receive the payment in their balance.
- **Admin View**: Admin users can view the list of all registered users.

## Tech Stack

- **Backend**: Flask, SQLite
- **Frontend**: HTML, CSS, Jinja2
- **Security**: Bcrypt for password hashing
- **Rate Limiting**: Flask-Limiter
- **File Validation**: Custom validation for file type and size

## Installation

1. **Clone the Repository**
    ```bash
    git clone https://github.com/your-repo/movie-store-app.git
    cd movie-store-app
    ```

2. **Set Up Virtual Environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4. **Run the Application**
    ```bash
    python store.py
    ```

5. **Access the Application**
    Open your browser and navigate to `http://127.0.0.1:5000`.

## Usage

### User Registration

1. Go to the registration page: `/register`.
2. Fill in the username and password.
3. Ensure the password meets the strength requirements.
4. Click Register.

### User Login

1. Go to the login page: `/login`.
2. Enter your username and password.
3. Click Login.

### Uploading Movies

1. Log in to your account.
2. Go to the upload movie page: `/uploadMovie`.
3. Fill in the movie details and upload an image.
4. Click Upload.

### Viewing and Commenting on Movies

1. Go to the home page: `/`.
2. Click on a movie title to view its details.
3. Add comments if you are logged in.

### Buying Movies

1. View the movie details.
2. Click the Buy button to purchase the movie.

## Validators

This project includes custom validators to ensure that uploaded files meet specific criteria. The validators are located in the `validators.py` file.

### Allowed File Extensions

The following file extensions are allowed:
- PNG
- JPG
- JPEG
- GIF

### Maximum File Size

The maximum file size for uploads is 10MB.

## Database Schema

### Users Table
- **id**: INTEGER PRIMARY KEY AUTOINCREMENT
- **username**: TEXT NOT NULL UNIQUE
- **password**: TEXT NOT NULL
- **balance**: REAL NOT NULL DEFAULT 0.0

### Movies Table
- **id**: INTEGER PRIMARY KEY AUTOINCREMENT
- **user_id**: INTEGER NOT NULL
- **title**: TEXT NOT NULL
- **description**: TEXT
- **price**: REAL NOT NULL
- **image_url**: TEXT
- **is_sold**: BOOLEAN DEFAULT 0

### Comments Table
- **id**: INTEGER PRIMARY KEY AUTOINCREMENT
- **user_id**: INTEGER NOT NULL
- **movie_id**: INTEGER NOT NULL
- **text**: TEXT NOT NULL
- **timestamp**: TIMESTAMP DEFAULT CURRENT_TIMESTAMP

## Security

- **Password Hashing**: Bcrypt is used to hash and verify passwords.
- **Rate Limiting**: Flask-Limiter is used to prevent abuse of the login endpoint.
- **File Upload Security**: Validation for file types and sizes to prevent unrestricted file uploads.
- **XSS Protection**: Measures implemented to prevent cross-site scripting attacks.
- **IDOR Prevention**: Checks to ensure authorized access to resources.
- **SQL Injection Protection**: Parameterized queries to prevent SQL injection attacks.
- **Cookie Security**: Secure attributes on cookies to prevent attacks.
- **Brute Force Protection**: Rate limiting on login attempts to prevent brute force attacks.
- **Price Manipulation Prevention**: Ensuring transaction integrity.

## Contribution

Feel free to fork this repository and contribute by submitting a pull request.


