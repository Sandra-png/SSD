from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for, flash
import sqlite3
import bcrypt
import traceback
import re
import jwt
from functools import wraps
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask (__name__)

app.config['SECRET_KEY'] = 'secret_key321'
app.config ["UPLOAD_FOLDER"] = "uploads"


# --------------------- FUNCTIONS ---------------------
# Function to create / connect to database
def initiateDatabase ():
    try:
        # Creating a database (or connecting once its been created)
        print ("Creating or connecting to database 'uploads_data.db'")
        connect = sqlite3.connect ("uploads_data.db")
        cursor = connect.cursor()

        # Creating the table where we will store log in and files, and comitting it to the created database
        print ('Creating a table to store data.')
        cursor.execute ('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL
            )
        ''')
        
        # Creating a table to store tokens
        print ('Creating a table to store tokens.')
        cursor.execute ('''
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                user_id TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Creating a table to store file metadata
        print ('Creating a table to store file metadata.')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL
            )
        ''')
        
        print ("\nDatabase 'login_data.db' created.")

        connect.commit()
        
    except Exception as e:
        print ("\nAn error occured:", e)
        traceback.print_exc()
        
    finally:
        # Always close the database after it's done getting used! :)
        connect.close()
        print ("\nDatabase connection closed.")

# Running to make sure the database is created everytime you run the server
initiateDatabase()


# Function to hash the password using bcrypt
def hashPassword (password):
    return bcrypt.hashpw(password.encode ("utf-8"), bcrypt.gensalt())

# Input validation
def validateUsername (username):
    pattern = r'^[a-zA-Z0-9_-]{4,20}$'
    return bool(re.match(pattern, username))
def validatePassword (password):
    pattern = r'^[a-zA-Z0-9._%+-]+'
    return bool(re.match(pattern, password))
def validateEmail (email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

# Function to authenticate username and password
def authenticate (username, password):
    with sqlite3.connect ("uploads_data.db") as connect:
        cursor = connect.cursor()
        
        cursor.execute ('SELECT password FROM users WHERE username=?', (username, ))
        result = cursor.fetchone()
        
        if result:
            dbPassword = result[0]
            bytePassword = password.encode ("utf-8")
            
            if bcrypt.checkpw (bytePassword, dbPassword):
                return True


# Function to generate tokens based on user id, and save them to the database
def generate_token(user_id):
    try:
        # Generate a new token
        token = jwt.encode({"user_id": user_id}, app.config["SECRET_KEY"], algorithm="HS256")
        
        # Store the token in the database
        with sqlite3.connect("uploads_data.db") as connect:
            cursor = connect.cursor()
            cursor.execute("INSERT INTO tokens (token, user_id) VALUES (?, ?)", (token, user_id))
            connect.commit()
        
        return token
    except Exception as e:
        print("\nAn error occurred while generating and storing the token:", e)
        return None

# --------------------- ROUTES ---------------------

# Home page that loads when you first enter the app
@app.route ("/")
def home():
    return render_template ("home.html")

# Route to the registration page...
@app.route ("/register_page", methods = ["GET"])
def register_page():
    return render_template ("register.html")

# Route to the login page...
@app.route ("/login_page", methods = ["GET"])
def login_page():
    return render_template ("login.html")

# Route to reset password page...
@app.route ("/reset_password", methods = ["GET", "POST"])
def reset_password_page():
    token = request.args.get("token")
    
    if not token:
        return jsonify({"message": "No token found."}), 401
    
    try:
        if request.method == "GET":
            return render_template ("reset_password.html")

        elif request.method == "POST":
            email = request.form.get ("email")
            password = request.form.get ("password")
                
            try:
                with sqlite3.connect("uploads_data.db") as connect:
                    cursor = connect.cursor()
                    cursor.execute("SELECT id, email, password FROM users WHERE email = ?", (email, ))
                    user = cursor.fetchone()

                    if user and bcrypt.checkpw(password.encode("utf-8"), user[2]):
                        user_id, email, _ = user
                        token = generate_token (user_id)
                        
                        if token:
                            with sqlite3.connect ("uploads_data.db") as connect:
                                cursor = connect.cursor()
                                cursor.execute ("INSERT INTO tokens (token, user_id) VALUES (?, ?)", (token, user_id))
                                connect.commit()
                                
                            return redirect (url_for ("reset_password_confirmation", token = token, user_id = user_id))
                    
                    else:
                        return jsonify ({"error": "Could not find user_id."}), 500
                
            except Exception as e:
                print ("Could not find user by email, error:", e)
                return jsonify ({"error": "Could not find user by email."}), 500
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Please log in again. Token has expired."}), 401

    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token."}), 401
            
    except Exception as e:
        print("\nAn error occurred:", e)
        return jsonify({"message": "Internal server error."}), 500

# Route to the confirmation of password reset
@app.route ("/reset_password_confirmation", methods = ["GET", "POST"])
def reset_password_confirmation():
    try:
        token = request.args.get("token")
        user_id = request.args.get("user_id")
        
        if not token or not user_id:
            return jsonify({"message": "No token or user_id found."}), 401
        
        try:
            if request.method == "GET":
                return render_template ("reset_password_confirmation.html")
        
            elif request.method == "POST":
                try:
                    if user_id:
                        new_password = request.form.get ("new_password")
                        
                        if not new_password:
                            return jsonify({"message": "Please do not leave the field empty."})
                        
                        if not validatePassword(new_password):
                            return make_response(jsonify({"Please make sure password follows the correct format."}), 400)

                        # Hashing the new password
                        hashed_password = hashPassword (new_password)
                        
                        # Updating the database with the new password
                        with sqlite3.connect ("uploads_data.db") as connect:
                            cursor = connect.cursor()
                            cursor.execute ("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
                            connect.commit()
                        
                            # Put users back to login after changing the password
                            return redirect (url_for ("login_page"))
                        
                    else:
                        return jsonify({"error": "Invalid token."}), 401
                
                except Exception as e:
                    print ("Could not find user, error:", e)
                    return jsonify ({"error": "Could not find user."}), 500
                
        except Exception as e:
            print ("Could not find user by email, error:", e)
            return jsonify ({"error": "Could not find user by email."}), 500
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Please log in again. Token has expired."}), 401

    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token."}), 401
            
    except Exception as e:
        print("\nAn error occurred:", e)
        return jsonify({"message": "Internal server error."}), 500

# Function to register a new user in the register route.
@app.route ("/register", methods = ["GET", "POST"])
def register ():
    try:
        username = request.form.get ("username")
        password = request.form.get ("password")
        email = request.form.get ("email")
            
        # Making sure username, password and email are not empty
        if not username or not password or not email:
            return make_response(jsonify({"Please make sure username and password are not empty."}), 400)
            
        if not validateUsername(username) or not validatePassword (password):
            return make_response(jsonify({"Please make sure username and password follow the correct format."}), 400)
            
        # Hashing the password
        hashedPassword = hashPassword (password)
        
        # Opening the database
        with sqlite3.connect ("uploads_data.db") as connect:
            cursor = connect.cursor()

            # Adding the information to the database...
            cursor.execute ('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashedPassword, email))
            connect.commit()
            
            # Redirecting to login when you register :)
            return redirect (url_for ("login_page"))

    except sqlite3.IntegrityError:
        return make_response(jsonify({"error": "Username already exists"}), 400)

    except Exception as e:
        print("\nAn error occurred:", e)
        return make_response(jsonify({"error": "Internal server error"}), 500)

# Function to log in to a new user (comparing database password with users input), in the login route, getting access token
@app.route ("/login", methods = ["GET", "POST"])
def logIn():
    try:
        username = request.form.get ("username")
        password = request.form.get ("password")
            
        # Check if username and password are provided
        if not username or not password:
            return make_response(jsonify({"error": "Please insert username and password."}), 400)

        with sqlite3.connect("uploads_data.db") as connect:
            cursor = connect.cursor()
            cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username, ))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode("utf-8"), user[2]):
                user_id, username, _ = user
                token = generate_token (user_id)
                
                if token:
                    # Redirecting to the verified page, adding the token as a query parameter to pass the require_authentication check
                    return redirect(url_for("verified", token=token))

                else:
                    return make_response (jsonify({"error": "Could not generate and store token."}), 500)

        return make_response (jsonify({"error": "Invalid username or password"}), 401)

    except Exception as e:
        print("\nAn error occurred:", e)
        return make_response (jsonify({"error": "Server error."}), 500)

@app.route ("/verified")
def verified():
    token = request.args.get("token")
    
    if not token:
        return jsonify({"message": "There is no token."}), 401
    
    try:
        return render_template("verified.html", token = token)
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Please log in again. Token has expired."}), 401

    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token."}), 401

@app.route ("/file_management", methods = ["GET", "POST"])
# If the user is in session, you can show the page
def file_management():
    token = request.args.get("token")
    
    if not token:
        return jsonify({"message": "There is no token."}), 401
    
    try:
        print ("poop")
        return render_template("file_management.html", token=token)
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Please log in again. Token has expired."}), 401

    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token."}), 401

@app.route ("/upload_file", methods = ["GET", "POST"])
def upload_file():
    try:
        token = request.args.get("token")
        
        if not token:
            return jsonify({"message": "There is no token."}), 401
        
        try:
            if request.method == "GET":
                return render_template ("upload_file.html")
        
            elif request.method == "POST":
                file = request.files ["file"]
                
                # Check if there is a file
                if 'file' not in request.files:
                    return jsonify({"error": "Please select a file to upload."}), 400
                
                file = request.files['file']

                # Check if the file has a name
                if file.filename == '':
                    return jsonify({"error": "Your file must have a name to be uploaded."}), 400

                # ! OBS ! I have used the pip install Werkzeug library for this ! OBS !
                # Sanitizes the name of the file
                filename = secure_filename(file.filename)

                # Saving the file to the UPLOAD_FOLDER
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save (filepath)
                flash (f"Your file has been uploaded to the folder.")
                
                # Storing it in the database
                with sqlite3.connect("uploads_data.db") as connect:
                    cursor = connect.cursor()
                    cursor.execute("INSERT INTO files (filename, filepath) VALUES (?, ?)", (filename,  filepath))
                    connect.commit()
                
                flash (f"Your file has been uploaded to the database.")
                return redirect (request.url)
                
        except Exception as e:
            print ("\nAn error occurred:", e)
            return jsonify({"error": "Server error."}), 500
        
    except Exception as e:
        print ("\nAn error occurred:", e)
        return jsonify({"error": "Server error."}), 500

# Endpoint to download filenames
@app.route("/download_file/<filename>", methods=["GET"])
def download_file_by_filename(filename):
    try:
        token = request.args.get("token")
    
        if not token:
            return jsonify({"message": "There is no token."}), 401
        
        try:
            # Get the path to the file to be downloaded
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Use Flask's send_file function to send the file as a response
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Please log in again. Token has expired."}), 401

        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token."}), 401
    
    except Exception as e:
        print("\nAn error occurred:", e)
        return jsonify({"error": "Server error."}), 500

@app.route ("/download_file", methods = ["GET"])
def download_file():
    token = request.args.get("token")
    
    if not token:
        return jsonify({"message": "There is no token."}), 401
    
    try:
        files_to_download = os.listdir(app.config['UPLOAD_FOLDER'])
        
        return render_template ("download_file.html", files_to_download = files_to_download, token = token)
    
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Please log in again. Token has expired."}), 401

    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token."}), 401
    



# ----------------- ENVIRONMENT VARIABLE -----------------

if __name__ == "__main__":
    app.run (debug = True)
