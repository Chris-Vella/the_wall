import re
from flask import Flask, render_template, redirect, request, flash, session
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app, 'walldb')
app.secret_key = 'bleh'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    query = "SELECT * from users where email = :email LIMIT 1"
    data = {
        'email': request.form['email']
    }
    get_user = mysql.query_db(query, data)
    if get_user:
        session['userid'] = get_user[0]['id']
        session['user_first_name'] = get_user[0]['first_name']
        hashed_password = get_user[0]['password']
        if bcrypt.check_password_hash(hashed_password, request.form['password']):
            session['logged_in'] = True
            flash("Login successful!")
            return redirect('/wall')
        else:
            session['logged_in'] = False
            flash("Login failed. Re-enter your credentials or register.")
            return redirect('/')
    else:
        flash("Your email could not be found.")
        return redirect('/')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    flash("You have successfuly logged out.")
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = 0
    if request.method == 'POST':
        first_name = request.form['first_name']
        if not first_name:
            error += 1
            flash("A first name is required.")
        elif not first_name.isalpha():
            error += 1
            flash("Invalid character type, please use letters only.")
        elif len(first_name) < 3:
            error += 1
            flash("First Name must be longer than 2 characters.")

        last_name = request.form['last_name']
        if not last_name:
            error += 1
            flash("A last name is required.")
        elif not last_name.isalpha():
            error += 1
            flash("Invalid character type, please use letters only.")
        elif len(last_name) < 3:
            error += 1
            flash("Last Name must be longer than 2 characters.")
        email = request.form['email']
        if not re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
            error += 1
            flash("Invalid email address.")

        user_password = request.form['user_password']
        confirm_password = request.form['confirm_password']
        if not user_password:
            error += 1
            flash("A Password is required.")
        elif not confirm_password:
            error += 1
            flash("Please confirm your password.")
        if user_password != confirm_password:
            error += 1
            flash("Password does not match. Try again.")
        elif len(user_password) < 8:
            error += 1
            flash("Password must be at least 8 characters long.")
        if error > 0:
            return redirect('/register')
        else:
            pw_hash = bcrypt.generate_password_hash(user_password)
            query = "INSERT INTO users (first_name, last_name, email, password, created_at, \
                                        updated_at) values (:first_name, :last_name, :email, \
                                        :password, now(), now())"
            data = {
                'first_name': first_name, 'last_name': last_name, \
                'email': email, 'password': pw_hash}
            mysql.query_db(query, data)
            session['logged_in'] = True
            return redirect('/wall')
    else:
        if request.method == 'GET':
            return render_template('registration.html')

@app.route('/wall')
def home():
    if not session['logged_in']:
        flash("Your are not currently logged in, please login or register.")
        return render_template('login.html')
    else:
        messagequery = (
            "SELECT m.message, DATE_FORMAT(m.created_at,'%M %D %Y') as datecreated, u.first_name,u.last_name,m.id FROM messages m JOIN users u on m.user_id = u.id ORDER BY id DESC")
        get_messages = mysql.query_db(messagequery)
        
        commentquery = (
            "SELECT c.comment, DATE_FORMAT(c.created_at,'%M %D %Y') as datecreated, u.first_name,u.last_name,c.message_id FROM comments c JOIN users u on c.user_id = u.id")
        get_comments = mysql.query_db(commentquery)

        return render_template('wall.html',user_messages=get_messages, user_comments=get_comments)
    
@app.route('/postmessage', methods=['GET', 'POST'])
def postmessage():
    try:
        session['logged_in']
    except KeyError:
        session['logged_in'] = False
   
    if session['logged_in']:
        query = "INSERT INTO messages (message, created_at, updated_at, user_id) \
                                    values (:message, now(), now(), :user_id)"
        data = {
            'message': request.form['message'], 'user_id': session['id']
        }
        mysql.query_db(query, data)
        return redirect('/')
    else:
        flash("Messages can only be posted while you are logged in.")
        flash("Please try logging in, or registering before posting a message. ")
        return redirect('/')

@app.route('/postcomment', methods=['GET', 'POST'])
def postcomment():
    try:
        session['logged_in']
    except KeyError:
        session['logged_in'] = False

    if session['logged_in']:
        query = "INSERT INTO comments (comment, created_at, updated_at, user_id, message_id) \
                                    values (:comment, now(), now(), :user_id, :message_id)"
        data = {
            'comment': request.form['comment'], 'message_id': request.form['messageid'], \
            'user_id': session['id']
        }
        mysql.query_db(query, data)
        return redirect('/')
    else:
        flash("Comments an only be posted while you are logged in.")
        flash("Please try logging in, or registering before posting a comment.")
        return redirect('/')

app.run(debug=True)