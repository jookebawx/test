from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from flask_pymongo import PyMongo

from wallet import Wallet
from bc import Blockchain
from tx import Transaction


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'samuel201'
app.config['MYSQL_DB'] = 'db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['MONGO_URI'] = "mongodb://localhost:27017/local"
mysql = MySQL(app)
mongo_client = PyMongo(app)
mongo_db = mongo_client.db

# @approute("/signup", methods = ['GET', 'POST'])
# def signup():
#     from forms import *
#     form = RegisterForm(request.form)
#     users = Table("users", "first_name", "last_name", "email", "password")
#     return render_template('newacc.html')

@app.route("/login")
def login():
    pass

@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    from formhelper import RegisterForm
    from sqlhelper import Table
    form = RegisterForm(request.form)
    users = Table("users", "first_name", "last_name", "email", "password")

    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        full_name = first_name + last_name
        wallet = Wallet(full_name, 0)
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)
        users.insert(first_name, last_name, email, password)
        mongo_db.wallets.insert_one({
            "private key" : str(wallet.private_key.to_string().hex()),
            "public_key" : str(wallet.signature),
            "address" : str(wallet.address),
            "balance" : wallet.balance
        })
        return redirect(url_for('homepage'))
    
    return render_template('signup.html', form=form)

@app.route("/homepage")
def homepage():
    return render_template('Homepage.html') 

@app.route("/")
def index():
    from sqlhelper import Table
    # form = RegisterForm(request.form)
    users = Table("users", "first_name", "last_name", "email", "password")
    # if request.method == 'POST' and form.validate():
    #     pass

    return render_template('newacc.html')

if __name__== '__main__':
    app.secret_key = '123456'
    app.run(debug = True)