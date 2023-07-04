from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from flask_pymongo import PyMongo

from wallet import *
from bc import Blockchain
from tx import Transaction

chain = Blockchain()
app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MONGO_URI'] = "mongodb://localhost:27017/local"

mysql = MySQL(app)
mongo_client = PyMongo(app)
mongo_db = mongo_client.db

def log_in_user(email):
    from sqlhelper import Table
    users = Table("users", "first_name", "last_name", "email", "password")
    user = users.getone("email", email)

    session['logged_in'] = True
    session['email'] =  email
    session['name'] =  user.get('first_name')+ " "+user.get('last_name')
    session['login_id'] = user.get('id')

@app.route("/wallet", methods = ['GET', 'POST'])
def wallet_page():
    login_id=session['login_id']
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    updated_tx = get_transaction(wallet["address"])
    update_tx_cmd = {"$set": {"transaction": updated_tx}}
    mongo_db.wallets.update_one(wallet, update_tx_cmd)
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    updated_balance = update_balance(updated_tx, wallet["address"])
    update_balance_cmd = {"$set": {"balance": updated_balance}}
    mongo_db.wallets.update_one(wallet, update_balance_cmd)
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    
    name = session['name']
    return render_template('wallet.html', wallet=wallet, name=name)

@app.route("/send", methods = ['GET', 'POST'])
def send():
    from formhelper import SendMoneyForm

    form = SendMoneyForm(request.form)
    login_id=session['login_id']
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
   
    if request.method == 'POST' and form.validate():
        receiver_address = form.receiver.data
        amount = form.amount.data
        print(receiver_address)
        tx ={
            "receiver": receiver_address,
            "amount": int(amount)
        }

        chain.mining(Block(INITIAL_BITS,chain.get_chain_length(),tx,datetime.datetime.now(), "", wallet["address"]))
        updated_tx = get_transaction(wallet["address"])
        update_tx_cmd = {"$set": {"transaction": updated_tx}}
        mongo_db.wallets.update_one(wallet, update_tx_cmd)
        wallet = mongo_db.wallets.find_one({'login_id': login_id})
        updated_balance = update_balance(updated_tx, wallet["address"])
        update_balance_cmd = {"$set": {"balance": updated_balance}}
        mongo_db.wallets.update_one(wallet, update_balance_cmd)
        wallet = mongo_db.wallets.find_one({'login_id': login_id})

    return render_template('send.html', wallet=wallet, form=form)

@app.route("/login", methods = ['GET', 'POST'])
def login():
    from sqlhelper import Table
    if request.method == 'POST':
        email = request.form['email']
        candidate = request.form['password']

        users = Table("users", "first_name", "last_name", "email", "password")
        user = users.getone("email", email)
        accpass= user.get('password')

        if accpass is None:
            flash("email not found", 'danger')
            return redirect(url_for('login'))
        else: 
            if sha256_crypt.verify(candidate, accpass):
                log_in_user(email)
                flash('You are now logged in', 'success')
                return redirect(url_for('homepage'))
            else: 
                flash('Invalid password', 'success')
                return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/upload", methods = ['GET', 'POST'])
def upload():
    return render_template('SubmitPage.html')

@app.route("/logout")
def logout():
    session.clear()
    flash("Logout success", "success")
    return redirect(url_for('index'))

@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    from formhelper import RegisterForm
    from sqlhelper import Table, isnewuser
    form = RegisterForm(request.form)
    users = Table("users","first_name", "last_name", "email", "password","id")

    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        full_name = first_name + last_name
        priv_key = generate_private_key()
        pub_key = generate_public_key(priv_key)
        address = generate_address(pub_key)
        email = form.email.data
        
        if isnewuser(email):
            password = sha256_crypt.hash(form.password.data)
            users.insert(first_name, last_name, email, password)
            login_id=users.getid("email",email)["id"]
            print(login_id)
            mongo_db.wallets.insert_one({
                "login_id": login_id,
                "private_key" : priv_key.to_string().hex(),
                "public_key" : pub_key.hex(),
                "address" : address.decode('ascii'),
                "balance" : 0,
                "transaction":get_transaction(address)
            })
            log_in_user(email)
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('signup'))
        
    return render_template('signup.html', form=form)

@app.route("/homepage")
def homepage():
    return render_template('Homepage.html') 

@app.route("/")
def index():
    return render_template('newacc.html')

if __name__== '__main__':
    app.secret_key = '123456'
    app.run(debug = True)