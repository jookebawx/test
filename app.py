from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, send_file
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
from flask_pymongo import PyMongo
import hashlib
import base64
import requests

from wallet import *
from bc import Blockchain
from tx import Transaction

JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiJiYjM1ZDA1OS00YzFmLTQ5MDAtYTRiZS01YjllNzU2YWQ0OTYiLCJlbWFpbCI6InNhbW15LnNhbjIwMUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGluX3BvbGljeSI6eyJyZWdpb25zIjpbeyJpZCI6IkZSQTEiLCJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MX0seyJpZCI6Ik5ZQzEiLCJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MX1dLCJ2ZXJzaW9uIjoxfSwibWZhX2VuYWJsZWQiOmZhbHNlLCJzdGF0dXMiOiJBQ1RJVkUifSwiYXV0aGVudGljYXRpb25UeXBlIjoic2NvcGVkS2V5Iiwic2NvcGVkS2V5S2V5IjoiZTlmY2Y0OTFmMmJkZjM2YjY3MmUiLCJzY29wZWRLZXlTZWNyZXQiOiIyZTc0YmQ4Mzc2NDlkODBmZDk5YjA1OGFjYjdlOWJiMDI1ZTBjY2FlNDJiYzY4OGFlZjBlZmRiYTAyMjg0OTYyIiwiaWF0IjoxNjg5NTA3ODA2fQ.x1EfjzA_i5zNv4kj4sXii0vSMuvjOwNyVG-hv0TyM24"
chain = Blockchain()
app = Flask(__name__, static_url_path='/static')

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'samuel201'
app.config['MYSQL_DB'] = 'db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['MONGO_URI'] = "mongodb://localhost:27017/local"

mysql = MySQL(app)
mongo_client = PyMongo(app)
mongo_db = mongo_client.db


def log_in_user(email):
    from sqlhelper import Table
    users = Table("users","first_name", "last_name", "email", "password","user_id")
    user = users.getone("email", email)

    session['logged_in'] = True
    session['email'] =  email
    session['name'] =  user.get('first_name')+ " "+user.get('last_name')
    session['login_id'] = user.get('user_id')
    session['account_type'] = "User"

def log_in_auth(email):
    from sqlhelper import Table
    auths = Table("auths", "first_name", "last_name", "email", "password","auth_id")
    auth = auths.getone("email", email)

    session['logged_in'] = True
    session['email'] =  email
    session['name'] =  auth.get('first_name')+ " "+auth.get('last_name')
    session['login_id'] = auth.get('auth_id')
    session['account_type'] = "Authenticator"

def update_wallet_info(wallet,login_id):
    updated_tx = get_transaction(wallet["address"])
    update_tx_cmd = {"$set": {"transaction": updated_tx}}
    mongo_db.wallets.update_one(wallet, update_tx_cmd)
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    updated_balance = update_balance(updated_tx, wallet["address"])
    update_balance_cmd = {"$set": {"balance": updated_balance}}
    mongo_db.wallets.update_one(wallet, update_balance_cmd)
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    updated_docs = update_docs(wallet["address"])
    update_docs_cmd ={"$set": {"authenticated_docs": updated_docs}}
    mongo_db.wallets.update_one(wallet, update_docs_cmd)
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    return wallet

def update_auth_wallet_info(wallet,login_id):
    updated_tx = get_transaction(wallet["address"])
    update_tx_cmd = {"$set": {"transaction": updated_tx}}
    mongo_db.auth_wallets.update_one(wallet, update_tx_cmd)
    wallet = mongo_db.auth_wallets.find_one({'login_id': login_id})
    updated_balance = update_balance(updated_tx, wallet["address"])
    update_balance_cmd = {"$set": {"balance": updated_balance}}
    mongo_db.auth_wallets.update_one(wallet, update_balance_cmd)
    wallet = mongo_db.auth_wallets.find_one({'login_id': login_id})
    return wallet

@app.route("/wallet", methods = ['GET', 'POST'])
def wallet_page():
    login_id=session['login_id']
    acc_type = session['account_type']
    if acc_type == "User":
        wallet = mongo_db.wallets.find_one({'login_id': login_id})
        wallet = update_wallet_info(wallet,login_id)
        links = get_doc_link(wallet["address"])
        homelink = "/homepage"
    else:
        wallet =mongo_db.auth_wallets.find_one({'login_id': login_id})
        wallet = update_auth_wallet_info(wallet,login_id)
        links = ""
        homelink = "/homepage_auth"
    name = session['name']
    return render_template('wallet.html', wallet=wallet, name=name, links=links, homelink=homelink)

@app.route("/send", methods = ['GET', 'POST'])
def send():
    from formhelper import SendMoneyForm

    form = SendMoneyForm(request.form)
    login_id=session['login_id']
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    message = ""
    classname=""
    if request.method == 'POST' and form.validate():
        receiver_address = form.receiver.data
        amount = form.amount.data
        if int(amount) > wallet["balance"]:
            message = "The inputted amount exceed your balance"
            classname = "notenough"
            return render_template('send.html', wallet=wallet, form=form, classname = classname, message=message)
        else:
            tx ={
                "type" : "Crypto",
                "receiver": receiver_address,
                "amount": int(amount)
            }
            chain.mining(Block(INITIAL_BITS,chain.get_chain_length(),tx,datetime.datetime.now(), "", wallet["address"]))
            wallet = update_wallet_info(wallet,login_id)

    return render_template('send.html', wallet=wallet, form=form, message=message)

@app.route("/login", methods = ['GET', 'POST'])
def login():
    from sqlhelper import Table
    if request.method == 'POST':
        email = request.form['email']
        candidate = request.form['password']
        users = Table("users","first_name", "last_name", "email", "password","user_id")
        user = users.getone("email", email)
        accpass= user.get('password')
        
        if accpass is None:
            auths = Table("auths", "first_name", "last_name", "email", "password","auth_id")
            auth = auths.getone("email", email)
            authpass = auth.get('password')
            if authpass is None:
                flash("email not found", 'danger')
                return redirect(url_for('login'))
            else:
                if sha256_crypt.verify(candidate, authpass):
                    log_in_auth(email)
                    flash('You are now logged in', 'success')
                    return redirect(url_for('homepage_auth'))
                else: 
                    flash('Invalid password', 'success')
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
    import PyPDF2
    from sqlhelper import Table, isnewdoc, isnewtable,sql_raw
    doc = Table("docs","doc_name", "doc_hash", "doc_author","author_sign","doc_id")
    authenticators = Table("auths", "first_name", "last_name", "email", "password","auth_id")
    login_id=session['login_id']
    name = session['name']
    email = session['email']
    wallet = mongo_db.wallets.find_one({'login_id': login_id})
    author = wallet["address"]
    author_priv_key = str_to_signing_key(wallet["private_key"])
    uploaded_docs=doc.getsome("doc_author",author)
    uploaded_docname=[uploaded_doc["doc_name"] for uploaded_doc in uploaded_docs]
    message = ""
    if request.method == 'POST':
        # Check if the file key is present in the request
        if 'file' not in request.files:
            return 'No file uploaded.', 400

        # Get the uploaded file from the request object
        uploaded_file = request.files['file']

        # Check if the file is empty
        if uploaded_file.filename == '':
            return 'No file selected.', 400
        file_path = 'static/uploaded-file/' + uploaded_file.filename
        uploaded_file.save(file_path)
        # Open the uploaded file using PyPDF2
        pdf_reader = PyPDF2.PdfReader(uploaded_file)

        # Extract the text from the PDF file
        text = ''
        for i in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[i]
            text += page.extract_text()
        hash = hashlib.sha256(text.encode()).hexdigest()
        author_sign = sign_transaction(author_priv_key, hash)
        if isnewdoc(uploaded_file.filename, hash):
            doc.insert(uploaded_file.filename, hash, author, author_sign)
            doc_id = doc.getone("doc_name", uploaded_file.filename)["doc_id"]
            if isnewtable("auth_session"):
                command = """
                CREATE TABLE auth_session (
                            doc_id int, 
                            authenticator_id int, 
                            signature varchar(500),
                            auth_session_id INT AUTO_INCREMENT PRIMARY KEY,
                            FOREIGN KEY (doc_id) REFERENCES docs(doc_id),
                            FOREIGN KEY (authenticator_id) REFERENCES auths(auth_id)
                            );
                """
                sql_raw(command)
            auth_session = Table("auth_session","doc_id","authenticator_id","signature","auth_session_id")
            uploaded_docs=doc.getsome("doc_author",author)
            uploaded_docname=[uploaded_doc["doc_name"] for uploaded_doc in uploaded_docs]
            rand_auths = authenticators.get_rand(3)
            rand_auth_ids = [rand_auth["auth_id"] for rand_auth in rand_auths]
            signature = None
            for id in rand_auth_ids:
                auth_session.insert(doc_id, id, signature)
            return render_template('SubmitPage.html',message=message,uploaded_doc=uploaded_docname, name=name, email=email)
        else:
            message = "Your document already exist"
            return render_template('SubmitPage.html',message=message,uploaded_doc=uploaded_docname, name=name, email=email)
    # Render the extracted text on a new page
    return render_template('SubmitPage.html',message=message, uploaded_doc=uploaded_docname, name=name, email=email)

@app.route("/authenticate")
def authenticate():
    from sqlhelper import Table
    doc_table = Table("docs","doc_name", "doc_hash", "doc_author","author_sign","doc_id")
    auth_session_table = Table("auth_session","doc_id","authenticator_id","signature", "auth_session_id")
    login_id = session['login_id']
    name = session['name']
    email = session['email']
    doc_id_to_auth = [doc_id['doc_id'] for doc_id in auth_session_table.getsome("authenticator_id", login_id)]
    doc_name_to_auth = []
    for id in doc_id_to_auth:
        docname = doc_table.getone("doc_id",id)
        doc_name_to_auth.append(docname["doc_name"])
    doc_to_auth = [{
                    "doc_id": doc_id,
                    "doc_name": doc_name
                    } for doc_id, doc_name in zip(doc_id_to_auth, doc_name_to_auth)]
    links = [(item["doc_name"],  f'/authenticate/{item["doc_id"]}',f'/authenticate/{item["doc_name"]}')for item in doc_to_auth]
    return render_template("authenticate.html", docname=doc_name_to_auth, links=links, name=name, email=email)
@app.route("/authenticate/<string:docname>")
def view(docname):
     pdf_path = 'static/uploaded-file/' + docname
     return send_file(pdf_path, mimetype='application/pdf')

@app.route("/authenticate/<int:id>")
def sign(id):
    from sqlhelper import Table,sql_raw
    doc_table = Table("docs","doc_name", "doc_hash", "doc_author","author_sign","doc_id")
    auth_session_table = Table("auth_session","doc_id","authenticator_id","signature","auth_session_id")
    login_id = session['login_id']

    hash = doc_table.getone("doc_id",id)["doc_hash"]
    wallet = mongo_db.auth_wallets.find_one({'login_id': login_id})
    priv_key = str_to_signing_key(wallet["private_key"])
    author_address = doc_table.getone("doc_id",id)["doc_author"]
    authenticator_sign = sign_transaction(priv_key, hash)
    doc_name = doc_table.getone("doc_id", id)["doc_name"]
    auth_session_id = auth_session_table.getby2value("authenticator_id", login_id, "doc_id", id)["auth_session_id"]
    sql_command = "UPDATE auth_session SET signature = \"%s\" WHERE auth_session_id =%s" %(authenticator_sign,auth_session_id)
    sql_raw(sql_command)
    auth_signs = [auth_sign["signature"] for auth_sign in auth_session_table.getsome("doc_id",id)]
    if len([value for value in auth_signs if value is not None]) == 3:
        file_path ='static/uploaded-file/' + doc_name
        tx=""
        block = Block(INITIAL_BITS,chain.get_chain_length(),tx,datetime.datetime.now(), "", author_address)
        block.signatures = auth_signs
        block.signatures.append(doc_table.getone("doc_id",id)["author_sign"])
        doc_metadata = "{\"name\" : \"%s\",\
                         \"keyvalues\":{\
                                \"doc_author\":\"%s\", \
                                \"doc_hash\":\"%s\", \
                                \"authenticators\":\"%s\", \
                                \"authenticated_date\":\"%s\"} }"%(doc_name,author_address,hash,block.signatures,str(datetime.datetime.now()))
        print(doc_metadata)
        url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
        payload={'pinataOptions': '{"cidVersion": 1}',
        'pinataMetadata':  doc_metadata}
        print(payload)
        file = open(file_path, 'rb')
        files=[
        ('file',(doc_name,file,'application/octet-stream'))
        ]
        headers = {
            'Authorization': 'Bearer %s'%(JWT)
        }
        response = requests.request("POST", url, headers=headers, data=payload, files=files)
        response_text= json.loads(response.text)
        print(response_text)
        cid = response_text["IpfsHash"]
        
        tx={
            "type": "Docs",
            "doc_name": doc_name,
            "doc_hash": hash,
            "ipfs_hash": cid
        }
        block.tx = tx
        chain.mining(block)  
        auth_session_ids = [auth_sess_id["auth_session_id"] for auth_sess_id in auth_session_table.getsome("doc_id",id)]
        for auth_sess_id in auth_session_ids:
            auth_session_table.deleteone("auth_session_id",auth_sess_id)
        doc_table.deleteone("doc_id",id)
        file.close()
        if os.path.exists(file_path):
            os.remove(file_path)
    return redirect(url_for('authenticate'))

@app.route("/logout")
def logout():
    session.clear()
    flash("Logout success", "success")
    return redirect(url_for('index'))

@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    from formhelper import RegisterForm
    from sqlhelper import Table, isnewuser, isnewauth
    form = RegisterForm(request.form)
    users = Table("users","first_name", "last_name", "email", "password","user_id")
    auths = Table("auths", "first_name", "last_name", "email", "password","auth_id")
    message =""
    if request.method == 'POST' and form.validate():
        first_name = form.first_name.data
        last_name = form.last_name.data
        auth_type = form.auth_type.data
        priv_key = generate_private_key()
        priv_key_bytes = priv_key.to_der()
        priv_key_string = base64.b64encode(priv_key_bytes).decode('ascii')
        pub_key = generate_public_key(priv_key)
        pub_key_bytes = pub_key.to_der()
        pub_key_string = base64.b64encode(pub_key_bytes).decode('ascii')
        address = generate_address(pub_key_bytes)
        email = form.email.data
        if auth_type == "regular":
            if isnewuser(email):
                password = sha256_crypt.hash(form.password.data)
                users.insert(first_name, last_name, email, password)
                login_id=users.getone("email",email)["user_id"]
                mongo_db.wallets.insert_one({
                    "login_id": login_id,
                    "private_key" : priv_key_string,
                    "public_key" : pub_key_string,
                    "address" : address.decode('ascii'),
                    "balance" : 100,
                    "authenticated_docs":"",
                    "transaction":get_transaction(address)
                })
                log_in_user(email)
                return redirect(url_for('homepage'))
            else:
                message ="Account already exist"
                render_template('signup.html', form=form, message=message)
        elif auth_type =="auth":
            if isnewuser(email):
                if isnewauth(email):
                    password = sha256_crypt.hash(form.password.data)
                    auths.insert(first_name, last_name, email, password)
                    login_id=auths.getone("email",email)["auth_id"]
                    mongo_db.auth_wallets.insert_one({
                        "login_id": login_id,
                        "private_key" : priv_key_string,
                        "public_key" : pub_key_string,
                        "address" : address.decode('ascii'),
                        "balance" : 100,
                        "transaction":get_transaction(address)
                    })
                    log_in_auth(email)
                    return redirect(url_for('homepage_auth'))
                else:
                    message ="Account already exist"
                    render_template('signup.html', form=form, message=message)
            else:
                message ="Account already exist"
                render_template('signup.html', form=form, message=message)
    return render_template('signup.html', form=form, message=message)

@app.route("/homepage")
def homepage():
    name = session['name']
    email = session['email']
    return render_template('Homepage.html', name = name, email = email) 

@app.route("/homepage_auth")
def homepage_auth():
    name = session['name']
    email = session['email']
    return render_template('Homepage_auth.html',name = name, email=email) 

@app.route("/")
def index():
    return render_template('newacc.html')

if __name__== '__main__':
    app.secret_key = '123456'
    app.run(debug = True)