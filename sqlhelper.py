
from app import mysql

class Table():
    def __init__(self, table_name, *args):
        self.table = table_name
        self.columns =  "(" + ", ".join("%s" % col for col in args) + ")"
        self.columnsList = args
        self.columnforinsert = "(" + ", ".join("%s" % col for col in args[:-1]) + ")"
    

        #if table does not already exist, create it.
        if isnewtable(table_name):
            create_data = ""
            for column in self.columnsList:
                if column == "id":
                    create_data += "%s INT AUTO_INCREMENT PRIMARY KEY," %column
                else:
                    create_data += "%s varchar(500)," %column

            cur = mysql.connection.cursor() #create the table
            cur.execute("CREATE TABLE %s(%s)" %(self.table, create_data[:len(create_data)-1]))
            cur.close()

    #get all the values from the table
    def getall(self):
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s" %self.table)
        data = cur.fetchall(); return data

    #get one value from the table based on a column's data
    #EXAMPLE using blockchain: ...getone("hash","00003f73gh93...")
    def getthree(self, search, value):
        data = {}; cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s WHERE %s = \"%s\"" %(self.table, search, value))
        if result > 0: data = cur.fetchone()
        cur.close(); return data
    
    def getsome(self, search, value):
        data = {}; cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s WHERE %s = \"%s\"" %(self.table, search, value))
        if result > 0: data = cur.fetchall()
        cur.close(); return data
    
    
    def getone(self, search, value):
        data = {}; cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM %s WHERE %s = \"%s\"" %(self.table, search, value))
        if result > 0: data = cur.fetchone()
        cur.close(); return data
    
    #delete a value from the table based on column's data
    def deleteone(self, search, value):
        cur = mysql.connection.cursor()
        cur.execute("DELETE from %s where %s = \"%s\"" %(self.table, search, value))
        mysql.connection.commit(); cur.close()

    #delete all values from the table.
    def deleteall(self):
        self.drop() #remove table and recreate
        self.__init__(self.table, *self.columnsList)

    #remove table from mysql
    def drop(self):
        cur = mysql.connection.cursor()
        cur.execute("DROP TABLE %s" %self.table)
        cur.close()

    #insert values into the table
    def insert(self, *args):
        data = ""
        for arg in args:
            data += "\'%s\'," %(arg)
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO %s %s VALUES (%s)" %(self.table, self.columnforinsert, data[:-1]))
        mysql.connection.commit()
        cur.close()



def sql_raw(execution):
    cur = mysql.connection.cursor()
    cur.execute(execution)
    mysql.connection.commit()
    cur.close()

def isnewtable(table_name):
    cur = mysql.connection.cursor()
    try:
        result = cur.execute("SELECT * from %s" %table_name)
        cur.close()
    except:
        return True
    else:
        return False
    
def isnewuser(email):
    users = Table("users", "first_name", "last_name", "email", "password","id")
    data = users.getall()
    emails = [user.get('email') for user in data]

    return False if email in emails else True

def isnewdoc(doc_name, hash):
    docs = Table("docs","doc_name", "doc_hash", "doc_author","id")
    data = docs.getall()
    docnames = [doc.get('doc_name') for doc in data]
    hashes = [dochash.get('doc_hash') for dochash in data]

    return False if doc_name in docnames or hash in hashes else True

def isnewauth(email):
    auths = Table("auths", "first_name", "last_name", "email", "password","id")
    data = auths.getall()
    emails = [auth.get('email') for auth in data]

    return False if email in emails else True
# users = Table("users", "first_name", "last_name", "email", "password")