import socket
from threading import Thread
import json
import math
import random
from random import randrange, getrandbits
import copy
import time
import hashlib

q = None
alpha = None
X = None
Y = None
Y_client = None
mutual_shared_key = None
password_file = []

initial_encoding = [['A', '01'], ['B', '02'], ['C', '03'], ['D', '04'], ['E', '05'], ['F', '06'], ['G', '07'], ['H', '08'],
                    ['I', '09'], ['J', '10'], ['K', '11'], ['L', '12'], ['M', '13'], ['N', '14'], ['O', '15'], ['P', '16'],
                    ['Q', '17'], ['R', '18'], ['S', '19'], ['T', '20'], ['U', '21'], ['V', '22'], ['W', '23'], ['X', '24'],
                    ['Y', '25'], ['Z', '26'], [',', '27'], ['.', '28'], ['?', '29'], ['0', '30'], ['1', '31'], ['2', '32'],
                    ['3', '33'], ['4', '34'], ['5', '35'], ['6', '36'], ['7', '37'], ['8', '38'], ['9', '39'], ['a', '40'],
                    ['b', '41'], ['c', '42'], ['d', '43'], ['e', '44'], ['f', '45'], ['g', '46'], ['h', '47'], ['i', '48'],
                    ['j', '49'], ['k', '50'], ['l', '51'], ['m', '52'], ['n', '53'], ['o', '54'], ['p', '55'], ['q', '56'],
                    ['r', '57'], ['s', '58'], ['t', '59'], ['u', '60'], ['v', '61'], ['w', '62'], ['x', '63'], ['y', '64'],
                    ['z', '65'], ['!', '66']]

clients_data = []

clients_credentials = []

def new_encoding(val):
    shift = val%len(initial_encoding)
    encoding_copy = copy.deepcopy(initial_encoding)
    if shift == 0:
        return encoding_copy
    else:
        m_idx = len(initial_encoding) - shift
        p=0
        while m_idx < len(initial_encoding):
            encoding_copy[p][0] = initial_encoding[m_idx][0]
            m_idx+=1
            p+=1
        p = 0
        while shift < len(initial_encoding):
            encoding_copy[shift][0] = initial_encoding[p][0]
            shift+=1
            p+=1
    return encoding_copy

def decrypt(encoded_data, encoding_used):
    decrypted_text = ""
    i=0
    while i<len(encoded_data)-1:
        enc_substr = encoded_data[i]+encoded_data[i+1]
        for enc in encoding_used:
            if enc_substr == "00":
                decrypted_text = decrypted_text + " "
                break
            elif enc[1] == enc_substr:
                decrypted_text = decrypted_text + enc[0]
                break
        i+=2
    return decrypted_text



def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

def generate_prime_candidate(length):
    p = getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=20):
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def generate_keys():
    global q
    global alpha
    global X
    global Y
    X = random.randint(2,q-1)
    Y = (alpha**X) % q

def return_roots(num):
    roots_list = []
    while num%2 == 0:
        roots_list.append(2)
        num = num/2
    root = math.sqrt(num)
    i=3
    while i<= root:
        while num%i == 0:
            roots_list.append(i)
            num = num/i
        i+=2
    if num>2:
        roots_list.append(num)
    return list(set(roots_list))

def find_premitive_root(prime):
    roots_list = return_roots(prime-1)
    r=2
    breaked = False
    while r <= (prime-1):
       flag = False
       for root in roots_list:
           to_div = int((prime-1)/root)
           val = (r**to_div) % prime
           if val == 1:
               flag = True
               break
       if flag == False:
           primitive_root = r
           breaked = True
           break
       r+=1

    if breaked == False:
        primitive_root = -1
    return primitive_root

class ListenClients(Thread):
    def __init__(self, sock, self_ip, self_port):
        Thread.__init__(self)
        self.sock = sock
        self.ip = self_ip
        self.port = self_port
        self.RCVCHUNKSIZE = 1024*1024*64

    def send_json_data(self, ip, port, data):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.sendall(str(data).encode())
            s.close()
        except:
            print("Connection refused by the master: "+ip+":"+str(port))

    def run(self):
        global q
        global alpha
        global X, Y
        global Y_client
        global mutual_shared_key
        global clients_data
        global password_file
        data = []
        while True:
            data_rcv = self.sock.recv(self.RCVCHUNKSIZE)
            if not data_rcv:
                break
            data.append(data_rcv)
        data = b''.join(data)

        #try:
        data = data.decode()
        data = data.replace("\'", "\"")
        j = json.loads(data)
        if j["topic"] == "request_keys":
            client_ip = j["ip"]
            client_port = j["port"]
            q = generate_prime_number()
            alpha = find_premitive_root(q)
            generate_keys()
            print("Global Q is: ",q)
            print("Global alpha is: ",alpha)
            print("X_server is: ", X)
            print("Y_server is: ", Y)
            send_data = {}
            send_data["topic"] = "request_keys_resp"
            send_data["data"] = {}
            send_data["data"]["q"] = q
            send_data["data"]["alpha"] = alpha
            send_data["data"]["Y_server"] = Y
            time.sleep(0.1)
            self.send_json_data(client_ip, client_port, send_data)
        elif j["topic"] == "shared_key":
            Y_client = j["data"]["Y_client"]
            print("Y_client is: ", Y_client)
            mutual_shared_key = (Y_client ** X) % q
            print("Mutual Key is: ",mutual_shared_key)
            c_data = {}
            c_data["ip"] = j["ip"]
            c_data["port"] = j["port"]
            c_data["mutual_shared_key"] = mutual_shared_key
            clients_data.append(c_data)
        elif j["topic"] == "LOGINCREATE":
            encoding_copy = None
            for client in clients_data:
                if client["ip"] == j["ip"] and client["port"] == j["port"]:
                    shared_key = client["mutual_shared_key"]
                    encoding_copy = new_encoding(shared_key)
                    break
            encoded_id = j["data"]["id"]
            encoded_password = j["data"]["password"]
            encoded_q = j["data"]["q"]
            decrypt_id = decrypt(encoded_id, encoding_copy)
            decrypt_password = decrypt(encoded_password, encoding_copy)
            decrypt_q = int(decrypt(encoded_q, encoding_copy))
            salt = random.randint(1,decrypt_q)
            combined_pass = decrypt_password+str(salt)+str(decrypt_q)
            hashed_password = hashlib.sha224(combined_pass.encode()).hexdigest()
            user = [decrypt_id, salt, hashed_password, decrypt_q, False]
            id_found = False
            for entry in password_file:
                if entry[0] == decrypt_id:
                    id_found = True
                    break
            if id_found:
                reply_msg = {}
                reply_msg["topic"] = "LOGINREPLY"
                reply_msg["description"] = "Entry already found"
            else:
                password_file.append(user)
                reply_msg = {}
                reply_msg["topic"] = "LOGINREPLY"
                reply_msg["description"] = "Successfully logged in"
            self.send_json_data(j["ip"], j["port"], reply_msg)
        elif j["topic"] == "AUTHREQUEST":
            encoding_copy = None
            for client in clients_data:
                if client["ip"] == j["ip"] and client["port"] == j["port"]:
                    shared_key = client["mutual_shared_key"]
                    encoding_copy = new_encoding(shared_key)
                    break
            encoded_id = j["data"]["id"]
            encoded_password = j["data"]["password"]
            decrypt_id = decrypt(encoded_id, encoding_copy)
            decrypt_password = decrypt(encoded_password, encoding_copy)
            authenticated = False
            for i in range(len(password_file)):
                entry = password_file[i]
                if entry[0] == decrypt_id:
                    salt_val = entry[1]
                    q_val = entry[3]
                    stored_pass = entry[2]
                    combined_pass = decrypt_password+str(salt_val)+str(q_val)
                    hashed_password = hashlib.sha224(combined_pass.encode()).hexdigest()
                    if hashed_password == stored_pass:
                        password_file[i][4] = True
                        authenticated = True
                    break
            if authenticated:
                reply_msg = {}
                reply_msg["topic"] = "AUTHREPLY"
                reply_msg["description"] = "Authentication successful"
            else:
                reply_msg = {}
                reply_msg["topic"] = "AUTHREPLY"
                reply_msg["description"] = "Error in authentication"
            self.send_json_data(j["ip"], j["port"], reply_msg)
        elif j["topic"] == "SERVICEREQUEST":
            encoding_copy = None
            for client in clients_data:
                if client["ip"] == j["ip"] and client["port"] == j["port"]:
                    shared_key = client["mutual_shared_key"]
                    encoding_copy = new_encoding(shared_key)
                    break
            user_id = decrypt(j["data"]["id"], encoding_copy)
            filename = decrypt(j["data"]["filename"], encoding_copy)
            entry_found = False
            for entry in password_file:
                if entry[0] == user_id:
                    entry_found = True
                    if entry[4] == False:
                        reply_msg = {}
                        reply_msg["topic"] = "SERVICEDONE"
                        reply_msg["description"] = "You are not allowed to use any services, first authenticate then retry"
                        self.send_json_data(j["ip"], j["port"], reply_msg)
                    else:
                        try:
                            file = open(filename, "rb")
                            file_data = file.read()
                            reply_msg = {}
                            reply_msg["topic"] = "SERVICEDONE"
                            reply_msg["description"] = "File read successfully, about to send data"
                            self.send_json_data(j["ip"], j["port"], reply_msg)
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.connect((j["ip"], j["port"]))
                            s.sendall(file_data)
                        except FileNotFoundError:
                            reply_msg = {}
                            reply_msg["topic"] = "SERVICEDONE"
                            reply_msg["description"] = "No such file found in the server"
                            self.send_json_data(j["ip"], j["port"], reply_msg)
                    break

            if entry_found == False:
                reply_msg = {}
                reply_msg["topic"] = "SERVICEDONE"
                reply_msg["description"] = "No entry which such id found on the server"
                self.send_json_data(j["ip"], j["port"], reply_msg)

        #except:
        #    print("Error in parsing data: ",data)


self_ip = "10.2.138.136"
self_port = 12008
tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcpsock.bind((self_ip, self_port))

while True:
    tcpsock.listen(1000)
    (conn, (ip,port)) = tcpsock.accept()
    listenthread = ListenClients(conn, self_ip, self_port)
    listenthread.daemon = True
    listenthread.start()
