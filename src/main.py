import ure as re
import ulogging as logging
import ujson
import sys
import os
import utime
import network
import ubinascii
from src.microdot import Microdot, redirect, send_file, Response
from machine import Pin, Timer
import mpyaes
import ubinascii

CREDS_FILE = '/data/creds.dat'
SSID_FILE = '/data/ssid.dat'
MASTER_FILE = '/data/master.dat'
ENCRYPT_FILE = '/data/encrypt.dat'
INIT_MASTER_PASS = '12345678'
INIT_SSID_PASS   = '12345678'


#-------------------------------------------
# program data
#-------------------------------------------
passwords = {}
activity = False
loggedin = False
led = Pin(13, Pin.OUT)
sleep_time = 100
enckey = ''
enciv = ''
enckey_set = False

#-------------------------------------------------
# This needs to be defined before http handlers
#-------------------------------------------------
app = Microdot()


#-------------------------------------------
# program functions
#-------------------------------------------
def get_byte_array(str):
    if len(str) < 16:
        a = len(str)
        for i in range(a, 16):
            str += ' '          
    elif len(str) > 16:
        str = str[:16]
    barray = bytearray(str)
    return barray
    
def encrypt_text(passw, text):
    key = get_byte_array(passw) 
    aes = mpyaes.new(key, mpyaes.MODE_CBC, enciv)
    barray = aes.encrypt(text)              # mpyaes.AES.encrypt([bytes, str]) returns a bytearray
    return barray

def decrypt_bytes(passw, barray):
    key = get_byte_array(passw) 
    aes = mpyaes.new(key, mpyaes.MODE_CBC, enciv)
    try:
        barr = aes.decrypt(barray)     
        text = barr.decode()         
    except:
        text = "ERROR"
    return text

def encrypt_and_encode(passw, text):
    barray = encrypt_text(passw, text)
    encoded = ubinascii.b2a_base64(bytes(barray))
    return encoded[:-1]

def decode_and_decrypt(enckey, text):
    decoded = ubinascii.a2b_base64(text)
    barray = bytearray(decoded)
    return decrypt_bytes(enckey, barray)

def encrypt_text2file(passw, text, file):
    barray = encrypt_text(passw, text)              
    with open(file, 'wb') as f:
        f.write(barray)

def decrypt_file2text(passw, file):
    with open(file, 'rb') as f:
        barray = bytearray(f.read())
    text = decrypt_bytes(passw, barray)    
    return text

def read_data(filename):
    with open(filename, 'r') as f:
        str = f.read()
    return ujson.loads(str)
    
def save_data(filename, data):
    with open(filename, 'w') as f:
        f.write(data)

def on_led_timer(timer):                # we will receive the timer object when being called
    if activity == True:
       led.toggle()      

def toggle_led(count):
    for x in range(count):
        led.toggle()
        utime.sleep_ms(sleep_time)
    led.off()
    
def file_exists(filename):
    try:
        os.stat(filename)
        return True
    except OSError:
        return False
    
def init():
    global enckey
    global enciv
    global enckey_set
    json = read_data(ENCRYPT_FILE)
    enckey = ubinascii.a2b_base64(json['encryption']['enckey'])
    enciv = ubinascii.a2b_base64(json['encryption']['iv'])
    enckey_set = json['encryption']['set']

    if not file_exists(MASTER_FILE):
        master_dict = {"username" : "admin", "password" : INIT_MASTER_PASS}
        text = ujson.dumps({"master" : master_dict})
        encrypt_text2file(INIT_MASTER_PASS, text, MASTER_FILE)
        
    if not file_exists(SSID_FILE):
        ssid_json = {"ap_name" : "BlueRiverAP", "ap_password" : INIT_SSID_PASS, "hint" : "not yet set, please change" }
        save_data( SSID_FILE, ujson.dumps({"accesspoint" : ssid_json}) )
    
    if not file_exists(CREDS_FILE):
        text = ujson.dumps({"records" : [] })
        encrypt_text2file(INIT_MASTER_PASS, text, CREDS_FILE)

def prep_error(status):
    user = {'status' : status}
    return ujson.dumps({'user' : user})
    
def get_rec_hash(json):
    curarr = json['records']
    hash = {}
    for rec in curarr: 
        for key in rec:
            hash[key] = rec[key]
    return hash

def logged_in_elsewhere(req):
    host_addr, port = req.client_addr
    if host_addr != IP_ADDRESS:
        return True, 'Not allowed to login from multiple devices at the same time.'
    else:
        return False, ''

def get_login():
    json = read_data(SSID_FILE)
    resp = send_file('static/views/login.html')
    resp.set_cookie('hintText', json['accesspoint']['hint'])
    return resp

#-------------------------------------------
# HTTP request handlers
#-------------------------------------------
'''
@app.route("/setenckey", methods=['POST'])
def index(req):
    # here take the steps to save the encryption key
    global enckey
    enckey = ubinascii.a2b_base64(bytes(req.body))
    encoded_iv = ubinascii.b2a_base64(bytes(IV))
    encoded_iv = encoded_iv[:-1]
    status = 'success'
    user = {'status' : status}
    keys = {'user':user}
    return ujson.dumps(keys)

@app.route("/test")
def test(req):
    enckey = '12345678'
    barray = get_byte_array(enckey)
    global IV
    text = encrypt_text(enckey, 'this is my text')
    encodediv = ubinascii.b2a_base64(bytes(IV))
    encodedtxt = ubinascii.b2a_base64(bytes(text))
    enckey64 = ubinascii.b2a_base64(bytes(barray))
    keys = {'key':enckey64, 'ivtext':encodediv, 'text':encodedtxt}
    return ujson.dumps(keys) 
'''

@app.route("/listkey")
def listkey(req):
    json = read_data(ENCRYPT_FILE)
    status = 'success'

    # now set all json vars
    data = {'status' : status, 'enckey': enckey, 'enciv':enciv, 'set':enckey_set, 
            'enckey_file':json['encryption']['enckey'],
            'iv_file':json['encryption']['iv']
           }
    retdata = {'data':data}
    return ujson.dumps(retdata)

@app.route("/")
def index(req):
    if not enckey_set:
        return send_file('static/views/initial.html')

    if loggedin:
        return send_file('static/views/index.html')

    return get_login()

@app.route("/setenckey")
def setenckey(req):
    global enckey_set
    enckey_set = True
    jsonw = read_data(ENCRYPT_FILE)
    jsonw['encryption']['set'] = True
    save_data( ENCRYPT_FILE, ujson.dumps(jsonw) )
    user = {'status' : 'success'}
    keys = {'user':user}
    return ujson.dumps(keys)

@app.route("/login", methods=['GET', 'POST'])
def login(req):
    global loggedin
    global MASTER_USER
    global MASTER_PASSWORD
    global IP_ADDRESS

    if loggedin:
        return send_file('static/views/index.html')
    
    if req.method == "GET":
        return get_login()
    
    bodytext = decode_and_decrypt(enckey, req.body)
    json_body = ujson.loads(bodytext)
    userx = json_body['login']['username']
    passwx = json_body['login']['password']
    text = decrypt_file2text(passwx, MASTER_FILE)

    if text == 'ERROR':
        user = {'status' : 'error'}
        keys = {'user':user}
        return ujson.dumps(keys)

    json = ujson.loads(text)

    if userx != json['master']['username'] or passwx != json['master']['password']:
        user = {'status' : 'error'}
        keys = {'user':user}
        return ujson.dumps(keys)
        
    loggedin = True
    MASTER_USER = json['master']['username']
    MASTER_PASSWORD = json['master']['password']
    IP_ADDRESS, port = req.client_addr
    user = {'status' : 'success'}
    keys = {'user':user}
    return ujson.dumps(keys)

'''
@app.route("/login", methods=['GET', 'POST'])
def login(req):
    global loggedin
    global MASTER_USER
    global MASTER_PASSWORD
    global IP_ADDRESS

    if loggedin:
        return send_file('static/views/index.html')
    
    if req.method == "GET":
        return send_file('static/views/login.html')
    
#    json_body = decode_and_decrypt(req.body)
#    user = json_body['login']['username']
#    passw = json_body['login']['password']
    userx = 'admin'
    passwx = '12345678'
    text = decrypt_file2text(passwx, MASTER_FILE)

    if text == 'ERROR':
        return send_file('static/views/login.html')

    json = ujson.loads(text)

    if userx != json['master']['username'] or passwx != json['master']['password']:
        return send_file('static/views/login.html')
        
    loggedin = True
    MASTER_USER = json['master']['username']
    MASTER_PASSWORD = json['master']['password']
    IP_ADDRESS, port = req.client_addr
    user = {'status' : 'success'}
    keys = {'user':user}
    return ujson.dumps(keys)
'''


@app.route("/getkeys")
def get_keys(req):
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    text = decrypt_file2text(MASTER_PASSWORD, CREDS_FILE) 
    if text == 'ERROR':
        return prep_error('error')

    json = ujson.loads(text)
    rechash = get_rec_hash(json)
    alist = []
    sortedpass = sorted(rechash.items())
    for key, value in sortedpass:
        alist.append(encrypt_and_encode(enckey, key))
    user = {'status' : 'loggedin'}
    keys = {'user':user, 'keys':alist}
    return ujson.dumps(keys)

@app.route("/delkey", methods=['POST'])
def del_key(req):
    if not loggedin:
        return prep_error('loggedout')

    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    key = decode_and_decrypt(enckey, req.body)

    # create the array of hashes        
    text = decrypt_file2text(MASTER_PASSWORD, CREDS_FILE)
    if text == 'ERROR':
        return prep_error('error')

    json = ujson.loads(text)
    curarr = json['records']

    # traverse that array and delete item when key is found
    ind = 0
    for rec in curarr:
        for arrkey in rec:
            if arrkey == key:
                del curarr[ind]
                newtext = ujson.dumps( {"records" : curarr} )
                encrypt_text2file(MASTER_PASSWORD, newtext, CREDS_FILE)
                break
            ind += 1 

    user = {'status' : 'success'}
    return ujson.dumps({'user' : user})
    
@app.route("/getvalues")
def get_key_values(req):
    if not loggedin:
        return prep_error('loggedout')

    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    text = decrypt_file2text(MASTER_PASSWORD, CREDS_FILE) 
    if text == 'ERROR':
        return prep_error('error')

    json = ujson.loads(text)
    arr = json['records']
    keyarr = []
    hash = {}

    for rec in arr:
        for key in rec:
            hash[key] = rec[key]
            keyarr.append(key)

    sortedkeys = sorted(keyarr)
    alist = []
    for key in sortedkeys:
        enc_key = encrypt_and_encode(enckey, key)
        enc_value = encrypt_and_encode(enckey, hash[key])
        alist.append( {'key':enc_key, 'value':enc_value} )
    user = {'status' : 'loggedin'}
    bdict = {'user':user, 'pairs':alist}
    return ujson.dumps(bdict)

@app.route("/savevalues", methods=['POST'])
def save_key_values(req):
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg
    
    curtext = decrypt_file2text(MASTER_PASSWORD, CREDS_FILE)
    json = ujson.loads(curtext)
    curarr = json['records']

    # create a hash to eliminate duplication of keys
    curhash = {}
    for rec in curarr: 
        for key in rec:
            curhash[key] = rec[key]

    # decrypt payload
    bodytext = decode_and_decrypt(enckey, req.body)
    json_body = ujson.loads(bodytext)

    # add the new passwords to the hash
    for rec in json_body['pairs']: 
        k = rec['key']
        v = rec['value']
        curhash[k] = v
        
    # create an array of hashes    
    objarr = []    
    for key, value in curhash.items():
        objarr.append( {key : value} )

    newtext = ujson.dumps( {"records" : objarr} )
    encrypt_text2file(MASTER_PASSWORD, newtext, CREDS_FILE)

    user = {'status' : 'success'}
    return ujson.dumps({'user' : user})

@app.route("/changepass", methods=['GET'])
def change_pass_get(req):
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    return send_file('static/views/chgpass.html')
        
# change master password
@app.route("/chgpass", methods=['POST'])
def change_pass(req):
    global loggedin
    global MASTER_PASSWORD
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    # decrypt payload
    bodytext = decode_and_decrypt(enckey, req.body)
    jsdata = ujson.loads(bodytext)

    if jsdata['password']['current'] !=  MASTER_PASSWORD:
        user = {'status' : 'error'}
        return ujson.dumps({'user' : user})
        
    # regenerate SSID file
    json = read_data(SSID_FILE)
    json['accesspoint']['hint'] = jsdata['password']['hint']
    save_data( SSID_FILE, ujson.dumps(json) )

    # regenerate master file    
    master_dict = {"username" : MASTER_USER, "password" : jsdata['password']['new']}
    text = ujson.dumps({"master" : master_dict})
    encrypt_text2file( jsdata['password']['new'], text, MASTER_FILE )

    # regenerate passwords file
    text = decrypt_file2text(MASTER_PASSWORD, CREDS_FILE)
    encrypt_text2file(jsdata['password']['new'], text, CREDS_FILE) 

    MASTER_PASSWORD = jsdata['password']['new']
    loggedin = False
    user = {'status' : 'success'}
    return ujson.dumps({'user' : user})


# change master password hint
@app.route("/chghint", methods=['POST'])
def change_pass(req):
    global loggedin
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    # decrypt payload
    bodytext = decode_and_decrypt(enckey, req.body)
    jsdata = ujson.loads(bodytext)

    if jsdata['password']['current'] !=  MASTER_PASSWORD:
        user = {'status' : 'error'}
        return ujson.dumps({'user' : user})

    # read SSID file
    json = read_data(SSID_FILE)

    # regenerate SSID file
    json['accesspoint']['hint'] = jsdata['password']['hint']
    save_data( SSID_FILE, ujson.dumps(json) )

    # prepare return
    user = {'status' : 'success'}
    return ujson.dumps({'user' : user})

# change SSID password
@app.route("/chgssidpass", methods=['POST'])
def change_ssid_pass(req):
    global AP_PASSWORD
    if not loggedin:
        return prep_error('loggedout')
        
    error, msg = logged_in_elsewhere(req)
    if error:
        return msg

    # decrypt payload
    bodytext = decode_and_decrypt(enckey, req.body)
    jsdata = ujson.loads(bodytext)

    if jsdata['password']['current'] !=  AP_PASSWORD:
        user = {'status' : 'error'}
        return ujson.dumps({'user' : user})
        
    json = {"ap_name" : jsdata['password']['newSSID'], "ap_password" : jsdata['password']['new'] }
    save_data( SSID_FILE, ujson.dumps({"accesspoint" : json}) )
    AP_PASSWORD = jsdata['password']['new']
    user = {'status' : 'success'}
    return ujson.dumps({'user' : user})

@app.route("/logout")
def logout(req):
    global loggedin
    loggedin = False
    return send_file('static/views/logout.html')
   
@app.get("/static/styles/<file>")
def get_style(request, file):
    return send_file('static/styles/' + file)

@app.get('/static/img/<img>')
def get_image(request, img):
    return send_file('static/img/' + img)
                
@app.get("/static/js/<file>")
def get_script(request, file):
    return send_file('static/js/' + file)

# this will create the files if not found
init()

#-------------------------------------------
# set the Access Point SSID and password
#-------------------------------------------
ap_json = read_data(SSID_FILE)
AP_NAME = ap_json['accesspoint']['ap_name']
AP_PASSWORD = ap_json['accesspoint']['ap_password']

#-------------------------------------------
# set the initial master password
#-------------------------------------------
MASTER_USER = ''
MASTER_PASSWORD = ''
IP_ADDRESS = ''

# set access point
ap = network.WLAN(network.AP_IF)
ap.active(True)
ap.config(essid=AP_NAME, password=AP_PASSWORD, authmode=3)

# make the access point active
while ap.active() == False:
  pass

config_info = ap.ifconfig()
print(config_info)


app.run(host='0.0.0.0', port=80, debug=True)

