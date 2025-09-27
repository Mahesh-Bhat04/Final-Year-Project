from tkinter import *
from CPABSC_Hybrid_R import *
import os
from flask import Flask, jsonify, request
from uuid import uuid4
import threading
import hashlib
import base64
import subprocess
import urllib.parse
from pathlib import Path
from charm.core.engine.util import objectToBytes, bytesToObject
import json

# Optional MQTT support
try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except Exception:
    MQTT_AVAILABLE = False

app = Flask(__name__)

groupObj = PairingGroup('SS512')
cpabe = CPabe_BSW07(groupObj)
hyb_abe = HybridABEnc(cpabe, groupObj)

# Initialize keys at startup
def initialize_keys():
    """Initialize or load cryptographic keys"""
    global pk, msk, sk, k_sign
    
    pkpath = Path("pk.txt")
    mskpath = Path("msk.txt")
    skpath = Path("sk.txt")
    k_signpath = Path("k_sign.txt")
    
    # Check if all key files exist
    if pkpath.is_file() and skpath.is_file():
        print("Loading existing keys...")
        
        # Load pk
        with open("pk.txt", 'r') as f:
            pk_str = f.read()
            pk_bytes = pk_str.encode("utf8")
            pk = bytesToObject(pk_bytes, groupObj)
        
        # Load sk
        with open("sk.txt", 'r') as f:
            sk_str = f.read()
            sk_bytes = sk_str.encode("utf8")
            sk = bytesToObject(sk_bytes, groupObj)
        
        # Load k_sign if exists
        if k_signpath.is_file():
            with open("k_sign.txt", 'r') as f:
                k_sign_str = f.read()
                k_sign_bytes = k_sign_str.encode("utf8")
                k_sign = bytesToObject(k_sign_bytes, groupObj)
        else:
            k_sign = None
            
        # Load msk if exists (might not be needed on RPi)
        if mskpath.is_file():
            with open("msk.txt", 'r') as f:
                msk_str = f.read()
                msk_bytes = msk_str.encode("utf8")
                msk = bytesToObject(msk_bytes, groupObj)
        else:
            msk = None
            
        print("Keys loaded successfully")
    else:
        print("Warning: Key files not found. RPi will wait to receive keys from PC node.")
        print("Make sure to register this RPi with a PC node to receive keys.")
        pk = None
        sk = None
        k_sign = None
        msk = None

def start_listening():
    initialize_keys()
    app.app_context()
    app.run(host='0.0.0.0', port=5001)

# MQTT configuration (overridable via env)
MQTT_BROKER = os.environ.get('MQTT_BROKER', 'localhost')
MQTT_PORT = int(os.environ.get('MQTT_PORT', '1883'))

def read_epoch_file():
    try:
        if os.path.exists('epoch.txt'):
            return int(open('epoch.txt').read().strip())
    except Exception:
        pass
    return 1

def process_update(values):
    """Common processing for updates received via HTTP or MQTT."""
    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']
    if not all(k in values for k in required):
        print("Missing values in update payload")
        return False

    try:
        print("Writing file as ct")
        with open("ct", 'w') as ct_write:
            ct_write.write(values['ct'])
        print("Writing file as pk.txt")
        with open("pk.txt", 'w') as pk_write:
            pk_write.write(values['pk'])
    except Exception as e:
        print(f"ERROR writing ct/pk files: {e}")
        return False

    name = values['name']
    file = values['file']
    pi = values['pi']
    msg_epoch = int(values.get('epoch', read_epoch_file()))

    try:
        ct = bytesToObject(values['ct'].encode('utf8'), groupObj)
        pk_local = bytesToObject(values['pk'].encode('utf8'), groupObj)
    except Exception as e:
        print(f"ERROR decoding ct/pk: {e}")
        return False

    # Load epoch-specific secret key if available; fallback to default
    sk_path_epoch = f"sk_{msg_epoch}.txt"
    try:
        if os.path.exists(sk_path_epoch):
            with open(sk_path_epoch, 'r') as skf:
                sk_epoch = bytesToObject(skf.read().encode('utf8'), groupObj)
        else:
            if not os.path.exists("sk.txt"):
                print("ERROR - Secret key not found (sk.txt / sk_<epoch>.txt)")
                return False
            with open("sk.txt", 'r') as skf:
                sk_epoch = bytesToObject(skf.read().encode('utf8'), groupObj)
    except Exception as e:
        print(f"ERROR loading epoch secret key: {e}")
        return False

    # Enforce epoch acceptance window (current or previous)
    current_epoch = read_epoch_file()
    acceptable_epochs = {current_epoch, max(1, current_epoch - 1)}
    if msg_epoch not in acceptable_epochs:
        print(f"Rejected message due to epoch mismatch. msg_epoch={msg_epoch} current={current_epoch}")
        return False

    print("INFO - Received message (HTTP/MQTT)...")
    return install_sw(name, ct, pk_local, sk_epoch, pi, file)

def start_mqtt(node_id):
    if not MQTT_AVAILABLE:
        print("MQTT not available (paho-mqtt not installed). Skipping MQTT listener.")
        return

    topics = [("updates/all", 0), (f"updates/{node_id}", 0)]

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"MQTT connected to {MQTT_BROKER}:{MQTT_PORT}")
            for t, qos in topics:
                client.subscribe(t, qos)
                print(f"Subscribed to MQTT topic: {t}")
        else:
            print(f"MQTT connection failed with code {rc}")

    def on_message(client, userdata, msg):
        try:
            payload = msg.payload.decode('utf-8')
            values = json.loads(payload)
            print(f"MQTT message on {msg.topic}")
            ok = process_update(values)
            print("MQTT update processed" if ok else "MQTT update failed")
        except Exception as e:
            print(f"ERROR processing MQTT message: {e}")

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
    except Exception as e:
        print(f"MQTT connect error: {e}")
        return
    client.loop_start()

@app.route('/ping', methods=['GET'])
def transactions():
    response = {
        'message': "PONG!",
    }
    return jsonify(response), 200

@app.route('/keys/receive', methods=['POST'])
def receive_keys():
    """Receive cryptographic keys from PC node"""
    global pk, sk, k_sign, msk
    
    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values
    
    required = ['pk', 'sk']  # Minimum required keys
    if not all(k in values for k in required):
        return jsonify({'error': 'Missing required keys'}), 400
    
    try:
        # Save epoch if provided
        old_epoch = read_epoch_file()
        epoch = int(values.get('epoch', old_epoch))
        with open('epoch.txt', 'w') as ef:
            ef.write(str(epoch))
        if epoch != old_epoch:
            print(f"Epoch updated on RPi: {old_epoch} -> {epoch}")
        else:
            print(f"Epoch confirmed on RPi: {epoch}")

        # Save and load pk (current) and versioned
        with open("pk.txt", 'w') as f:
            f.write(values['pk'])
        with open(f"pk_{epoch}.txt", 'w') as fpkv:
            fpkv.write(values['pk'])
        pk_bytes = values['pk'].encode("utf8")
        pk = bytesToObject(pk_bytes, groupObj)
        
        # Save and load sk (current) and versioned
        with open("sk.txt", 'w') as f:
            f.write(values['sk'])
        with open(f"sk_{epoch}.txt", 'w') as fskv:
            fskv.write(values['sk'])
        sk_bytes = values['sk'].encode("utf8")
        sk = bytesToObject(sk_bytes, groupObj)
        
        # Save k_sign if provided
        if 'k_sign' in values:
            with open("k_sign.txt", 'w') as f:
                f.write(values['k_sign'])
            with open(f"k_sign_{epoch}.txt", 'w') as fksv:
                fksv.write(values['k_sign'])
            k_sign_bytes = values['k_sign'].encode("utf8")
            k_sign = bytesToObject(k_sign_bytes, groupObj)
        
        # Save msk if provided (usually not needed on RPi)
        if 'msk' in values:
            with open("msk.txt", 'w') as f:
                f.write(values['msk'])
            msk_bytes = values['msk'].encode("utf8")
            msk = bytesToObject(msk_bytes, groupObj)
        
        print("Successfully received and saved keys from PC node")
        
        # Update UI if available
        try:
            text_keygen_time.set("Keys received from PC node")
        except:
            pass
            
        return jsonify({'message': 'Keys received successfully'}), 200
        
    except Exception as e:
        print(f"Error receiving keys: {e}")
        return jsonify({'error': str(e)}), 500

def install_sw(name, ct, pk, sk, pi, file):
    (file_pr_, delta_pr) = hyb_abe.decrypt(pk, sk, ct)
    file_pr = base64.b64decode(file_pr_).decode('ascii')

    print("Writing Received Message: " + str(name))
    cur_directory = os.getcwd()
    file_path = os.path.join(cur_directory, name)
    open(file_path, 'w').write(file_pr)

    delta_bytes = objectToBytes(delta_pr, groupObj)
    pi_pr = hashlib.sha256(bytes(str(file), 'utf-8')).hexdigest() + hashlib.sha256(delta_bytes).hexdigest()

    print('-----------------------------------------------------------------------------------')

    if pi == pi_pr:

        print('Successfully Verified!')

        if os.name == "posix":
            os.chmod(file_path, 0o777)
        try:
            print("Running Files....")
            subprocess.call(file_path)
            print("The message has been reached!")
            print('-----------------------------------------------------------------------------------')
            return True

        except OSError as e:
            print("ERROR - The file is not a valid application: " + str(e))
            print('-----------------------------------------------------------------------------------')
            return False

    else:

        print('Verification Failed.. !!')
        print('-----------------------------------------------------------------------------------')
        return False


@app.route('/updates/new', methods=['POST'])
def post_updates_new():
    global pk, sk  # Use global keys if available
    
    # Try to get JSON data first, fall back to form/URL parameters
    values = request.get_json(silent=True)
    if values is None:
        values = request.values

    required = ['name', 'file', 'file_hash', 'ct', 'pi', 'pk']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # write ct
    print("Writing file as ct")
    ct_write = open("ct", 'w')
    ct_write.write(values['ct'])
    ct_write.close()

    # write pk
    print("Writing file as pk.txt")
    pk_write = open("pk.txt", 'w')
    pk_write.write(values['pk'])
    pk_write.close()

    name = values['name']
    file = values['file']
    file_hash = values['file_hash']
    pi = values['pi']

    ct_str = values['ct']
    ct_bytes = ct_str.encode("utf8")
    ct = bytesToObject(ct_bytes, groupObj)

    pk_str = values['pk']
    pk_bytes = pk_str.encode("utf8")
    pk = bytesToObject(pk_bytes, groupObj)

    # Check if sk exists, either from initialization or needs to be loaded
    if sk is None:
        if not os.path.exists("sk.txt"):
            print("ERROR - Secret key (sk.txt) not found!")
            print("Please ensure this RPi has received keys from a PC node.")
            return 'Secret key not found - RPi needs keys from PC node', 500
        
        print("Reading sk from saved file")
        sk_read = open("sk.txt", 'r')
        sk_str = sk_read.read()
        sk_bytes = sk_str.encode("utf8")
        sk = bytesToObject(sk_bytes, groupObj)
        sk_read.close()
    
    print("INFO - Received message...")
    if install_sw(name, ct, pk, sk, pi, file):
        return 'File reached!', 200
    else:
        return 'Failed!', 400

def _line(line):
    if line == 1:
        return 10
    else:
        return 10 + 30*(line-1)

def _column(col):
    if col == 1:
        return 10
    else:
        return 10 + 120*(col-1)

node_identifier = str(uuid4()).replace('-', '')

main_window = Tk()
main_window.title("Blockchain Based Message Dissemination - Smart Device Window")
main_window.geometry("600x250")
text_keygen_time = StringVar()
label_keygen_time = Label(main_window, text="Integrity Checking:").place(x=_column(1), y=_line(1))
entry_keygen_time = Entry(main_window, textvariable=text_keygen_time).place(x=_column(3)-35, y=_line(1))

listening_thread = threading.Thread(name="listening", target=start_listening, daemon=True)
listening_thread.start()
if MQTT_AVAILABLE:
    mqtt_thread = threading.Thread(name="mqtt", target=lambda: start_mqtt(node_identifier), daemon=True)
    mqtt_thread.start()
mainloop()