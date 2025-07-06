from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from Crypto.Cipher import AES
import base64
import qrcode
from PIL import Image
import cv2
import numpy as np
import os
import json
from datetime import datetime, timedelta
import io

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = 'super-secret-key'

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = {'admin': {'password': '1234'}}  

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

# --- Paths ---
QR_FOLDER = 'static/qr_codes'
os.makedirs(QR_FOLDER, exist_ok=True)

# --- AES Helpers ---

def pad_key(key):
    return key.ljust(32, '0')[:32]  # AES-256

def encrypt_AES_with_expiry(message: str, key: str, expiry_minutes: int) -> str:
    expiry_time = (datetime.now() + timedelta(minutes=expiry_minutes)).strftime('%Y-%m-%d %H:%M:%S')
    payload = json.dumps({"msg": message, "exp": expiry_time})
    key = pad_key(key).encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(payload.encode())
    # Concatenate nonce, tag, and ciphertext for storage/transmission
    encrypted = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    return encrypted

def decrypt_AES_with_expiry(encrypted_message: str, key: str) -> str:
    key = pad_key(key).encode()
    data = base64.b64decode(encrypted_message)
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    payload = decrypted.decode('utf-8')
    data = json.loads(payload)

    msg = data.get("msg")
    exp = data.get("exp")
    if datetime.now() > datetime.strptime(exp, '%Y-%m-%d %H:%M:%S'):
        raise ValueError("EXPIRED")
    return msg

# --- QR Functions ---

def generate_qr_code(data):
    qr = qrcode.QRCode(version=2, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color='black', back_color='white').convert('RGB')

def embed_qr_in_qr(dummy_qr_img, real_qr_img):
    dummy_gray = np.array(dummy_qr_img.convert('L'))
    real_gray = np.array(real_qr_img.convert('L'))
    real_resized = cv2.resize(real_gray, (dummy_gray.shape[1], dummy_gray.shape[0]))
    embedded = (dummy_gray & 0xFC) | ((real_resized >> 6) & 0x03)
    return cv2.cvtColor(embedded, cv2.COLOR_GRAY2BGR)

# --- Routes ---

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            login_user(User(username))
            return redirect(url_for('index'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    message = ''
    if request.method == 'POST':
        real_message = request.form['message']
        fake_message = request.form['fake_message']
        key = request.form['key']
        expiry_minutes = int(request.form.get('expiry_minutes', 5))

        encrypted_message = encrypt_AES_with_expiry(real_message, key, expiry_minutes)

        real_qr_img = generate_qr_code(encrypted_message)
        fake_qr_img = generate_qr_code(fake_message)
        embedded_qr = embed_qr_in_qr(fake_qr_img, real_qr_img)

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{timestamp}.png"
       
        buf = io.BytesIO()
        pil_img = Image.fromarray(cv2.cvtColor(embedded_qr, cv2.COLOR_BGR2RGB))
        pil_img.save(buf, format='PNG')
        buf.seek(0)

        return send_file(
            buf,
            mimetype='image/png',
            as_attachment=True,
            download_name=filename
        )

    return render_template('encrypt.html', message=message)

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    decrypted_message = ''
    uploaded_qr_path = ''
    extracted_qr_path = ''
    error = False
    color = 'black'

    if request.method == 'POST':
        qr_image = request.files['qr_image']
        key = request.form['key']

        filename = qr_image.filename
        uploaded_qr_path = os.path.join(QR_FOLDER, filename)
        qr_image.save(uploaded_qr_path)

        img = cv2.imread(uploaded_qr_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        extracted_bits = (gray & 0x03) << 6
        # extracted_bits = extracted_bits.astype(np.uint8)

        # extracted_qr_filename = 'extracted_qr.png'
        extracted_qr_path = None 
        # cv2.imwrite(extracted_qr_path, extracted_bits)

        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(extracted_bits)

        if data:
            try:
                decrypted_message = decrypt_AES_with_expiry(data, key)
                color = 'green'
                extracted_qr_filename = 'extracted_qr.png'
                extracted_qr_path = os.path.join(QR_FOLDER, extracted_qr_filename)
                cv2.imwrite(extracted_qr_path, extracted_bits)
            except ValueError as e:
                if str(e) == "EXPIRED":
                    decrypted_message = "QR Code has expired."
                else:
                    decrypted_message = "Invalid decryption key."
                error = True
                color = 'red'
        else:
            decrypted_message = "Could not decode QR Code."
            error = True
            color = 'red'


    return render_template('decrypt.html',
                           decrypted_message=decrypted_message,
                           uploaded_qr=os.path.basename(uploaded_qr_path) if uploaded_qr_path else None,
                           extracted_qr=os.path.basename(extracted_qr_path) if extracted_qr_path else None,
                           error=error,
                           color=color)

# --- Main ---
if __name__ == '__main__':
    app.run(debug=True)
