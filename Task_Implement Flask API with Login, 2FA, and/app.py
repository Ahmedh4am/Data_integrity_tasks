from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
import bcrypt
import pyotp
import qrcode
import jwt
import datetime
from functools import wraps
from io import BytesIO
import base64

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'data_integrity_db'
mysql = MySQL(app)

# JWT Secret Key
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret'

# ============================
#  Middleware - JWT Authentication
# ============================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith("Bearer "):
            return jsonify({'error': 'Token is missing or invalid'}), 401
        try:
            token = token.split(" ")[1]  # Extract token part
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated


# ============================
#  User Registration
# ============================
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate Google Authenticator Secret
    secret = pyotp.random_base32()

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", (username, hashed_pw, secret))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "User registered successfully!", "twofa_secret": secret})

# ============================
#  Generate 2FA QR Code
# ============================
from flask import send_file

@app.route('/generate_qr/<username>', methods=['GET'])
def generate_qr(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = user[0]
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskApp")

    qr = qrcode.make(otp_uri)
    
    # Save the QR code as a file
    qr_path = f"{username}_qr.png"
    qr.save(qr_path)

    return send_file(qr_path, as_attachment=True, download_name=f"{username}_qr.png", mimetype="image/png")

# ============================
#  User Login with 2FA
# ============================
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    user_id, hashed_pw, secret = user

    if not bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8')):
        return jsonify({"error": "Invalid username or password"}), 401

    return jsonify({"message": "Enter 2FA code", "user_id": user_id})

# ============================
#  Verify 2FA and Generate JWT
# ============================
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    user_id = data.get('user_id')
    code = data.get('code')

    if not user_id or not code:
        return jsonify({"error": "User ID and 2FA code required"}), 400

    cur = mysql.connection.cursor()
    cur.execute("SELECT twofa_secret FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = user[0]
    totp = pyotp.TOTP(secret)

    if not totp.verify(code):
        return jsonify({"error": "Invalid 2FA code"}), 401

    token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    return jsonify({"message": "Login successful!", "token": token})

# ============================
#  CRUD Operations (Protected)
# ============================
@app.route('/products', methods=['POST'])
@token_required
def create_product():
    data = request.json
    name, description, price, quantity = data.get('name'), data.get('description'), data.get('price'), data.get('quantity')

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", (name, description, price, quantity))
    mysql.connection.commit()
    cur.close()

    return jsonify({"message": "Product created successfully"})

@app.route('/products', methods=['GET'])
@token_required
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    cur.close()

    return jsonify({"products": [{"id": p[0], "name": p[1], "description": p[2], "price": str(p[3]), "quantity": p[4]} for p in products]})

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                (data.get('name'), data.get('description'), data.get('price'), data.get('quantity'), product_id))
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Product updated successfully"})

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Product deleted successfully"})

# ============================
#  Home Route & Favicon Fix
# ============================
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Flask API!"})

@app.route('/favicon.ico')
def favicon():
    return '', 204  # No content response

# ============================
#  Run the Flask App
# ============================
if __name__ == '__main__':
    app.run(debug=True)
