from functools import wraps
from flask_cors import CORS

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime, json, plotly.graph_objs as go, plotly
import time

from models import db, TransactionModel, User, BlockModel, PendingTransferModel, BatchModel
from blockchain import Blockchain


app = Flask(__name__)

CORS(app, origins=["http://localhost:5173"])

# Configs
app.config["JWT_SECRET_KEY"] = "supersecretkey123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///supplychain.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=1)

# Init DB & JWT
db.init_app(app)
jwt = JWTManager(app)

# Blockchain Instance
with app.app_context():
    db.create_all()
    blockchain = Blockchain()

def role_required(allowed_roles):
    def decorator(func):
        @wraps(func)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role")
            if role not in allowed_roles:
                return jsonify({"error": "Access denied for your role"}), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Routes
@app.route('/')
def home():
    return "Welcome to the Food Supply Chain Blockchain API!"

@app.route('/chain', methods=['GET'])
def get_chain():
    """Return the full blockchain"""
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'index': block.index,
            'timestamp': datetime.datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            'transactions': block.transactions,
            'previous_hash': block.previous_hash,
            'hash': block.hash
        })
    return jsonify({"length": len(chain_data), "chain": chain_data})

@app.route('/add_transaction', methods=['POST'])
@jwt_required()
def add_transaction():
    tx_data = request.get_json()
    required_fields = ["batch_id", "product", "owner", "location", "temperature", "humidity", "transport"]

    # Verify all fields
    for field in required_fields:
        if field not in tx_data:
            return "Missing field: " + field, 400

    # Get user info from JWT
    email = get_jwt_identity()        # only email
    claims = get_jwt()                # contains role
    role = claims.get("role")         # SAFE way to get role

    # Business logic for role control
    existing_batch = TransactionModel.query.filter_by(batch_id=tx_data['batch_id']).first()

    if not existing_batch:
        # No batch yet → must be created by Farmer
        if role != "Farmer":
            return jsonify({"error": f"Only Farmers can create new batch, but you are {role}"}), 403
    else:
        # Already exists → must be Distributor or Retailer
        if role not in ["Distributor", "Retailer"]:
            return jsonify({"error": f"Only Distributor/Retailer can transfer ownership, but you are {role}"}), 403

    # Save transaction
    tx_data['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    blockchain.add_block(tx_data)
    new_tx = TransactionModel(**tx_data)
    db.session.add(new_tx)
    db.session.commit()

    return jsonify({"message": "Transaction added successfully!", "role": role})


@app.route('/db_transactions/<batch_id>', methods=['GET'])
def db_transactions(batch_id):
    txs = TransactionModel.query.filter_by(batch_id=batch_id).all()
    if not txs:
        return jsonify({"message": "No transactions in DB for this batch"}), 404

    data = []
    for t in txs:
        data.append({
            "product": t.product,
            "owner": t.owner,
            "location": t.location,
            "temperature": t.temperature,
            "humidity": t.humidity,
            "transport": t.transport,
            "timestamp": t.timestamp
        })
    return jsonify({"batch_id": batch_id, "transactions": data})


@app.route('/product/<batch_id>', methods=['GET'])
def get_product_history(batch_id):
    """Return blockchain history for a given batch"""
    product_history = []
    for block in blockchain.chain:
        tx = block.transactions
        if isinstance(tx, dict) and tx.get('batch_id') == batch_id:
            product_history.append({
                'index': block.index,
                'timestamp': datetime.datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
                'transactions': tx,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            })

    if not product_history:
        return jsonify({"message": f"No transactions found for batch_id {batch_id}"}), 404

    return jsonify({"batch_id": batch_id, "history": product_history})

@app.route('/debug_chain', methods=['GET'])
def debug_chain():
    """Debug: dump full chain"""
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'index': block.index,
            'timestamp': datetime.datetime.fromtimestamp(block.timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            'transactions': block.transactions,
            'previous_hash': block.previous_hash,
            'hash': block.hash
        })
    return jsonify(chain_data)

# Visualization Routes
@app.route('/visualize/<batch_id>', methods=['GET'])
def visualize_batch(batch_id):
    """Return Plotly JSON for temperature & humidity trend"""
    times, temps, humids = [], [], []

    for block in blockchain.chain:
        tx = block.transactions
        if isinstance(tx, dict) and tx.get('batch_id') == batch_id:
            try:
                times.append(datetime.datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S"))
                temps.append(int(tx['temperature'].replace('°C','')))
                humids.append(int(tx['humidity'].replace('%','')))
            except:
                continue

    if not times:
        return jsonify({"message": f"No data to visualize for batch_id {batch_id}"}), 404

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=temps, mode='lines+markers', name='Temperature (°C)'))
    fig.add_trace(go.Scatter(x=times, y=humids, mode='lines+markers', name='Humidity (%)'))

    fig.update_layout(title=f"Temperature & Humidity Over Time for {batch_id}",
                      xaxis_title="Timestamp",
                      yaxis_title="Value",
                      legend_title="Metrics")

    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return Response(graphJSON, mimetype='application/json')

@app.route('/visualize_html/<batch_id>', methods=['GET'])
def visualize_batch_html(batch_id):
    """Render an interactive HTML chart for a batch"""
    import plotly.offline as pyo

    times, temps, humids = [], [], []
    for block in blockchain.chain:
        tx = block.transactions
        if isinstance(tx, dict) and tx.get('batch_id') == batch_id:
            try:
                times.append(datetime.datetime.strptime(tx['timestamp'], "%Y-%m-%d %H:%M:%S"))
                temps.append(int(tx['temperature'].replace('°C','')))
                humids.append(int(tx['humidity'].replace('%','')))
            except:
                continue

    if not times:
        return "No data to visualize", 404

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=temps, mode='lines+markers', name='Temperature (°C)'))
    fig.add_trace(go.Scatter(x=times, y=humids, mode='lines+markers', name='Humidity (%)'))

    fig.update_layout(title=f"Temp & Humidity Over Time for {batch_id}",
                      xaxis_title="Timestamp",
                      yaxis_title="Value",
                      legend_title="Metrics")

    return pyo.plot(fig, output_type='div')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    required = ["name", "role", "email", "password"]
    for f in required:
        if f not in data:
            return f"Missing {f}", 400

    if User.query.filter_by(email=data['email']).first():
        return "Email already registered", 400

    hashed_pw = generate_password_hash(data['password'], method='pbkdf2:sha256')

    role = data['role'].lower()
    new_user = User(
        name=data['name'],
        role=data['role'],
        email=data['email'],
        password=hashed_pw
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return "Invalid credentials", 401

    # Role is stored as custom claim
    access_token = create_access_token(
        identity=user.email,
        additional_claims={"role": user.role}
    )

    return jsonify({
        "message": "Login successful!",
        "access_token": access_token,
        "role": user.role,
        "name": user.name
    })


@app.route('/secure_test', methods=['GET'])
@jwt_required()
def secure_test():
    current_user_email = get_jwt_identity()  # main subject
    claims = get_jwt()
    user_role = claims["role"]  # extra claim we added
    return jsonify({"email": current_user_email, "role": user_role})


@app.route("/transfer_request", methods=["POST"])
@jwt_required()
def transfer_request():
    data = request.get_json()
    required = ["batch_id", "from", "to"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    claims = get_jwt()
    sender_role = claims["role"]
    sender_email = get_jwt_identity()

    # Validate current ownership
    history = blockchain.get_batch_history(data["batch_id"])
    if not history:
        # Only Farmer can create new batch
        if sender_role != "Farmer":
            return jsonify({"error": "Only Farmers can initiate first-time transfers"}), 403
    else:
        latest_owner = history[-1]["to"] if history[-1]["action"] == "ownership_accepted" else history[-1]["from"]
        if latest_owner != sender_email:
            return jsonify({"error": f"Only current owner '{latest_owner}' can initiate a transfer"}), 403
        if sender_role not in ["Distributor"]:
            return jsonify({"error": "Only Distributors can transfer after Farmers"}), 403

    # Create transfer request
    tx = blockchain.create_transfer_request(
        batch_id=data["batch_id"],
        sender=data["from"],
        receiver=data["to"]
    )
    return jsonify({"message": "Transfer request created", "transaction": tx})



@app.route("/accept_transfer", methods=["POST"])
@jwt_required()
def accept_transfer():
    data = request.get_json()
    required = ["batch_id", "receiver", "conditions"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    claims = get_jwt()
    receiver_role = claims["role"]
    receiver_email = get_jwt_identity()

    if data["receiver"] != receiver_email:
        return jsonify({"error": "You are not the intended receiver for this transfer"}), 403

    # Allow both Distributors and Retailers to accept
    if receiver_role not in ["Distributor", "Retailer"]:
        return jsonify({"error": f"{receiver_role}s are not allowed to accept ownership"}), 403

    tx = blockchain.accept_transfer(
        batch_id=data["batch_id"],
        receiver=data["receiver"],
        conditions=data["conditions"]
    )
    if tx:
        return jsonify({"message": "Transfer accepted", "transaction": tx})
    return jsonify({"error": "No pending transfer found for this batch"}), 404


@app.route("/reject_transfer", methods=["POST"])
@jwt_required()
def reject_transfer():
    data = request.get_json()
    batch_id = data.get("batch_id")
    receiver = get_jwt_identity()

    pending = PendingTransferModel.query.filter_by(
        batch_id=batch_id, receiver=receiver, status="pending"
    ).first()
    if not pending:
        return jsonify({"error": "No pending transfer found"}), 404

    # Mark as rejected
    pending.status = "rejected"
    db.session.commit()

    # Update batch status
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    if batch:
        batch.status = "Rejected"
        db.session.commit()

    # Log rejection on blockchain too
    tx = {
        "batch_id": batch_id,
        "from": pending.sender,
        "to": receiver,
        "action": "transfer_rejected",
        "timestamp": time.time(),
        "status": "rejected"
    }
    blockchain.add_block(tx)

    return jsonify({"message": "Transfer rejected", "transaction": tx})


@app.route("/dashboard_stats", methods=["GET"])
@jwt_required()
def dashboard_stats():
    total = BatchModel.query.count()
    created = BatchModel.query.filter_by(status="Created").count()
    in_transit = BatchModel.query.filter_by(status="In Transit").count()
    delivered = BatchModel.query.filter_by(status="Delivered").count()
    rejected = BatchModel.query.filter_by(status="Rejected").count()

    return jsonify({
        "total_batches": total,
        "pending": created + in_transit,
        "delivered": delivered,
        "rejected": rejected
    })


@app.route("/log_conditions", methods=["POST"])
@jwt_required()
def log_conditions():
    data = request.get_json()
    required = ["batch_id", "conditions"]

    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    tx = blockchain.log_conditions(
        batch_id=data["batch_id"],
        conditions=data["conditions"]
    )
    return jsonify({"message": "Conditions logged", "transaction": tx})


@app.route("/batch_history/<batch_id>", methods=["GET"])
@jwt_required()
def batch_history(batch_id):
    history = blockchain.get_batch_history(batch_id)
    if not history:
        return jsonify({"message": f"No transactions found for batch_id {batch_id}"}), 404
    return jsonify({"batch_id": batch_id, "history": history})


# Main Entry
if __name__ == "__main__":
    # Create DB tables if not exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
