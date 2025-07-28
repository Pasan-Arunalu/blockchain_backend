from functools import wraps
from flask_cors import CORS

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

import datetime, json, plotly.graph_objs as go, plotly
import time

from models import db, TransactionModel, User, BlockModel, PendingTransferModel, BatchModel
from blockchain import Blockchain


app = Flask(__name__)

CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:5173"}})

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


@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    return response


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
    print("Incoming transaction data:", tx_data)
    required_fields = ["batch_id", "product", "owner_email", "location", "temperature", "humidity", "transport"]

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
        if role.lower() != "farmer":
            return jsonify({"error": f"Only Farmers can create new batch, but you are {role}"}), 403

        # Call create_initial_batch instead of manually creating a block
        blockchain.create_initial_batch(
            batch_id=tx_data['batch_id'],
            owner_email=email,
            details={
                "product": tx_data["product"],
                "location": tx_data["location"],
                "temperature": tx_data["temperature"],
                "humidity": tx_data["humidity"],
                "transport": tx_data["transport"]
            }
        )
    else:
        # Already exists → must be Distributor or Retailer
        if role.lower() not in ["distributor", "retailer"]:
            return jsonify({"error": f"Only Distributor/Retailer can transfer ownership, but you are {role}"}), 403

    # Save transaction
    tx_data['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tx_data['owner'] = tx_data.pop('owner_email')
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

    access_token = create_access_token(
        identity=user.email,
        additional_claims={"role": user.role, "name": user.name}
    )

    return jsonify({
        "message": "Login successful!",
        "access_token": access_token,
        "role": user.role,
        "name": user.name,
        "email": user.email
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
    required = ["batch_id", "from_email", "to_email"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    claims = get_jwt()
    sender_role = claims.get("role")
    sender_email = get_jwt_identity()

    # Validate sender matches the JWT identity
    if sender_email != data["from_email"]:
        print("[DEBUG] Sender email does not match from_email in request body")
        return jsonify({"error": "Sender email does not match logged-in user"}), 403

    # Fetch blockchain history for batch
    history = blockchain.get_batch_history(data["batch_id"])

    print(f"[DEBUG] Blockchain history for batch (length): {len(history) if history else 0}")
    if history:
        print(f"[DEBUG] Last transaction in history: {history[-1]}")

    if not history:
        # First-time transfer → only Farmers allowed
        if sender_role.lower() != "farmer":
            print("[DEBUG] Role not farmer but trying first-time transfer")
            return jsonify({"error": "Only Farmers can initiate first-time transfers"}), 403
    else:
        last_tx = history[-1]
        # Determine latest owner email
        if "action" in last_tx and last_tx.get("action") == "ownership_accepted":
            latest_owner_email = last_tx.get("to_email")
        elif "from_email" in last_tx:
            latest_owner_email = last_tx.get("from_email")
        elif "owner_email" in last_tx:
            latest_owner_email = last_tx.get("owner_email")
        elif "owner" in last_tx:
            latest_owner_email = last_tx.get("owner")
        else:
            print("[DEBUG] Invalid transaction format in blockchain")
            return jsonify({"error": "Invalid transaction format in blockchain"}), 500

        print(f"[DEBUG] Latest owner email: {latest_owner_email}")

        if latest_owner_email != sender_email:
            print("[DEBUG] Sender is not the current owner of this batch")
            return jsonify({"error": "You are not the current owner of this batch"}), 403

    # Create transfer request using email identifiers
    tx = blockchain.create_transfer_request(
        batch_id=data["batch_id"],
        sender_email=data["from_email"],
        receiver_email=data["to_email"]
    )

    return jsonify({"message": "Transfer request created", "transaction": tx}), 201


@app.route("/my_pending_requests", methods=["GET"])
@jwt_required()
def my_pending_requests():
    user_email = get_jwt_identity()
    requests = PendingTransferModel.query.filter_by(receiver_email=user_email, status="pending").all()

    result = []
    for req in requests:
        result.append({
            "batch_id": req.batch_id,
            "from": req.sender_email,
            "to": req.receiver_email,
            "status": req.status,
            "timestamp": req.timestamp
        })

    return jsonify({"pending_requests": result})


@app.route("/accept_transfer", methods=["POST"])
@jwt_required()
def accept_transfer():
    data = request.get_json()
    required = ["batch_id", "receiver_email", "conditions"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing field: {field}"}), 400

    # Get logged-in user info
    claims = get_jwt()
    receiver_role = claims["role"]
    logged_in_email = get_jwt_identity()

    if data["receiver_email"] != logged_in_email:
        return jsonify({"error": "You are not the intended receiver for this transfer"}), 403

    if receiver_role.lower() not in ["distributor", "retailer"]:
        return jsonify({"error": f"{receiver_role}s are not allowed to accept ownership"}), 403

    # Accept in blockchain
    tx = blockchain.accept_transfer(
        batch_id=data["batch_id"],
        receiver_email=logged_in_email,
        conditions=data["conditions"]
    )

    if tx:
        try:
            # Extract conditions safely
            conditions = data["conditions"]
            location = conditions.get("location", "Unknown")
            temperature = str(conditions.get("temperature", ""))
            humidity = str(conditions.get("humidity", ""))
            transport = conditions.get("transport", "")

            # Get product name from batch (optional)
            batch = BatchModel.query.filter_by(batch_id=tx["batch_id"]).first()
            product_name = batch.product_name if batch else "N/A"

            # 1. Save to TransactionModel
            new_tx = TransactionModel(
                batch_id=tx["batch_id"],
                product=product_name,
                owner=tx["owner_email"],
                location=location,
                temperature=temperature,
                humidity=humidity,
                transport=transport,
                timestamp=str(tx["timestamp"])
            )
            db.session.add(new_tx)

            # 2. Update PendingTransferModel
            pending = PendingTransferModel.query.filter_by(batch_id=tx["batch_id"], status="pending").first()
            if pending:
                pending.status = "accepted"

            # 3. Update BatchModel current owner
            if batch:
                batch.current_owner_email = logged_in_email
                batch.status = "Delivered" if receiver_role.lower() == "retailer" else "In Transit"

            db.session.commit()

            return jsonify({"message": "Transfer accepted and recorded", "transaction": tx})
        except Exception as e:
            import traceback
            traceback.print_exc()
            db.session.rollback()
            return jsonify({
                "error": "Transfer accepted but DB failed",
                "details": str(e)
            }), 500

    return jsonify({"error": "No pending transfer found for this batch"}), 404


# @app.route("/reject_transfer", methods=["POST"])
# @jwt_required()
# def reject_transfer():
#     data = request.get_json()
#     batch_id = data.get("batch_id")
#     receiver = get_jwt_identity()
#
#     pending = PendingTransferModel.query.filter_by(
#         batch_id=batch_id, receiver=receiver, status="pending"
#     ).first()
#     if not pending:
#         return jsonify({"error": "No pending transfer found"}), 404
#
#     # Mark as rejected
#     pending.status = "rejected"
#     db.session.commit()
#
#     # Update batch status
#     batch = BatchModel.query.filter_by(batch_id=batch_id).first()
#     if batch:
#         batch.status = "Rejected"
#         db.session.commit()
#
#     # Log rejection on blockchain too
#     tx = {
#         "batch_id": batch_id,
#         "from": pending.sender,
#         "to": receiver,
#         "action": "transfer_rejected",
#         "timestamp": time.time(),
#         "status": "rejected"
#     }
#     blockchain.add_block(tx)
#
#     return jsonify({"message": "Transfer rejected", "transaction": tx})


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


@app.route("/my_transactions", methods=["GET"])
@jwt_required()
def my_transactions():

    user_email = get_jwt_identity()

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    transactions = TransactionModel.query.filter_by(owner=user_email).order_by(TransactionModel.timestamp.desc()).all()

    if not transactions:
        return jsonify({"transactions": []})

    result = []
    for tx in transactions:
        # Fetch batch status (if any)
        batch = BatchModel.query.filter_by(batch_id=tx.batch_id).first()
        status = batch.status if batch else "Unknown"

        result.append({
            "batch_id": tx.batch_id,
            "product": tx.product,
            "to": tx.owner,
            "date": tx.timestamp,
            "status": status
        })

    return jsonify({"transactions": result})


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

@app.route("/my_transaction_count", methods=["GET"])
@jwt_required()
def my_transaction_count():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"count": 0})

    count = TransactionModel.query.filter_by(owner=user_email).count()
    return jsonify({"count": count})


@app.route("/my_pending_count", methods=["GET"])
@jwt_required()
def my_pending_count():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"count": 0})

    count = PendingTransferModel.query.filter_by(sender_email=user_email).count()
    return jsonify({"count": count})

@app.route("/get_users", methods=["GET"])
def get_users():
    users = User.query.all()
    user_list = []

    for user in users:
        # Convert SQLAlchemy object to dict and remove internal attributes
        user_data = {
            "id": user.id,
            "name": user.name,
            "role": user.role,
            "email": user.email
        }
        user_list.append(user_data)

    return jsonify(user_list)

# Main Entry
if __name__ == "__main__":
    # Create DB tables if not exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
