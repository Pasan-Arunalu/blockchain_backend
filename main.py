from functools import wraps
from flask_cors import CORS

from flask import Flask, jsonify, request, Response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash

import datetime, json, matplotlib.pyplot as plt, matplotlib
import matplotlib.dates as mdates
import io
import base64
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
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:5173")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
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

@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    """Handle CORS preflight requests"""
    response = jsonify({"message": "OK"})
    response.headers.add("Access-Control-Allow-Origin", "http://localhost:5173")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response

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
    try:
        tx_data = request.get_json()
        print("Incoming transaction data:", tx_data)
        
        if not tx_data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        required_fields = ["batch_id", "product", "owner_email", "location", "temperature", "humidity", "transport"]

        # Verify all fields
        for field in required_fields:
            if field not in tx_data:
                return jsonify({"error": f"Missing field: {field}"}), 400

        # Get user info from JWT
        email = get_jwt_identity()        # only email
        claims = get_jwt()                # contains role
        role = claims.get("role")         # SAFE way to get role
        
        print(f"User email: {email}, role: {role}")

        # Business logic for role control
        existing_transaction = TransactionModel.query.filter_by(batch_id=tx_data['batch_id']).first()
        existing_batch = BatchModel.query.filter_by(batch_id=tx_data['batch_id']).first()

        if not existing_transaction and not existing_batch:
            # No batch exists anywhere → must be created by Farmer
            if role.lower() != "farmer":
                return jsonify({"error": f"Only Farmers can create new batch, but you are {role}"}), 403

            print(f"Creating initial batch: {tx_data['batch_id']}")
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
        elif existing_batch:
            # Batch exists in BatchModel → check if user is the current owner
            if existing_batch.current_owner_email != email:
                return jsonify({"error": f"You are not the current owner of this batch. Current owner: {existing_batch.current_owner_email}"}), 403
        else:
            # Batch exists in TransactionModel but not BatchModel (inconsistent state)
            print(f"Warning: Batch {tx_data['batch_id']} exists in TransactionModel but not BatchModel")
            # Continue with the transaction creation

        # Save transaction with current user as owner
        tx_data['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tx_data['owner'] = email  # Set owner to current user
        
        # Remove owner_email field as TransactionModel doesn't have it
        if 'owner_email' in tx_data:
            del tx_data['owner_email']
        
        print(f"Creating transaction with data: {tx_data}")
        new_tx = TransactionModel(**tx_data)
        db.session.add(new_tx)
        db.session.commit()
        
        print("Transaction saved successfully")

        return jsonify({
            "message": "Transaction added successfully!", 
            "role": role,
            "batch_id": tx_data['batch_id'],
            "is_new_batch": not existing_transaction and not existing_batch
        })
        
    except Exception as e:
        print(f"Error in add_transaction: {str(e)}")
        db.session.rollback()
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@app.route('/db_transactions/<batch_id>', methods=['GET'])
def db_transactions(batch_id):
    txs = TransactionModel.query.filter_by(batch_id=batch_id).all()
    if not txs:
        return jsonify({"message": "No transactions in DB for this batch"}), 404

    # Get current batch owner
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    current_owner = batch.current_owner_email if batch else None

    data = []
    for t in txs:
        # Check if this transaction shows ownership transfer
        is_transfer = t.owner != current_owner if current_owner else False
        
        data.append({
            "product": t.product,
            "owner": t.owner,
            "current_owner": current_owner,
            "location": t.location,
            "temperature": t.temperature,
            "humidity": t.humidity,
            "transport": t.transport,
            "timestamp": t.timestamp,
            "is_transfer": is_transfer
        })
    return jsonify({"batch_id": batch_id, "transactions": data, "current_owner": current_owner})


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
@jwt_required()
def visualize_batch(batch_id):
    """Return matplotlib chart as base64 encoded image"""
    user_email = get_jwt_identity()
    
    # Check if user has access to this batch
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    if not batch:
        return jsonify({"error": "Batch not found"}), 404
    
    # Only allow access if user is the current owner or has transactions for this batch
    if batch.current_owner_email != user_email:
        # Check if user has any transactions for this batch
        user_transaction = TransactionModel.query.filter_by(
            batch_id=batch_id, 
            owner=user_email
        ).first()
        if not user_transaction:
            return jsonify({"error": "Access denied. You don't have permission to view this batch data"}), 403
    
    # Get temperature and humidity data from database transactions
    transactions = TransactionModel.query.filter_by(batch_id=batch_id).order_by(TransactionModel.timestamp).all()
    
    times, temps, humids = [], [], []
    
    for tx in transactions:
        try:
            # Parse timestamp
            timestamp = datetime.datetime.strptime(tx.timestamp, "%Y-%m-%d %H:%M:%S")
            times.append(timestamp)
            
            # Parse temperature (remove °C and convert to int)
            if tx.temperature and tx.temperature != "N/A":
                temp_value = int(tx.temperature.replace('°C', '').strip())
                temps.append(temp_value)
            else:
                temps.append(None)
            
            # Parse humidity (remove % and convert to int)
            if tx.humidity and tx.humidity != "N/A":
                humid_value = int(tx.humidity.replace('%', '').strip())
                humids.append(humid_value)
            else:
                humids.append(None)
                
        except (ValueError, AttributeError) as e:
            print(f"Error parsing transaction data: {e}")
            continue

    if not times:
        return jsonify({"message": f"No temperature/humidity data found for batch_id {batch_id}"}), 404

    # Create matplotlib figure
    plt.figure(figsize=(12, 6))
    
    # Plot temperature data
    valid_temp_data = [(t, temp) for t, temp in zip(times, temps) if temp is not None]
    if valid_temp_data:
        temp_times, temp_values = zip(*valid_temp_data)
        plt.plot(temp_times, temp_values, 'r-o', label='Temperature (°C)', linewidth=2, markersize=6)
    
    # Plot humidity data
    valid_humid_data = [(t, humid) for t, humid in zip(times, humids) if humid is not None]
    if valid_humid_data:
        humid_times, humid_values = zip(*valid_humid_data)
        plt.plot(humid_times, humid_values, 'b-s', label='Humidity (%)', linewidth=2, markersize=6)
    
    # Customize the plot
    plt.title(f'Temperature & Humidity Over Time for {batch_id}', fontsize=14, fontweight='bold')
    plt.xlabel('Timestamp', fontsize=12)
    plt.ylabel('Value', fontsize=12)
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3)
    
    # Format x-axis dates
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.gcf().autofmt_xdate()  # Rotate and align the tick labels
    
    # Adjust layout
    plt.tight_layout()
    
    # Save to bytes buffer
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
    img_buffer.seek(0)
    
    # Encode to base64
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    
    # Close the plot to free memory
    plt.close()
    
    return jsonify({
        "image": img_base64,
        "format": "png",
        "batch_id": batch_id,
        "data_points": len(times)
    })

@app.route('/visualize_html/<batch_id>', methods=['GET'])
@jwt_required()
def visualize_batch_html(batch_id):
    """Render matplotlib chart as HTML with embedded image"""
    user_email = get_jwt_identity()
    
    # Check if user has access to this batch
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    if not batch:
        return jsonify({"error": "Batch not found"}), 404
    
    # Only allow access if user is the current owner or has transactions for this batch
    if batch.current_owner_email != user_email:
        # Check if user has any transactions for this batch
        user_transaction = TransactionModel.query.filter_by(
            batch_id=batch_id, 
            owner=user_email
        ).first()
        if not user_transaction:
            return jsonify({"error": "Access denied. You don't have permission to view this batch data"}), 403

    # Get temperature and humidity data from database transactions
    transactions = TransactionModel.query.filter_by(batch_id=batch_id).order_by(TransactionModel.timestamp).all()
    
    times, temps, humids = [], [], []
    
    for tx in transactions:
        try:
            # Parse timestamp
            timestamp = datetime.datetime.strptime(tx.timestamp, "%Y-%m-%d %H:%M:%S")
            times.append(timestamp)
            
            # Parse temperature (remove °C and convert to int)
            if tx.temperature and tx.temperature != "N/A":
                temp_value = int(tx.temperature.replace('°C', '').strip())
                temps.append(temp_value)
            else:
                temps.append(None)
            
            # Parse humidity (remove % and convert to int)
            if tx.humidity and tx.humidity != "N/A":
                humid_value = int(tx.humidity.replace('%', '').strip())
                humids.append(humid_value)
            else:
                humids.append(None)
                
        except (ValueError, AttributeError) as e:
            print(f"Error parsing transaction data: {e}")
            continue

    if not times:
        return jsonify({"error": f"No temperature/humidity data found for batch_id {batch_id}"}), 404

    # Create matplotlib figure
    plt.figure(figsize=(12, 6))
    
    # Plot temperature data
    valid_temp_data = [(t, temp) for t, temp in zip(times, temps) if temp is not None]
    if valid_temp_data:
        temp_times, temp_values = zip(*valid_temp_data)
        plt.plot(temp_times, temp_values, 'r-o', label='Temperature (°C)', linewidth=2, markersize=6)
    
    # Plot humidity data
    valid_humid_data = [(t, humid) for t, humid in zip(times, humids) if humid is not None]
    if valid_humid_data:
        humid_times, humid_values = zip(*valid_humid_data)
        plt.plot(humid_times, humid_values, 'b-s', label='Humidity (%)', linewidth=2, markersize=6)
    
    # Customize the plot
    plt.title(f'Temperature & Humidity Over Time for {batch_id}', fontsize=14, fontweight='bold')
    plt.xlabel('Timestamp', fontsize=12)
    plt.ylabel('Value', fontsize=12)
    plt.legend(fontsize=10)
    plt.grid(True, alpha=0.3)
    
    # Format x-axis dates
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
    plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
    plt.gcf().autofmt_xdate()  # Rotate and align the tick labels
    
    # Adjust layout
    plt.tight_layout()
    
    # Save to bytes buffer
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
    img_buffer.seek(0)
    
    # Encode to base64
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    
    # Close the plot to free memory
    plt.close()
    
    # Create HTML with embedded image
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Temperature & Humidity Chart - {batch_id}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #333;
                text-align: center;
                margin-bottom: 20px;
            }}
            .chart-container {{
                text-align: center;
                margin: 20px 0;
            }}
            img {{
                max-width: 100%;
                height: auto;
                border: 1px solid #ddd;
                border-radius: 4px;
            }}
            .info {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin-top: 20px;
            }}
            .info h3 {{
                margin-top: 0;
                color: #495057;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Temperature & Humidity Monitoring</h1>
            <div class="chart-container">
                <img src="data:image/png;base64,{img_base64}" alt="Temperature and Humidity Chart">
            </div>
            <div class="info">
                <h3>Batch Information</h3>
                <p><strong>Batch ID:</strong> {batch_id}</p>
                <p><strong>Data Points:</strong> {len(times)}</p>
                <p><strong>Latest Temperature:</strong> {temps[-1] if temps and temps[-1] is not None else 'N/A'}°C</p>
                <p><strong>Latest Humidity:</strong> {humids[-1] if humids and humids[-1] is not None else 'N/A'}%</p>
                <p><strong>Latest Timestamp:</strong> {times[-1].strftime('%Y-%m-%d %H:%M:%S') if times else 'N/A'}</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_content


@app.route('/my_visualizations', methods=['GET'])
@jwt_required()
def my_visualizations():
    """Get visualization data for all batches owned by the current user"""
    user_email = get_jwt_identity()
    
    # Get all batches owned by the current user
    owned_batches = BatchModel.query.filter_by(current_owner_email=user_email).all()
    
    if not owned_batches:
        return jsonify({"message": "No batches found for visualization"}), 404
    
    result = []
    for batch in owned_batches:
        # Get transactions for this batch
        transactions = TransactionModel.query.filter_by(batch_id=batch.batch_id).order_by(TransactionModel.timestamp).all()
        
        times, temps, humids = [], [], []
        
        for tx in transactions:
            try:
                # Parse timestamp
                timestamp = datetime.datetime.strptime(tx.timestamp, "%Y-%m-%d %H:%M:%S")
                times.append(timestamp)
                
                # Parse temperature
                if tx.temperature and tx.temperature != "N/A":
                    temp_value = int(tx.temperature.replace('°C', '').strip())
                    temps.append(temp_value)
                else:
                    temps.append(None)
                
                # Parse humidity
                if tx.humidity and tx.humidity != "N/A":
                    humid_value = int(tx.humidity.replace('%', '').strip())
                    humids.append(humid_value)
                else:
                    humids.append(None)
                    
            except (ValueError, AttributeError) as e:
                print(f"Error parsing transaction data: {e}")
                continue
        
        # Only include batches with valid data
        if times:
            result.append({
                "batch_id": batch.batch_id,
                "product_name": batch.product_name,
                "status": batch.status,
                "data_points": len(times),
                "latest_temperature": temps[-1] if temps and temps[-1] is not None else None,
                "latest_humidity": humids[-1] if humids and humids[-1] is not None else None,
                "latest_timestamp": times[-1].strftime("%Y-%m-%d %H:%M:%S") if times else None,
                "visualization_url": f"/visualize/{batch.batch_id}",
                "html_visualization_url": f"/visualize_html/{batch.batch_id}"
            })
    
    return jsonify({"batches": result})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    required = ["name", "role", "email", "password"]
    for f in required:
        if f not in data:
            return jsonify({"error": f"Missing field: {f}"}), 400

    # Basic validation
    if not data['email'] or '@' not in data['email']:
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(data['password']) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    if data['role'].lower() not in ['farmer', 'distributor', 'retailer']:
        return jsonify({"error": "Invalid role. Must be farmer, distributor, or retailer"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400

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
        return jsonify({"error": "Invalid credentials"}), 401

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

        # Verify sender is the current owner
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
        # Get sender user details
        sender_user = User.query.filter_by(email=req.sender_email).first()
        
        # Get batch details
        batch = BatchModel.query.filter_by(batch_id=req.batch_id).first()
        
        result.append({
            "transfer_id": req.id,
            "batch_id": req.batch_id,
            "batch_product": batch.product_name if batch else "Unknown",
            "batch_status": batch.status if batch else "Unknown",
            "from_email": req.sender_email,
            "from_name": sender_user.name if sender_user else "Unknown",
            "from_role": sender_user.role if sender_user else "Unknown",
            "to_email": req.receiver_email,
            "status": req.status,
            "timestamp": req.timestamp,
            "accept_url": f"/accept_transfer/{req.id}"
        })

    return jsonify({"pending_requests": result})


@app.route("/my_sent_transfers", methods=["GET"])
@jwt_required()
def my_sent_transfers():
    """Get transfers sent by the current user"""
    user_email = get_jwt_identity()
    requests = PendingTransferModel.query.filter_by(sender_email=user_email).all()

    result = []
    for req in requests:
        # Get receiver user details
        receiver_user = User.query.filter_by(email=req.receiver_email).first()
        
        # Get batch details
        batch = BatchModel.query.filter_by(batch_id=req.batch_id).first()
        
        result.append({
            "transfer_id": req.id,
            "batch_id": req.batch_id,
            "batch_product": batch.product_name if batch else "Unknown",
            "batch_status": batch.status if batch else "Unknown",
            "to_email": req.receiver_email,
            "to_name": receiver_user.name if receiver_user else "Unknown",
            "to_role": receiver_user.role if receiver_user else "Unknown",
            "from_email": req.sender_email,
            "status": req.status,
            "timestamp": req.timestamp
        })

    return jsonify({"sent_transfers": result})


@app.route("/accept_transfer/<int:transfer_id>", methods=["POST"])
@jwt_required()
def accept_transfer(transfer_id):
    receiver_email = get_jwt_identity()
    pending_transfer = PendingTransferModel.query.get(transfer_id)

    if not pending_transfer:
        return jsonify({"error": "Transfer not found"}), 404

    if pending_transfer.receiver_email != receiver_email:
        return jsonify({"error": "Not authorized"}), 403

    # Get the JSON data from the POST request body
    req_data = request.get_json()

    if not req_data:
        return jsonify({"error": "Missing data"}), 400

    # Use batch_id from URL param or request data
    batch_id = pending_transfer.batch_id
    
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    if not batch:
        return jsonify({"error": "Batch not found"}), 404

    if batch.status == "Distributed":
        return jsonify({"error": "Blockchain is closed for this product"}), 400

    # Accept the transfer using blockchain method
    tx = blockchain.accept_transfer(
        batch_id=batch_id,
        receiver_email=receiver_email,
        conditions=req_data.get("conditions", {})
    )
    
    if not tx:
        return jsonify({"error": "Failed to accept transfer"}), 400

    # Create a new transaction record with the updated owner
    new_tx = TransactionModel(
        batch_id=batch_id,
        product=batch.product_name,
        owner=receiver_email,  # Set owner to the receiver
        location=req_data.get("location", "Unknown"),
        temperature=req_data.get("temperature", "N/A"),
        humidity=req_data.get("humidity", "N/A"),
        transport=req_data.get("transport", "N/A"),
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.session.add(new_tx)

    # Remove pending transfer
    db.session.delete(pending_transfer)
    db.session.commit()

    return jsonify({"message": "Transfer accepted and added to blockchain", "transaction": tx}), 200



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
    in_distribution = BatchModel.query.filter_by(status="In Distribution").count()
    distributed = BatchModel.query.filter_by(status="Distributed").count()
    rejected = BatchModel.query.filter_by(status="Rejected").count()

    return jsonify({
        "total_batches": total,
        "pending": created + in_transit + in_distribution,
        "delivered": distributed,
        "rejected": rejected
    })


@app.route("/my_transactions", methods=["GET"])
@jwt_required()
def my_transactions():
    user_email = get_jwt_identity()

    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Get all transactions where user is the owner (current owner)
    owned_transactions = TransactionModel.query.filter_by(owner=user_email).order_by(TransactionModel.timestamp.desc()).all()

    # Get all batches where user is the current owner
    owned_batches = BatchModel.query.filter_by(current_owner_email=user_email).all()
    owned_batch_ids = [batch.batch_id for batch in owned_batches]

    # Get all transactions for batches owned by the user
    all_user_transactions = TransactionModel.query.filter(
        TransactionModel.batch_id.in_(owned_batch_ids)
    ).order_by(TransactionModel.timestamp.desc()).all()

    # Combine and deduplicate transactions
    all_transactions = list(set(owned_transactions + all_user_transactions))
    all_transactions.sort(key=lambda x: x.timestamp, reverse=True)

    if not all_transactions:
        return jsonify({"transactions": []})

    # Get all batch information in one query to avoid N+1 problem
    batch_ids = list(set(tx.batch_id for tx in all_transactions))
    batches = {batch.batch_id: batch for batch in BatchModel.query.filter(
        BatchModel.batch_id.in_(batch_ids)
    ).all()}

    result = []
    for tx in all_transactions:
        # Get batch status and current owner from cached data
        batch = batches.get(tx.batch_id)
        status = batch.status if batch else "Unknown"
        current_owner = batch.current_owner_email if batch else tx.owner

        # Determine if this transaction shows ownership transfer
        is_transfer = tx.owner != current_owner
        
        result.append({
            "batch_id": tx.batch_id,
            "product": tx.product,
            "owner": tx.owner,  # Original owner in this transaction
            "current_owner": current_owner,  # Current owner of the batch
            "date": tx.timestamp,
            "status": status,
            "is_transfer": is_transfer,
            "location": tx.location,
            "temperature": tx.temperature,
            "humidity": tx.humidity,
            "transport": tx.transport
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

    # Count transfers sent TO the user (not FROM the user)
    count = PendingTransferModel.query.filter_by(receiver_email=user_email, status="pending").count()
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


@app.route("/batch_owner/<batch_id>", methods=["GET"])
@jwt_required()
def get_batch_owner(batch_id):
    """Get the current owner of a specific batch"""
    batch = BatchModel.query.filter_by(batch_id=batch_id).first()
    
    if not batch:
        return jsonify({"error": "Batch not found"}), 404
    
    # Get user details for the current owner
    owner_user = User.query.filter_by(email=batch.current_owner_email).first()
    
    return jsonify({
        "batch_id": batch_id,
        "current_owner_email": batch.current_owner_email,
        "current_owner_name": owner_user.name if owner_user else "Unknown",
        "current_owner_role": owner_user.role if owner_user else "Unknown",
        "status": batch.status
    })


@app.route("/my_batches", methods=["GET"])
@jwt_required()
def my_batches():
    """Get all batches owned by the current user"""
    user_email = get_jwt_identity()
    
    batches = BatchModel.query.filter_by(current_owner_email=user_email).all()
    
    result = []
    for batch in batches:
        result.append({
            "batch_id": batch.batch_id,
            "product_name": batch.product_name,
            "status": batch.status,
            "created_at": batch.created_at,
            "updated_at": batch.updated_at
        })
    
    return jsonify({"batches": result})

# Main Entry
if __name__ == "__main__":
    # Create DB tables if not exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
