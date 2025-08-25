from flask_sqlalchemy import SQLAlchemy
from datetime_utils import get_current_timestamp

db = SQLAlchemy()

class TransactionModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(50), nullable=False)
    product = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    temperature = db.Column(db.String(10))
    humidity = db.Column(db.String(10))
    transport = db.Column(db.String(50))
    timestamp = db.Column(db.Float, nullable=False, default=get_current_timestamp)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class BlockModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Float, nullable=False, default=get_current_timestamp)
    transactions = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False)

class PendingTransferModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(100), nullable=False, index=True)
    sender_email = db.Column(db.String(100), nullable=False)
    receiver_email = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="pending")
    conditions = db.Column(db.Text)

class BatchModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(100), unique=True, nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    creator_email = db.Column(db.String(200), nullable=False)
    current_owner_email = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default="Created")  # Created, In Transit, Delivered, Rejected
    created_at = db.Column(db.Float, default=get_current_timestamp)
    updated_at = db.Column(db.Float, default=get_current_timestamp, onupdate=get_current_timestamp)
