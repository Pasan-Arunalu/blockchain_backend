import hashlib, json
from datetime_utils import get_current_timestamp
from models import db, BlockModel, PendingTransferModel, BatchModel, User
from dataclasses import dataclass, field

from contract.deploy import push_transaction

@dataclass(frozen=True)
class Block:
    index: int
    timestamp: float
    transactions: list
    previous_hash: str
    hash: str = field(default="", compare=False)  # default empty, computed later

    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __post_init__(self):
        # If hash is missing, compute automatically
        if not self.hash:
            object.__setattr__(self, "hash", self.calculate_hash())

class Blockchain:
    def __init__(self, use_db=True):
        self.use_db = use_db
        self.pending_transactions = []

        self.chain = self.load_chain_from_db() if self.use_db else []

        if not self.chain:
            genesis = self.create_genesis_block()
            self.chain.append(genesis)
            if self.use_db:
                self.save_block_to_db(genesis)
        # else:
        #     if not self.is_chain_valid():
        #         raise ValueError("Blockchain integrity check failed! Possible tampering detected.")

    def create_genesis_block(self):
        return Block(
            index=0,
            timestamp=get_current_timestamp(),
            transactions=[{"message": "Genesis Block"}],
            previous_hash="0",
            hash=""
        )

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_transactions):
        if isinstance(new_transactions, dict):
            new_transactions = [new_transactions]
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=get_current_timestamp(),
            transactions=new_transactions,
            previous_hash=latest_block.hash
        )
        self.chain.append(new_block)
        if self.use_db:
            self.save_block_to_db(new_block)

    def save_block_to_db(self, block):
        block_record = BlockModel(
            index=block.index,
            timestamp=block.timestamp,  # Now stored as float directly
            transactions=json.dumps(block.transactions),
            previous_hash=block.previous_hash,
            hash=block.hash
        )
        db.session.add(block_record)
        db.session.commit()

    def load_chain_from_db(self):
        blocks = BlockModel.query.order_by(BlockModel.index.asc()).all()
        chain = []
        for b in blocks:
            chain.append(
                Block(
                    index=b.index,
                    timestamp=b.timestamp,  # Already float, no conversion needed
                    transactions=json.loads(b.transactions) if b.transactions else [],
                    previous_hash=b.previous_hash,
                    hash=b.hash
                )
            )
        return chain

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash() or current.previous_hash != previous.hash:
                return False
        return True

    def create_initial_batch(self, batch_id, owner_email, details=None):
        # Ensure details is always a dict
        details = details or {}

        # Extract product_name
        product_name = details.get("product") or "Unknown Product"

        # Add a blockchain transaction
        tx = {
            "batch_id": batch_id,
            "owner_email": owner_email,
            "action": "batch_created",
            "details": details,
            "timestamp": get_current_timestamp()
        }
        self.add_block(tx)
        push_transaction(tx)

        # Save in DB → include product_name
        batch = BatchModel(
            batch_id=batch_id,
            product_name=product_name,
            creator_email=owner_email,
            current_owner_email=owner_email,
            status="Created"
        )
        db.session.add(batch)
        db.session.commit()

        return tx

    def create_transfer_request(self, batch_id, sender_email, receiver_email):
        tx = {
            "batch_id": batch_id,
            "from_email": sender_email,
            "to_email": receiver_email,
            "action": "transfer_request",
            "status": "pending",
            "timestamp": get_current_timestamp()
        }

        pending = PendingTransferModel(
            batch_id=batch_id,
            sender_email=sender_email,
            receiver_email=receiver_email,
            timestamp=tx["timestamp"],  # Already float from get_current_timestamp()
            status="pending"
        )
        db.session.add(pending)
        db.session.commit()
        return tx

    def accept_transfer(self, batch_id, receiver_email, conditions):
        pending = PendingTransferModel.query.filter_by(
            batch_id=batch_id,
            receiver_email=receiver_email,
            status="pending"
        ).first()

        if not pending:
            return None

        tx = {
            "batch_id": batch_id,
            "from_email": pending.sender_email,
            "to_email": pending.receiver_email,
            "owner_email": pending.receiver_email,
            "action": "ownership_accepted",
            "conditions": conditions,
            "timestamp": get_current_timestamp(),
            "status": "accepted"
        }

        # Add to blockchain
        self.add_block(tx)
        push_transaction(tx)

        # Update DB record
        pending.status = "accepted"
        pending.conditions = json.dumps(conditions)
        db.session.commit()

        # Update current owner in BatchModel
        batch = BatchModel.query.filter_by(batch_id=batch_id).first()
        if batch:
            batch.current_owner_email = receiver_email

            # Update status based on receiver role
            user = User.query.filter_by(email=receiver_email).first()
            if user:
                if user.role.lower() == "distributor":
                    batch.status = "In Distribution"
                elif user.role.lower() == "retailer":
                    batch.status = "Distributed"
                else:
                    batch.status = "In Transit"
            db.session.commit()

        tx["owner"] = tx["owner_email"]
        return tx

    def log_conditions(self, batch_id, conditions):
        batch = BatchModel.query.filter_by(batch_id=batch_id).first()
        if not batch:
            return None

        tx = {
            "batch_id": batch_id,
            "owner_email": batch.current_owner_email,
            "action": "update_conditions",
            "conditions": conditions,
            "timestamp": get_current_timestamp()
        }
        self.add_block(tx)
        push_transaction(tx)
        return tx

    def get_batch_history(self, batch_id):
        history = []
        for block in self.chain:
            for tx in (block.transactions if isinstance(block.transactions, list) else []):
                if tx.get("batch_id") == batch_id:
                    history.append(tx)
        return history
