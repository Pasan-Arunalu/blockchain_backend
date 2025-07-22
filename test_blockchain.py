from blockchain import Blockchain

# ✅ Create a blockchain instance (loads from DB or starts fresh)
bc = Blockchain(use_db=False)

# ✅ 1. Farmer creates a transfer request
print("\n=== Farmer creates transfer ===")
tx1 = bc.create_transfer_request(
    batch_id="BATCH123",
    sender="Farmer_A",
    receiver="Distributor_B"
)
print("Pending Transfer:", tx1)
print("Pending Transactions:", bc.pending_transactions)

# ✅ 2. Distributor accepts transfer
print("\n=== Distributor accepts transfer ===")
accepted_tx = bc.accept_transfer(
    batch_id="BATCH123",
    receiver="Distributor_B",
    conditions={"temperature": "5°C", "humidity": "70%", "location": "Warehouse_A"}
)
print("Accepted Transfer:", accepted_tx)

# ✅ 3. Distributor logs conditions during transport
print("\n=== Distributor logs conditions ===")
bc.log_conditions(
    batch_id="BATCH123",
    conditions={"temperature": "4.8°C", "humidity": "72%", "location": "Truck_42"}
)
bc.log_conditions(
    batch_id="BATCH123",
    conditions={"temperature": "4.5°C", "humidity": "75%", "location": "Warehouse_B"}
)

# ✅ 4. Retailer accepts transfer from distributor
print("\n=== Retailer accepts final delivery ===")
bc.create_transfer_request(
    batch_id="BATCH123",
    sender="Distributor_B",
    receiver="Retailer_C"
)
bc.accept_transfer(
    batch_id="BATCH123",
    receiver="Retailer_C",
    conditions={"temperature": "4°C", "humidity": "68%", "location": "Retailer_Store"}
)

# ✅ 5. Check batch history
print("\n=== Batch History ===")
history = bc.get_batch_history("BATCH123")
for i, tx in enumerate(history, 1):
    print(f"Block {i}: {tx}")

# ✅ 6. Validate chain
print("\n=== Chain Valid? ===", bc.is_chain_valid())

