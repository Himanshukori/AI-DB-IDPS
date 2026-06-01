import random

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
NUM_SAMPLES = 1500

users = ["alice","bob","charlie","admin","svc","analyst","guest","dev","ops"]
ips = [f"192.168.1.{i}" for i in range(10,80)] + [f"10.0.0.{i}" for i in range(1,50)]

tables = ["users","orders","products","sessions","logs","reviews","inventory","payments","notifications"]
columns = ["id","name","email","price","status","created_at","user_id","stock","amount"]

def rand_user(): return random.choice(users)
def rand_ip(): return random.choice(ips)
def rand_id(): return random.randint(1,1000)
def rand_price(): return random.randint(10,5000)

queries = []

# 1. SIMPLE SELECT
for _ in range(250):
    q = f"SELECT {random.choice(columns)} FROM {random.choice(tables)} WHERE id={rand_id()}"
    queries.append((q, rand_user(), rand_ip()))

# 2. SELECT WITH MULTI CONDITIONS
for _ in range(200):
    q = f"SELECT * FROM {random.choice(tables)} WHERE id > {rand_id()} AND id < {rand_id()+100}"
    queries.append((q, rand_user(), rand_ip()))

# 3. ORDER BY + LIMIT
for _ in range(150):
    q = f"SELECT * FROM {random.choice(tables)} ORDER BY created_at DESC LIMIT {random.randint(5,50)}"
    queries.append((q, rand_user(), rand_ip()))

# 4. JOIN QUERIES
for _ in range(250):
    q = f"SELECT a.id, b.name FROM {random.choice(tables)} a JOIN {random.choice(tables)} b ON a.id = b.id WHERE a.id > {rand_id()}"
    queries.append((q, rand_user(), rand_ip()))

# 5. COMPLEX JOIN + FILTER
for _ in range(150):
    q = f"SELECT u.id, o.amount FROM users u JOIN orders o ON u.id = o.user_id WHERE o.amount > {rand_price()}"
    queries.append((q, rand_user(), rand_ip()))

# 6. GROUP BY + AGGREGATION
for _ in range(150):
    q = "SELECT user_id, COUNT(*) as cnt FROM orders GROUP BY user_id"
    queries.append((q, rand_user(), rand_ip()))

# 7. GROUP BY + HAVING
for _ in range(120):
    q = f"SELECT user_id, COUNT(*) as cnt FROM orders GROUP BY user_id HAVING COUNT(*) > {random.randint(1,10)}"
    queries.append((q, rand_user(), rand_ip()))

# 8. INSERT QUERIES
for _ in range(120):
    q = f"INSERT INTO {random.choice(tables)} (id, name) VALUES ({rand_id()}, 'test_user')"
    queries.append((q, rand_user(), rand_ip()))

# 9. UPDATE QUERIES
for _ in range(120):
    q = f"UPDATE {random.choice(tables)} SET name = 'updated' WHERE id = {rand_id()}"
    queries.append((q, rand_user(), rand_ip()))

# 10. DELETE QUERIES
for _ in range(90):
    q = f"DELETE FROM {random.choice(tables)} WHERE id = {rand_id()}"
    queries.append((q, rand_user(), rand_ip()))

# SHUFFLE + SAVE
random.shuffle(queries)

with open("normal_queries.csv", "w") as f:
    f.write("query,user,ip\n")
    for q,u,i in queries[:NUM_SAMPLES]:
        f.write(f"{q},{u},{i}\n")

print(f"Generated {NUM_SAMPLES} realistic queries")
