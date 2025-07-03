import sqlite3

# Connect to the .db file
conn = sqlite3.connect("instance/password_manager.db")

# Create a cursor object
cursor = conn.cursor()

# Example: list all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables:", tables)

print('USER TABLE')
# Example: read data from users
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()
for row in rows:
    print(row)

print('CREDENTIAL TABLE')
# Example: read data from credentails
cursor.execute("SELECT * FROM credentials")
rows = cursor.fetchall()
for row in rows:
    print(row)

# Close connection
conn.close()