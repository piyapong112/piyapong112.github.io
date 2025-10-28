import sqlite3

def init_db():
    """
    Initializes the database. Creates tables if they don't exist
    and adds the user_id column to existing tables if it's missing.
    """
    conn = sqlite3.connect('inventory.db')
    c = conn.cursor()

    # สร้างตาราง users ใหม่ให้มีทุกคอลัมน์
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            is_verified BOOLEAN DEFAULT FALSE,
            otp TEXT,
            otp_expiry TEXT
        )
    ''')

    # 2. Create the 'products' table with all necessary columns including user_id
    # This combines the original creation and the later alteration.
    c.execute('''
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT NOT NULL,
            sku TEXT NOT NULL,
            factory_sku TEXT NOT NULL,
            details TEXT,
            stock INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            deleted_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # 3. Create other tables if they don't exist
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_details TEXT NOT NULL,
            factory_sku TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            cost_per_item REAL NOT NULL,
            order_date TEXT NOT NULL,
            updated_at TEXT,
            deleted_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            sale_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER NOT NULL,
            price_per_item REAL NOT NULL,
            sale_date TEXT NOT NULL,
            updated_at TEXT,
            deleted_at TEXT,
            FOREIGN KEY(product_id) REFERENCES products(product_id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            payment_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            order_id INTEGER,
            amount REAL NOT NULL,
            payment_date TEXT NOT NULL,
            updated_at TEXT,
            deleted_at TEXT,
            FOREIGN KEY(order_id) REFERENCES orders(order_id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # 4. Add 'user_id' column to tables that might be missing it (for backward compatibility)
    tables_to_update = ['products', 'orders', 'sales', 'payments']
    for table in tables_to_update:
        try:
            # This will fail if the column already exists, which is caught by the exception.
            c.execute(f'ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)')
            print(f"Added 'user_id' column to '{table}' table.")
        except sqlite3.OperationalError as e:
            # The most common error here is "duplicate column name". We can ignore it.
            if "duplicate column name" in str(e):
                pass # Column already exists, no action needed.
            else:
                raise # Re-raise other unexpected errors.
        try:
            c.execute('ALTER TABLE users ADD COLUMN email TEXT UNIQUE')
        except sqlite3.OperationalError:
            pass # คอลัมน์มีอยู่แล้ว
        try:
            c.execute('ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT FALSE')
        except sqlite3.OperationalError:
            pass # คอลัมน์มีอยู่แล้ว
        try:
            c.execute('ALTER TABLE users ADD COLUMN otp TEXT')
        except sqlite3.OperationalError:
            pass # คอลัมน์มีอยู่แล้ว
        try:
            c.execute('ALTER TABLE users ADD COLUMN otp_expiry TEXT')
        except sqlite3.OperationalError:
            pass # คอลัมน์มีอยู่แล้ว

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database schema updated for 2FA and email verification!")
