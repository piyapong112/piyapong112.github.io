from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime, timedelta
import os
import requests
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# โหลด Environment Variables จากไฟล์ .env สำหรับการพัฒนาบนเครื่อง
load_dotenv()

app = Flask(__name__)

# --- การตั้งค่าทั่วไป ---
app.secret_key = os.environ.get('SECRET_KEY', 'default-fallback-key')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY')

# --- การตั้งค่าสำหรับการส่ง Email ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('Your App Name', app.config['MAIL_USERNAME'])

mail = Mail(app)

# --- ตั้งค่า Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], email=user_data['email'])
    return None

def get_db_connection():
    conn = sqlite3.connect('inventory.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp):
    """
    ส่งอีเมลพร้อมรหัส OTP และคืนค่าสถานะพร้อมข้อความ Error (ถ้ามี)
    """
    try:
        msg = Message('Your Verification Code', recipients=[recipient_email])
        msg.body = f'Your verification code is: {otp}\nThis code will expire in 10 minutes.'
        mail.send(msg)
        return True, None  # คืนค่าว่าสำเร็จ และไม่มี Error
    except Exception as e:
        # พิมพ์ Error ที่เกิดขึ้นจริงลงใน Log ของเซิร์ฟเวอร์
        print(f"ERROR: [Flask-Mail] - {e}")
        return False, str(e) # คืนค่าว่าล้มเหลว และส่งข้อความ Error กลับไป

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # ... (ส่วน reCAPTCHA ยังคงเดิม) ...
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน', 'danger')
            return redirect(url_for('register'))

        conn = get_db_connection()
        if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username นี้มีผู้ใช้งานแล้ว', 'danger')
            conn.close()
            return redirect(url_for('register'))
        if conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email นี้มีผู้ใช้งานแล้ว', 'danger')
            conn.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=10)

        try:
            conn.execute(
                'INSERT INTO users (username, email, password, otp, otp_expiry, is_verified) VALUES (?, ?, ?, ?, ?, ?)',
                (username, email, hashed_password, otp, otp_expiry.strftime('%Y-%m-%d %H:%M:%S'), False)
            )
            conn.commit()
        except sqlite3.Error as e:
            conn.close()
            flash(f'เกิดข้อผิดพลาดกับฐานข้อมูล: {e}', 'danger')
            return redirect(url_for('register'))

        # --- ปรับปรุงการจัดการ Error ตรงนี้ ---
        success, error_message = send_otp_email(email, otp)
        if success:
            conn.close()
            flash('ลงทะเบียนสำเร็จ! กรุณาตรวจสอบอีเมลเพื่อนำรหัสมายืนยันตัวตน', 'info')
            return redirect(url_for('verify_registration', email=email))
        else:
            # ถ้าส่งอีเมลไม่สำเร็จ ให้ลบ user ที่เพิ่งสร้างออกไป
            conn.execute('DELETE FROM users WHERE email = ?', (email,))
            conn.commit()
            conn.close()
            flash('เกิดข้อผิดพลาดในการส่งอีเมลยืนยัน กรุณาลองใหม่อีกครั้ง', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html', site_key=os.environ.get('RECAPTCHA_SITE_KEY', '6Lf3cbQrAAAAAK4XKDcHDrGw9PjQmjOXS4avkGMo'))

@app.route('/verify-registration/<email>', methods=['GET', 'POST'])
def verify_registration(email):
    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if not user_data:
            flash('ไม่พบอีเมลนี้ในระบบ', 'danger')
            return redirect(url_for('register'))

        otp_expiry = datetime.strptime(user_data['otp_expiry'], '%Y-%m-%d %H:%M:%S')

        if user_data['otp'] == submitted_otp and datetime.now() < otp_expiry:
            # ยืนยันสำเร็จ
            conn.execute('UPDATE users SET is_verified = ?, otp = NULL, otp_expiry = NULL WHERE email = ?', (True, email))
            conn.commit()
            conn.close()
            flash('ยืนยันอีเมลสำเร็จ! กรุณาล็อกอิน', 'success')
            return redirect(url_for('login'))
        else:
            conn.close()
            flash('รหัส OTP ไม่ถูกต้องหรือหมดอายุแล้ว', 'danger')
            return redirect(url_for('verify_registration', email=email))

    return render_template('verify.html', email=email, action_url=url_for('verify_registration', email=email))

# --- Routes สำหรับการล็อกอินและ 2FA ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user_data and check_password_hash(user_data['password'], password):
            if not user_data['is_verified']:
                flash('บัญชีของคุณยังไม่ได้ยืนยันอีเมล กรุณาตรวจสอบอีเมลของคุณ', 'warning')
                conn.close()
                return redirect(url_for('verify_registration', email=email))

            # ขั้นตอนที่ 1: รหัสผ่านถูกต้อง -> เริ่ม 2FA
            otp = generate_otp()
            otp_expiry = datetime.now() + timedelta(minutes=10)
            conn.execute('UPDATE users SET otp = ?, otp_expiry = ? WHERE id = ?', (otp, otp_expiry.strftime('%Y-%m-%d %H:%M:%S'), user_data['id']))
            conn.commit()
            conn.close()

            if send_otp_email(email, otp):
                session['user_id_to_verify'] = user_data['id'] # เก็บ id ไว้ใน session ชั่วคราว
                flash('กรุณาตรวจสอบอีเมลเพื่อนำรหัสมายืนยันการล็อกอิน', 'info')
                return redirect(url_for('verify_login'))
            else:
                flash('เกิดข้อผิดพลาดในการส่งรหัสยืนยัน', 'danger')
                return redirect(url_for('login'))
        else:
            conn.close()
            flash('Email หรือ Password ไม่ถูกต้อง', 'danger')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/verify-login', methods=['GET', 'POST'])
def verify_login():
    if 'user_id_to_verify' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id_to_verify']
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        submitted_otp = request.form.get('otp')
        otp_expiry = datetime.strptime(user_data['otp_expiry'], '%Y-%m-%d %H:%M:%S')

        if user_data['otp'] == submitted_otp and datetime.now() < otp_expiry:
            # ยืนยัน 2FA สำเร็จ
            conn.execute('UPDATE users SET otp = NULL, otp_expiry = NULL WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            user = User(id=user_data['id'], username=user_data['username'], email=user_data['email'])
            login_user(user)
            session.pop('user_id_to_verify', None) # ล้าง session
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('รหัส OTP ไม่ถูกต้องหรือหมดอายุแล้ว', 'danger')
            return redirect(url_for('verify_login'))

    conn.close()
    return render_template('verify.html', email=user_data['email'], action_url=url_for('verify_login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('คุณได้ออกจากระบบแล้ว', 'info')
    return redirect(url_for('login'))

# ====================================================================
# --- FIX: แก้ไขทุก Query ให้มีการกรองข้อมูลด้วย user_id ---
# ====================================================================

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()
    user_id = current_user.id
    
    orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    sales = conn.execute('SELECT s.*, p.factory_sku, p.name, p.details FROM sales s JOIN products p ON s.product_id = p.product_id WHERE s.deleted_at IS NULL AND s.user_id = ?', (user_id,)).fetchall()
    products = conn.execute('SELECT * FROM products WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    payments = conn.execute('SELECT * FROM payments WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    low_stock_products = conn.execute('SELECT * FROM products WHERE stock <= 10 AND deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()

    total_stock_remaining_data = conn.execute('SELECT SUM(stock) as total FROM products WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchone()
    total_stock_remaining = total_stock_remaining_data['total'] if total_stock_remaining_data and total_stock_remaining_data['total'] is not None else 0


    cost_map = {o['factory_sku']: o['cost_per_item'] for o in orders}
    total_revenue = sum(s['quantity'] * s['price_per_item'] for s in sales)
    total_items_sold = sum(s['quantity'] for s in sales)
    total_cost_of_goods_sold = sum(cost_map.get(s['factory_sku'], 0) * s['quantity'] for s in sales)
    net_profit = total_revenue - total_cost_of_goods_sold
    net_profit_margin = (net_profit / total_revenue * 100) if total_revenue > 0 else 0
    current_stock_value = sum(cost_map.get(p['factory_sku'], 0) * p['stock'] for p in products)
    
    product_profit = {}
    for sale in sales:
        profit = (sale['price_per_item'] - cost_map.get(sale['factory_sku'], 0)) * sale['quantity']
        product_key = f"{sale['name']} ({sale['details']})"
        product_profit[product_key] = product_profit.get(product_key, 0) + profit
        
    top_profitable_products = sorted(product_profit.items(), key=lambda item: item[1], reverse=True)[:5]
    total_order_costs = sum(o['quantity'] * o['cost_per_item'] for o in orders)
    total_payments_sum = sum(p['amount'] for p in payments)
    total_outstanding = total_order_costs - total_payments_sum

    conn.close()
    return render_template('dashboard.html', 
                           net_profit=net_profit, 
                           total_revenue=total_revenue, 
                           total_cost_of_goods_sold=total_cost_of_goods_sold, 
                           net_profit_margin=net_profit_margin, 
                           total_items_sold=total_items_sold, 
                           current_stock_value=current_stock_value, 
                           top_profitable_products=top_profitable_products, 
                           low_stock_products=low_stock_products, 
                           total_outstanding=total_outstanding,
                           total_stock_remaining=total_stock_remaining)
@app.route('/forms/stock-in')
@login_required
def forms_stock_in():
    return render_template('stock_in_forms.html')

@app.route('/forms/stock-out')
@login_required
def forms_stock_out():
    return render_template('stock_out_forms.html')
@app.route('/api/performance_data')
@login_required
def performance_data():
    conn = get_db_connection()
    user_id = current_user.id
    sales = conn.execute('SELECT sale_date, quantity, price_per_item, product_id FROM sales WHERE deleted_at IS NULL AND user_id = ? ORDER BY sale_date ASC', (user_id,)).fetchall()
    orders = conn.execute('SELECT factory_sku, cost_per_item FROM orders WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    cost_map = {o['factory_sku']: o['cost_per_item'] for o in orders}
    daily_data = {}

    for sale in sales:
        day = datetime.strptime(sale['sale_date'], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
        
        if day not in daily_data:
            daily_data[day] = {'revenue': 0, 'cost': 0, 'profit': 0}
            
        revenue = sale['quantity'] * sale['price_per_item']
        
        product_info = conn.execute('SELECT factory_sku FROM products WHERE product_id = ? AND user_id = ?', (sale['product_id'], user_id)).fetchone()
        cost = 0
        if product_info:
            factory_sku = product_info['factory_sku']
            cost_per_item = cost_map.get(factory_sku, 0)
            cost = cost_per_item * sale['quantity']
        
        daily_data[day]['revenue'] += revenue
        daily_data[day]['cost'] += cost
        daily_data[day]['profit'] += (revenue - cost)
        
    conn.close()

    sorted_days = sorted(daily_data.keys())
    chart_data = {
        'labels': sorted_days,
        'datasets': [
            {'label': 'ยอดขาย', 'data': [daily_data[day]['revenue'] for day in sorted_days], 'borderColor': 'rgba(75, 192, 192, 1)', 'tension': 0.1},
            {'label': 'ต้นทุน', 'data': [daily_data[day]['cost'] for day in sorted_days], 'borderColor': 'rgba(255, 99, 132, 1)', 'tension': 0.1},
            {'label': 'กำไร', 'data': [daily_data[day]['profit'] for day in sorted_days], 'borderColor': 'rgba(54, 162, 235, 1)', 'tension': 0.1}
        ]
    }
    return jsonify(chart_data)

@app.route('/accounting')
@login_required
def accounting_page():
    conn = get_db_connection()
    user_id = current_user.id
    orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NULL AND user_id = ? ORDER BY order_date DESC', (user_id,)).fetchall()
    payments = conn.execute('SELECT * FROM payments WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    
    payments_map = {}
    for payment in payments:
        order_id = payment['order_id']
        payments_map[order_id] = payments_map.get(order_id, 0) + payment['amount']

    accounting_data = []
    total_order_costs = 0
    total_paid_amount = 0

    for order in orders:
        order_id = order['order_id']
        total_cost = order['quantity'] * order['cost_per_item']
        paid_amount = payments_map.get(order_id, 0)
        outstanding = total_cost - paid_amount

        accounting_data.append({
            'order_id': order_id,
            'product_details': order['product_details'],
            'factory_sku': order['factory_sku'],
            'order_date': order['order_date'],
            'total_cost': total_cost,
            'paid_amount': paid_amount,
            'outstanding': outstanding
        })
        total_order_costs += total_cost
        total_paid_amount += paid_amount

    total_outstanding = total_order_costs - total_paid_amount
    conn.close()
    
    return render_template('accounting.html', 
                           accounting_data=accounting_data,
                           total_order_costs=total_order_costs,
                           total_paid_amount=total_paid_amount,
                           total_outstanding=total_outstanding)

@app.route('/api/products')
@login_required
def api_products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE deleted_at IS NULL AND user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in products])

@app.route('/api/orders')
@login_required
def api_orders():
    conn = get_db_connection()
    orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NULL AND user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in orders])

@app.route('/submit_order', methods=['POST'])
@login_required
def submit_order():
    product_details_list = request.form.getlist('product_details[]')
    factory_sku_list = request.form.getlist('factory_sku[]')
    quantity_list = request.form.getlist('quantity[]')
    cost_per_item_list = request.form.getlist('cost_per_item[]')

    conn = get_db_connection()
    user_id = current_user.id
    for product_details, factory_sku, quantity, cost_per_item in zip(product_details_list, factory_sku_list, quantity_list, cost_per_item_list):
        if product_details and factory_sku and quantity and cost_per_item:
            conn.execute('INSERT INTO orders (product_details, factory_sku, quantity, cost_per_item, order_date, user_id) VALUES (?, ?, ?, ?, ?, ?)',
                         (product_details, factory_sku, int(quantity), float(cost_per_item), datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()
    flash('คุณได้บันทึกข้อมูล "สั่งซื้อ" เรียบร้อยแล้ว!')
    return redirect(url_for('forms_stock_in'))

@app.route('/submit_stock_in', methods=['POST'])
@login_required
def submit_stock_in():
    product_name_list = request.form.getlist('product_name[]')
    sku_list = request.form.getlist('sku[]')
    factory_sku_list = request.form.getlist('factory_sku[]')
    details_list = request.form.getlist('details[]')
    quantity_list = request.form.getlist('quantity[]')
    group_index_list = request.form.getlist('group_index[]')
    
    conn = get_db_connection()
    user_id = current_user.id
    for main_index, (product_name, sku, factory_sku) in enumerate(zip(product_name_list, sku_list, factory_sku_list)):
        for i, details in enumerate(details_list):
            if i < len(group_index_list) and int(group_index_list[i]) == main_index:
                quantity = quantity_list[i]
                if product_name and sku and factory_sku and details and quantity:
                    quantity_int = int(quantity)
                    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    existing_product = conn.execute('SELECT * FROM products WHERE sku = ? AND details = ? AND user_id = ?', (sku, details, user_id)).fetchone()
                    if existing_product:
                        conn.execute('UPDATE products SET stock = stock + ? WHERE sku = ? AND details = ? AND user_id = ?', (quantity_int, sku, details, user_id))
                    else:
                        conn.execute('INSERT INTO products (name, sku, factory_sku, details, stock, created_at, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                                     (product_name, sku, factory_sku, details, quantity_int, created_at, user_id))
    conn.commit()
    conn.close()
    flash('คุณได้บันทึกข้อมูล "รับของ" เรียบร้อยแล้ว!')
    return redirect(url_for('forms_stock_in'))

@app.route('/submit_stock_out', methods=['POST'])
@login_required
def submit_stock_out():
    sku_list = request.form.getlist('sku[]')
    details_list = request.form.getlist('details[]')
    quantity_list = request.form.getlist('quantity[]')
    price_list = request.form.getlist('price[]')
    group_index_list = request.form.getlist('group_index[]')

    conn = get_db_connection()
    user_id = current_user.id
    for main_index, sku in enumerate(sku_list):
        for i, details in enumerate(details_list):
            if i < len(group_index_list) and int(group_index_list[i]) == main_index:
                quantity = quantity_list[i]
                price = price_list[i]
                if details and quantity and price:
                    quantity_int = int(quantity)
                    price_float = float(price)
                    sale_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    product = conn.execute('SELECT product_id FROM products WHERE sku = ? AND details = ? AND user_id = ?', (sku, details, user_id)).fetchone()
                    if product:
                        product_id = product['product_id']
                        conn.execute('INSERT INTO sales (product_id, quantity, price_per_item, sale_date, user_id) VALUES (?, ?, ?, ?, ?)',
                                     (product_id, quantity_int, price_float, sale_date, user_id))
                        conn.execute('UPDATE products SET stock = stock - ? WHERE product_id = ? AND user_id = ?', (quantity_int, product_id, user_id))
    conn.commit()
    conn.close()
    flash('คุณได้บันทึกข้อมูล "ขายออก" เรียบร้อยแล้ว!')
    return redirect(url_for('forms_stock_out'))

@app.route('/submit_payment', methods=['POST'])
@login_required
def submit_payment():
    order_id = request.form.get('order_id')
    amount = request.form.get('amount')
    payment_date = request.form.get('payment_date')
    
    if not payment_date:
        payment_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    else:
        payment_date = datetime.strptime(payment_date, '%Y-%m-%d').strftime('%Y-%m-%d %H:%M:%S')

    conn = get_db_connection()
    # Check if this order belongs to the current user before inserting payment
    order = conn.execute('SELECT order_id FROM orders WHERE order_id = ? AND user_id = ?', (order_id, current_user.id)).fetchone()
    if order:
        conn.execute('INSERT INTO payments (order_id, amount, payment_date, user_id) VALUES (?, ?, ?, ?)',
                     (order_id, float(amount), payment_date, current_user.id))
        conn.commit()
        flash('บันทึกการชำระเงินเรียบร้อยแล้ว!')
    else:
        flash('ไม่พบ Order ID หรือคุณไม่มีสิทธิ์ในการชำระเงินนี้', 'danger')
    conn.close()
    return redirect(url_for('accounting_page'))
    
@app.route('/data')
@login_required
def data_management():
    conn = get_db_connection()
    user_id = current_user.id
    orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NULL AND user_id = ? ORDER BY order_id DESC', (user_id,)).fetchall()
    products = conn.execute('SELECT * FROM products WHERE deleted_at IS NULL AND user_id = ? ORDER BY product_id DESC', (user_id,)).fetchall()
    sales_with_details = conn.execute('''
        SELECT s.sale_id, p.sku, p.details, s.quantity, s.price_per_item, s.sale_date, s.updated_at
        FROM sales s
        JOIN products p ON s.product_id = p.product_id
        WHERE s.deleted_at IS NULL AND s.user_id = ?
        ORDER BY s.sale_id DESC
    ''', (user_id,)).fetchall()
    conn.close()
    return render_template('data_management.html',
                           orders=orders, products=products, sales_with_details=sales_with_details)

@app.route('/delete/<item_type>/<int:item_id>')
@login_required
def soft_delete(item_type, item_id):
    conn = get_db_connection()
    delete_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    user_id = current_user.id
    if item_type == 'order':
        conn.execute('UPDATE orders SET deleted_at = ? WHERE order_id = ? AND user_id = ?', (delete_time, item_id, user_id))
    elif item_type == 'product':
        conn.execute('UPDATE products SET deleted_at = ? WHERE product_id = ? AND user_id = ?', (delete_time, item_id, user_id))
    elif item_type == 'sale':
        conn.execute('UPDATE sales SET deleted_at = ? WHERE sale_id = ? AND user_id = ?', (delete_time, item_id, user_id))
    conn.commit()
    conn.close()
    flash(f'ลบข้อมูล {item_type} หมายเลข {item_id} สำเร็จ (ย้ายไปถังขยะ)', 'success')
    return redirect(url_for('data_management'))

@app.route('/trash')
@login_required
def trash_bin():
    conn = get_db_connection()
    user_id = current_user.id
    three_days_ago = (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d %H:%M:%S')
    deleted_orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NOT NULL AND deleted_at >= ? AND user_id = ?', (three_days_ago, user_id)).fetchall()
    deleted_products = conn.execute('SELECT * FROM products WHERE deleted_at IS NOT NULL AND deleted_at >= ? AND user_id = ?', (three_days_ago, user_id)).fetchall()
    deleted_sales = conn.execute('SELECT * FROM sales WHERE deleted_at IS NOT NULL AND deleted_at >= ? AND user_id = ?', (three_days_ago, user_id)).fetchall()
    conn.close()
    return render_template('trash.html', orders=deleted_orders, products=deleted_products, sales=deleted_sales)

@app.route('/restore/<item_type>/<int:item_id>')
@login_required
def restore_item(item_type, item_id):
    conn = get_db_connection()
    user_id = current_user.id
    if item_type == 'order':
        conn.execute('UPDATE orders SET deleted_at = NULL WHERE order_id = ? AND user_id = ?', (item_id, user_id))
    elif item_type == 'product':
        conn.execute('UPDATE products SET deleted_at = NULL WHERE product_id = ? AND user_id = ?', (item_id, user_id))
    elif item_type == 'sale':
        conn.execute('UPDATE sales SET deleted_at = NULL WHERE sale_id = ? AND user_id = ?', (item_id, user_id))
    conn.commit()
    conn.close()
    flash(f'กู้คืนข้อมูล {item_type} หมายเลข {item_id} สำเร็จ', 'success')
    return redirect(url_for('trash_bin'))

@app.route('/outstanding')
@login_required
def outstanding_page():
    conn = get_db_connection()
    user_id = current_user.id
    orders = conn.execute('SELECT * FROM orders WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    outstanding_items = []
    for order in orders:
        payments_for_order = conn.execute('SELECT SUM(amount) as total_paid FROM payments WHERE order_id = ? AND user_id = ?', (order['order_id'], user_id)).fetchone()
        total_paid = payments_for_order['total_paid'] if payments_for_order['total_paid'] else 0
        outstanding_amount = (order['quantity'] * order['cost_per_item']) - total_paid
        if outstanding_amount > 0:
            outstanding_items.append({'factory_sku': order['factory_sku'], 'amount': outstanding_amount, 'order_id': order['order_id']})
    conn.close()
    return render_template('outstanding.html', outstanding_items=outstanding_items)

@app.route('/edit/order/<int:order_id>', methods=['GET', 'POST'])
@login_required
def edit_order(order_id):
    conn = get_db_connection()
    user_id = current_user.id
    if request.method == 'POST':
        product_details = request.form['product_details']
        factory_sku = request.form['factory_sku']
        quantity = int(request.form['quantity'])
        cost_per_item = float(request.form['cost_per_item'])
        conn.execute('UPDATE orders SET product_details = ?, factory_sku = ?, quantity = ?, cost_per_item = ?, updated_at = ? WHERE order_id = ? AND user_id = ?',
             (product_details, factory_sku, quantity, cost_per_item, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), order_id, user_id))
        conn.commit()
        conn.close()
        flash('แก้ไขข้อมูล Order สำเร็จ', 'success')
        return redirect(url_for('data_management'))
    
    order = conn.execute('SELECT * FROM orders WHERE order_id = ? AND user_id = ?', (order_id, user_id)).fetchone()
    conn.close()
    if order is None:
        flash('ไม่พบข้อมูล Order หรือคุณไม่มีสิทธิ์เข้าถึง', 'danger')
        return redirect(url_for('data_management'))
    return render_template('edit_order.html', order=order)

@app.route('/edit/product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    conn = get_db_connection()
    user_id = current_user.id
    if request.method == 'POST':
        name = request.form['name']
        sku = request.form['sku']
        factory_sku = request.form['factory_sku']
        details = request.form['details']
        stock = int(request.form['stock'])
        conn.execute('UPDATE products SET name = ?, sku = ?, factory_sku = ?, details = ?, stock = ?, updated_at = ? WHERE product_id = ? AND user_id = ?',
             (name, sku, factory_sku, details, stock, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), product_id, user_id))
        conn.commit()
        conn.close()
        flash('แก้ไขข้อมูล Product สำเร็จ', 'success')
        return redirect(url_for('data_management'))
        
    product = conn.execute('SELECT * FROM products WHERE product_id = ? AND user_id = ?', (product_id, user_id)).fetchone()
    conn.close()
    if product is None:
        flash('ไม่พบข้อมูล Product หรือคุณไม่มีสิทธิ์เข้าถึง', 'danger')
        return redirect(url_for('data_management'))
    return render_template('edit_product.html', product=product)

@app.route('/edit/sale/<int:sale_id>', methods=['GET', 'POST'])
@login_required
def edit_sale(sale_id):
    conn = get_db_connection()
    user_id = current_user.id
    if request.method == 'POST':
        product_id = int(request.form['product_id'])
        quantity = int(request.form['quantity'])
        price_per_item = float(request.form['price_per_item'])
        conn.execute('UPDATE sales SET product_id = ?, quantity = ?, price_per_item = ?, updated_at = ? WHERE sale_id = ? AND user_id = ?',
             (product_id, quantity, price_per_item, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), sale_id, user_id))
        conn.commit()
        conn.close()
        flash('แก้ไขข้อมูล Sale สำเร็จ', 'success')
        return redirect(url_for('data_management'))
        
    sale = conn.execute('SELECT * FROM sales WHERE sale_id = ? AND user_id = ?', (sale_id, user_id)).fetchone()
    products = conn.execute('SELECT * FROM products WHERE deleted_at IS NULL AND user_id = ?', (user_id,)).fetchall()
    conn.close()
    if sale is None:
        flash('ไม่พบข้อมูล Sale หรือคุณไม่มีสิทธิ์เข้าถึง', 'danger')
        return redirect(url_for('data_management'))
    return render_template('edit_sale.html', sale=sale, products=products)

# --- ฟังก์ชันที่ไม่จำเป็นและอาจทำให้เกิดปัญหา ถูกลบออกไป ---
# @app.route('/reset_db')

# --- ส่วนของการรันแอปพลิเคชัน ---
# (ฟอร์มและหน้าอื่นๆ ที่ไม่ได้แสดงในที่นี้ถือว่าไม่มีการเปลี่ยนแปลง)

if __name__ == '__main__':
    # เมื่อรันบน Production จริงๆ ควรใช้ Waitress หรือ Gunicorn แทน app.run()
    # และตั้ง debug=False
    app.run(debug=True)
