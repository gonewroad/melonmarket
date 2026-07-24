import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from flask_socketio import SocketIO, send, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- SECRET_KEY: 환경변수 우선, 없으면 로컬 파일에 랜덤 생성 후 재사용 (git에 올리지 않음) ---
SECRET_KEY_FILE = '.secret_key'
if os.environ.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
elif os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.config['SECRET_KEY'] = f.read().strip()
else:
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    app.config['SECRET_KEY'] = key

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

DATABASE = 'market.db'
REPORT_THRESHOLD = 3
INITIAL_BALANCE = 100000
DEBUG_MODE = os.environ.get('FLASK_DEBUG', '0') == '1'

socketio = SocketIO(app)


# ---------- DB ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                balance INTEGER NOT NULL DEFAULT 100000,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_suspended INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price INTEGER NOT NULL,
                seller_id TEXT NOT NULL,
                is_blocked INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                room TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transfer_log (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- 인증/인가 ----------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if not g.current_user or not g.current_user['is_admin']:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def load_current_user():
    g.current_user = None
    if 'user_id' in session:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        g.current_user = cursor.fetchone()
        if g.current_user and g.current_user['is_suspended']:
            session.pop('user_id', None)
            g.current_user = None
            flash('신고 누적으로 휴면 처리된 계정입니다.')


def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


@app.context_processor
def inject_globals():
    return dict(current_user=g.get('current_user'), csrf_token=get_csrf_token)


def validate_csrf():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(400, description='잘못된 요청입니다 (CSRF 토큰 불일치)')


USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')

def is_valid_username(name):
    return bool(USERNAME_RE.match(name or ''))

def is_valid_password(pw):
    return bool(pw) and 6 <= len(pw) <= 100


# ---------- 라우트 ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        validate_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not is_valid_username(username):
            flash('아이디는 영문/숫자/밑줄 3~20자여야 합니다.')
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash('비밀번호는 6자 이상이어야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        try:
            cursor.execute(
                "INSERT INTO user (id, username, password, balance) VALUES (?, ?, ?, ?)",
                (user_id, username, generate_password_hash(password), INITIAL_BALANCE)
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        validate_csrf()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            if user['is_suspended']:
                flash('신고 누적으로 휴면 처리된 계정입니다.')
                return redirect(url_for('login'))
            session.clear()
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    cursor = db.cursor()
    q = request.args.get('q', '').strip()
    if q:
        like = f'%{q}%'
        cursor.execute(
            "SELECT * FROM product WHERE is_blocked = 0 AND (title LIKE ? OR description LIKE ?) ORDER BY rowid DESC",
            (like, like)
        )
    else:
        cursor.execute("SELECT * FROM product WHERE is_blocked = 0 ORDER BY rowid DESC")
    return render_template('dashboard.html', products=cursor.fetchall(), q=q)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        validate_csrf()
        bio = request.form.get('bio', '')[:500]
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))

        current_pw = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        if new_pw:
            if not check_password_hash(g.current_user['password'], current_pw):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))
            if not is_valid_password(new_pw):
                flash('새 비밀번호는 6자 이상이어야 합니다.')
                return redirect(url_for('profile'))
            cursor.execute("UPDATE user SET password = ? WHERE id = ?",
                           (generate_password_hash(new_pw), session['user_id']))

        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=g.current_user)


@app.route('/users')
@login_required
def user_list():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, bio FROM user WHERE is_suspended = 0 ORDER BY username")
    return render_template('users.html', users=cursor.fetchall())


@app.route('/users/<user_id>')
@login_required
def user_view(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, bio FROM user WHERE id = ? AND is_suspended = 0", (user_id,))
    target = cursor.fetchone()
    if not target:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('user_list'))
    cursor.execute("SELECT * FROM product WHERE seller_id = ? AND is_blocked = 0", (user_id,))
    return render_template('user_view.html', target=target, products=cursor.fetchall())


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
def new_product():
    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()[:100]
        description = request.form.get('description', '').strip()[:2000]

        if not title or not description:
            flash('상품명과 설명을 입력해주세요.')
            return redirect(url_for('new_product'))
        try:
            price = int(request.form.get('price', ''))
            if price < 0 or price > 100_000_000:
                raise ValueError
        except ValueError:
            flash('가격은 0 이상의 숫자로 입력해주세요.')
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    is_owner = 'user_id' in session and session['user_id'] == product['seller_id']
    is_admin = bool(g.current_user and g.current_user['is_admin'])
    if product['is_blocked'] and not (is_owner or is_admin):
        flash('신고 누적으로 차단된 상품입니다.')
        return redirect(url_for('dashboard'))

    cursor.execute("SELECT id, username, bio FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller, is_owner=is_owner)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] != session['user_id']:
        abort(403)

    if request.method == 'POST':
        validate_csrf()
        title = request.form.get('title', '').strip()[:100]
        description = request.form.get('description', '').strip()[:2000]
        try:
            price = int(request.form.get('price', ''))
            if price < 0 or price > 100_000_000:
                raise ValueError
        except ValueError:
            flash('가격은 0 이상의 숫자로 입력해주세요.')
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute(
            "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ? AND seller_id = ?",
            (title, description, price, product_id, session['user_id'])
        )
        db.commit()
        flash('상품 정보가 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    validate_csrf()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] != session['user_id'] and not (g.current_user and g.current_user['is_admin']):
        abort(403)
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))


@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        validate_csrf()
        receiver_username = request.form.get('receiver', '').strip()
        try:
            amount = int(request.form.get('amount', ''))
        except ValueError:
            flash('송금액은 숫자로 입력해주세요.')
            return redirect(url_for('transfer'))

        if amount <= 0:
            flash('송금액은 0보다 커야 합니다.')
            return redirect(url_for('transfer'))

        cursor.execute("SELECT * FROM user WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash('받는 사람을 찾을 수 없습니다.')
            return redirect(url_for('transfer'))
        if receiver['id'] == session['user_id']:
            flash('자기 자신에게는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute("SELECT balance FROM user WHERE id = ?", (session['user_id'],))
        sender_balance = cursor.fetchone()['balance']
        if sender_balance < amount:
            db.rollback()
            flash('잔액이 부족합니다.')
            return redirect(url_for('transfer'))

        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, session['user_id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        cursor.execute(
            "INSERT INTO transfer_log (id, sender_id, receiver_id, amount, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session['user_id'], receiver['id'], amount, now_iso())
        )
        db.commit()
        flash(f'{receiver_username}님에게 {amount}원을 송금했습니다.')
        return redirect(url_for('profile'))

    cursor.execute(
        "SELECT * FROM transfer_log WHERE sender_id = ? OR receiver_id = ? ORDER BY created_at DESC LIMIT 20",
        (session['user_id'], session['user_id'])
    )
    return render_template('transfer.html', history=cursor.fetchall())


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        validate_csrf()
        target_id = request.form.get('target_id', '').strip()
        reason = request.form.get('reason', '').strip()[:500]
        if not target_id or not reason:
            flash('신고 대상과 사유를 입력해주세요.')
            return redirect(url_for('report'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM product WHERE id = ?", (target_id,))
        target_product = cursor.fetchone()
        cursor.execute("SELECT id FROM user WHERE id = ?", (target_id,))
        target_user = cursor.fetchone()

        if not target_product and not target_user:
            flash('신고 대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))

        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), session['user_id'], target_id, reason, now_iso())
        )
        cursor.execute("SELECT COUNT(*) as cnt FROM report WHERE target_id = ?", (target_id,))
        count = cursor.fetchone()['cnt']

        if count >= REPORT_THRESHOLD:
            if target_product:
                cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
            elif target_user:
                cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ?", (target_id,))

        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('report.html', target_id=request.args.get('target_id', ''))


@app.route('/chat')
@login_required
def chat_lobby():
    return render_template('chat_lobby.html')


@app.route('/chat/<other_id>')
@login_required
def chat_private(other_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (other_id,))
    other = cursor.fetchone()
    if not other:
        abort(404)
    room = '_'.join(sorted([session['user_id'], other_id]))
    cursor.execute("SELECT * FROM chat_message WHERE room = ? ORDER BY created_at ASC LIMIT 200", (room,))
    return render_template('chat_private.html', other=other, room=room, history=cursor.fetchall())


@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user ORDER BY username")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM product ORDER BY rowid DESC")
    products = cursor.fetchall()
    cursor.execute("SELECT * FROM report ORDER BY created_at DESC LIMIT 100")
    reports = cursor.fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@app.route('/admin/user/<user_id>/toggle_suspend', methods=['POST'])
@admin_required
def admin_toggle_suspend(user_id):
    validate_csrf()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_suspended FROM user WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    cursor.execute("UPDATE user SET is_suspended = ? WHERE id = ?", (0 if row['is_suspended'] else 1, user_id))
    db.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/toggle_block', methods=['POST'])
@admin_required
def admin_toggle_block(product_id):
    validate_csrf()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT is_blocked FROM product WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    cursor.execute("UPDATE product SET is_blocked = ? WHERE id = ?", (0 if row['is_blocked'] else 1, product_id))
    db.commit()
    return redirect(url_for('admin_dashboard'))


# ---------- 실시간 채팅 ----------
@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        return
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    row = cursor.fetchone()
    send({
        'message_id': str(uuid.uuid4()),
        'username': row['username'] if row else 'unknown',
        'message': (data.get('message') or '')[:1000]
    }, broadcast=True)


@socketio.on('join_private')
def handle_join_private(data):
    if 'user_id' not in session:
        return
    room = data.get('room', '')
    if session['user_id'] not in room.split('_'):
        return
    join_room(room)


@socketio.on('send_private_message')
def handle_send_private_message(data):
    if 'user_id' not in session:
        return
    room = data.get('room', '')
    if session['user_id'] not in room.split('_'):
        return
    message = (data.get('message') or '')[:1000]
    if not message:
        return
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (session['user_id'],))
    username = cursor.fetchone()['username']
    msg_id = str(uuid.uuid4())
    created_at = now_iso()
    cursor.execute(
        "INSERT INTO chat_message (id, room, sender_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (msg_id, room, session['user_id'], message, created_at)
    )
    db.commit()
    emit('receive_private_message', {
        'message_id': msg_id, 'sender_id': session['user_id'],
        'username': username, 'message': message, 'created_at': created_at
    }, room=room)


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=DEBUG_MODE)