import os
import io
import csv
import jwt
import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", template_folder="static")
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'finedge-jwt-production-secret-2026')
database_url = os.environ.get('DATABASE_URL', 'sqlite:///finedge.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), default='General')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ExpenseSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_owed = db.Column(db.Float, nullable=False)

# --- JWT Middleware ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Authentication token missing'}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'error': 'User session invalid'}), 401
        except Exception:
            return jsonify({'error': 'Token has expired or is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- Frontend Serving ---
@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join('static', path)):
        return send_from_directory('static', path)
    return send_from_directory('static', 'index.html')

# --- Auth APIs ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not name or not email or not password:
        return jsonify({'error': 'Name, email, and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email address already registered'}), 409

    hashed_pw = generate_password_hash(password)
    user = User(name=name, email=email, password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials provided'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'token': token,
        'user': {'id': user.id, 'name': user.name, 'email': user.email}
    }), 200

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([{'id': u.id, 'name': u.name, 'email': u.email} for u in users]), 200

# --- Expense APIs ---
@app.route('/api/expenses', methods=['GET'])
@token_required
def get_expenses(current_user):
    expenses = Expense.query.order_by(Expense.created_at.desc()).all()
    result = []
    for exp in expenses:
        payer = User.query.get(exp.payer_id)
        splits = ExpenseSplit.query.filter_by(expense_id=exp.id).all()
        splits_detail = []
        for s in splits:
            u = User.query.get(s.user_id)
            splits_detail.append({
                'user_id': s.user_id,
                'name': u.name if u else 'Unknown',
                'amount': round(s.amount_owed, 2)
            })
        result.append({
            'id': exp.id,
            'title': exp.title,
            'total_amount': round(exp.total_amount, 2),
            'category': exp.category,
            'payer_name': payer.name if payer else 'Unknown',
            'created_at': exp.created_at.strftime('%Y-%m-%d %H:%M'),
            'splits': splits_detail
        })
    return jsonify(result), 200

@app.route('/api/expenses', methods=['POST'])
@token_required
def create_expense(current_user):
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    total_amount = float(data.get('total_amount', 0))
    category = data.get('category', 'General')
    splits = data.get('splits', [])

    if not title or total_amount <= 0 or not splits:
        return jsonify({'error': 'Valid title, amount and split participants required'}), 400

    sum_splits = sum(float(item.get('amount', 0)) for item in splits)
    if abs(sum_splits - total_amount) > 0.05:
        return jsonify({'error': f'Split allocation sum ({sum_splits}) must match total ({total_amount})'}), 422

    try:
        new_expense = Expense(
            title=title,
            total_amount=total_amount,
            payer_id=current_user.id,
            category=category
        )
        db.session.add(new_expense)
        db.session.flush()

        for s in splits:
            entry = ExpenseSplit(
                expense_id=new_expense.id,
                user_id=int(s['user_id']),
                amount_owed=float(s['amount'])
            )
            db.session.add(entry)

        db.session.commit()
        return jsonify({'message': 'Expense recorded successfully', 'expense_id': new_expense.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Transaction aborted', 'details': str(e)}), 500

# --- Advanced Analytics Endpoints ---
@app.route('/api/analytics', methods=['GET'])
@token_required
def get_analytics(current_user):
    # Category aggregation
    category_rows = db.session.query(
        Expense.category,
        db.func.sum(Expense.total_amount).label('total'),
        db.func.count(Expense.id).label('count')
    ).group_by(Expense.category).all()

    category_breakdown = [
        {'category': cat or 'General', 'total': round(float(tot or 0), 2), 'count': cnt}
        for cat, tot, cnt in category_rows
    ]

    # Daily spending trajectory (last 7 recorded days)
    daily_rows = db.session.query(
        db.func.date(Expense.created_at).label('date_str'),
        db.func.sum(Expense.total_amount).label('total')
    ).group_by(db.func.date(Expense.created_at)).order_by(db.func.date(Expense.created_at).desc()).limit(7).all()

    daily_trend = [
        {'date': str(d), 'amount': round(float(amt or 0), 2)}
        for d, amt in reversed(daily_rows)
    ]

    # Overall Metrics
    total_spend = db.session.query(db.func.sum(Expense.total_amount)).scalar() or 0.0
    total_paid_user = db.session.query(db.func.sum(Expense.total_amount))        .filter(Expense.payer_id == current_user.id).scalar() or 0.0
    total_owed_user = db.session.query(db.func.sum(ExpenseSplit.amount_owed))        .filter(ExpenseSplit.user_id == current_user.id).scalar() or 0.0

    return jsonify({
        'total_platform_spend': round(total_spend, 2),
        'user_paid': round(total_paid_user, 2),
        'user_owed': round(total_owed_user, 2),
        'user_net': round(total_paid_user - total_owed_user, 2),
        'categories': category_breakdown,
        'daily_trend': daily_trend
    }), 200

# --- Algorithmic Debt Settlement Engine (Greedy Min-Cash Flow) ---
@app.route('/api/settlements', methods=['GET'])
@token_required
def get_settlements(current_user):
    users = User.query.all()
    user_names = {u.id: u.name for u in users}
    
    # Compute net balance for every single user
    net_balances = {u.id: 0.0 for u in users}

    # Add money paid by users
    for exp in Expense.query.all():
        net_balances[exp.payer_id] = net_balances.get(exp.payer_id, 0.0) + exp.total_amount

    # Deduct money owed by users
    for split in ExpenseSplit.query.all():
        net_balances[split.user_id] = net_balances.get(split.user_id, 0.0) - split.amount_owed

    # Separate into debtors and creditors
    debtors = []   # net < 0 (owes money)
    creditors = [] # net > 0 (owed money)

    for uid, bal in net_balances.items():
        rounded_bal = round(bal, 2)
        if rounded_bal < -0.01:
            debtors.append({'user_id': uid, 'name': user_names.get(uid, f"User {uid}"), 'amount': -rounded_bal})
        elif rounded_bal > 0.01:
            creditors.append({'user_id': uid, 'name': user_names.get(uid, f"User {uid}"), 'amount': rounded_bal})

    # Greedy settlement matching
    settlements = []
    i = 0
    j = 0

    while i < len(debtors) and j < len(creditors):
        debtor = debtors[i]
        creditor = creditors[j]

        settle_amt = min(debtor['amount'], creditor['amount'])
        settle_amt = round(settle_amt, 2)

        if settle_amt > 0.01:
            settlements.append({
                'from_user': debtor['name'],
                'to_user': creditor['name'],
                'amount': settle_amt
            })

        debtor['amount'] = round(debtor['amount'] - settle_amt, 2)
        creditor['amount'] = round(creditor['amount'] - settle_amt, 2)

        if debtor['amount'] <= 0.01:
            i += 1
        if creditor['amount'] <= 0.01:
            j += 1

    return jsonify({
        'simplified_settlements': settlements,
        'total_transfers_needed': len(settlements)
    }), 200

# --- CSV Statement Export API ---
@app.route('/api/reports/csv', methods=['GET'])
@token_required
def export_csv(current_user):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Category', 'Total Amount (INR)', 'Payer', 'Created Date'])

    expenses = Expense.query.order_by(Expense.created_at.desc()).all()
    for exp in expenses:
        payer = User.query.get(exp.payer_id)
        writer.writerow([
            exp.id,
            exp.title,
            exp.category,
            f"{exp.total_amount:.2f}",
            payer.name if payer else 'Unknown',
            exp.created_at.strftime('%Y-%m-%d %H:%M')
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=finedge_expenses_report.csv"}
    )

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
