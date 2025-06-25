import dash
from dash import dcc, html, Input, Output, State, dash_table, callback_context
import plotly.express as px
import pandas as pd
import random
from datetime import datetime, timedelta
import threading
import time
from sklearn.metrics import confusion_matrix, roc_curve, auc
import plotly.figure_factory as ff
import numpy as np
import requests
from flask import request, jsonify, render_template_string, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
import paho.mqtt.client as mqtt
import json

# Enhanced Geolocation Functions
def is_private_ip(ip):
    private_ranges = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255')
    ]
    ip_int = int(''.join(f"{int(octet):02x}" for octet in ip.split('.')), 16)
    for start, end in private_ranges:
        start_int = int(''.join(f"{int(octet):02x}" for octet in start.split('.')), 16)
        end_int = int(''.join(f"{int(octet):02x}" for octet in end.split('.')), 16)
        if start_int <= ip_int <= end_int:
            return True
    return False

def lookup_ip(ip):
    if is_private_ip(ip):
        return {
            'country': 'India',
            'region': 'Tamil Nadu',
            'city': 'Pondicherry',
            'org': 'Private',
            'lat': 11.9416,
            'lon': 79.8083
        }
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data.get('status') == 'fail':
            raise ValueError("Geolocation lookup failed")
        return {
            'country': data.get('country', 'Unknown'),
            'region': data.get('regionName', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'org': data.get('org', 'Unknown'),
            'lat': data.get('lat', 11.9416),
            'lon': data.get('lon', 79.8083)
        }
    except Exception:
        return {
            'country': 'India',
            'region': 'Tamil Nadu',
            'city': 'Pondicherry',
            'org': 'Unknown',
            'lat': 11.9416,
            'lon': 79.8083
        }

# Initialize Dash app
app = dash.Dash(__name__)
server = app.server
app.config.suppress_callback_exceptions = True

# ======== AUTHENTICATION SETUP ======== #
server.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = '/login'

@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/login')

class User(UserMixin):
    def __init__(self, id, username, password, role='analyst'):
        self.id = id
        self.username = username
        self.password_hash = generate_password_hash(password)
        self.role = role
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

users = {
    'admin': User(id='1', username='admin', password='admin123', role='supervisor'),
    'analyst': User(id='2', username='analyst', password='analyst123', role='analyst')
}

@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

@server.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or '/')
        else:
            error = 'Invalid username or password'
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IoT Security Dashboard - Login</title>
        <style>
            :root {
                --primary: #3498db;
                --danger: #e74c3c;
                --dark: #2c3e50;
                --light: #ecf0f1;
            }
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            body {
                background: #000000;
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .login-container {
                background: white;
                border-radius: 10px;
                box-shadow: 0 15px 30px rgba(0, 0, 0, 0.2);
                width: 400px;
                padding: 40px;
                animation: fadeIn 0.5s ease-in-out;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-20px); }
                to { opacity: 1; transform: translateY(0); }
            }
            .login-header {
                text-align: center;
                margin-bottom: 30px;
            }
            .login-header h1 {
                color: #ff2e63;
                text-shadow: 0 0 10px rgba(255, 46, 99, 0.5);
                font-size: 28px;
                margin-bottom: 10px;
            }
            .login-header img {
                width: 80px;
                height: 80px;
                margin-bottom: 15px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-group label {
                display: block;
                margin-bottom: 8px;
                color: var(--dark);
                font-weight: 500;
            }
            .form-control {
                width: 100%;
                padding: 12px 15px;
                border: 1px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                transition: border 0.3s;
            }
            .form-control:focus {
                border-color: var(--primary);
                outline: none;
            }
            .btn {
                width: 100%;
                padding: 12px;
                background-color: var(--primary);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
                transition: background-color 0.3s;
            }
            .btn:hover {
                background-color: #2980b9;
            }
            .alert {
                padding: 12px;
                border-radius: 5px;
                margin-bottom: 20px;
                text-align: center;
            }
            .alert-danger {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .footer {
                text-align: center;
                margin-top: 20px;
                color: #7f8c8d;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <img src="https://cdn-icons-png.flaticon.com/512/2285/2285533.png" alt="Security Shield">
                <h1>IoT Security Dashboard</h1>
                <p>Please sign in to continue</p>
            </div>
            
            {% if error %}
            <div class="alert alert-danger">
                {{ error }}
            </div>
            {% endif %}
            
            <form method="post">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">Sign In</button>
            </form>
            
            <div class="footer">
                <p>© 2025 IoT Security System</p>
            </div>
        </div>
    </body>
    </html>
    ''', error=error)

@server.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'supervisor':
            return "Unauthorized - Admin access required", 403
        return f(*args, **kwargs)
    return decorated_function

@server.before_request
def restrict_dashboard():
    if (not current_user.is_authenticated and 
        request.endpoint and 
        request.endpoint != 'login' and 
        not request.path.startswith(('/_', '/log_attack', '/download_logs'))):
        return redirect(url_for('login', next=request.path))

# ======== DASHBOARD FUNCTIONALITY ======== #
live_data = []
live_data_lock = threading.Lock()
last_attack_expiry = datetime.now()

BACKGROUND_TRAFFIC_INTERVAL = 1  # Seconds
ATTACK_DISPLAY_DURATION = 15    # Seconds

latest_ip = "127.0.0.1"
current_attack = None
block_state = {'blocked': False}  # Global block state for thread access

# MQTT Setup
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker with code 0")
        client.subscribe("iot/attack")
        print("Subscribed to topic: iot/attack")
    else:
        print(f"Failed to connect to MQTT broker with code {rc}")

def on_message(client, userdata, msg):
    global current_attack, last_attack_expiry, latest_ip
    try:
        payload = msg.payload.decode('utf-8')
        data = json.loads(payload)
        print(f"Received MQTT message: {data} on topic {msg.topic} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if block_state['blocked']:
            print("MQTT attack blocked due to active IP blocking")
            return

        attack_entry = {
            'timestamp': datetime.fromisoformat(data['timestamp']),
            'src_bytes': data['src_bytes'],
            'dst_bytes': data['dst_bytes'],
            'count': data['count'],
            'predictions': data.get('prediction', -1),
            'attack_type': data['attack_label'],
            'source_ip': data.get('source_ip', '127.0.0.1'),
            'is_attack': True,
            **lookup_ip(data.get('source_ip', '127.0.0.1'))
        }
        
        with live_data_lock:
            live_data.append(attack_entry)
            current_attack = attack_entry['attack_type']
            latest_ip = attack_entry['source_ip']
            last_attack_expiry = datetime.now() + timedelta(seconds=ATTACK_DISPLAY_DURATION)
        
        print(f"Processed MQTT attack: {attack_entry['attack_type']} from {attack_entry['source_ip']}")
    except Exception as e:
        print(f"Error processing MQTT message: {e}")

mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message

def start_mqtt_client():
    mqtt_client.connect("localhost", 1883, 60)
    mqtt_client.loop_forever()

mqtt_thread = threading.Thread(target=start_mqtt_client)
mqtt_thread.daemon = True
mqtt_thread.start()

def generate_background_traffic():
    global current_attack
    while True:
        now = datetime.now()
        src = random.randint(100, 2000)
        dst = random.randint(100, 2000)
        count = random.randint(1, 100)
        proto = random.choice(['tcp', 'udp'])
        serv = random.choice(['http', 'dns', 'ftp'])
        flag = random.choice(['SF', 'REJ'])

        payload = {
            'src_bytes': src,
            'dst_bytes': dst,
            'count': count,
            'protocol': proto,
            'service': serv,
            'flag': flag
        }

        try:
            response = requests.post("http://127.0.0.1:8081/predict", json=payload, timeout=2)
            result = response.json()
            label = result.get('label', 'Unknown')
            pred_class = result.get('prediction', -1)
        except Exception as e:
            label = f"Error: {e}"
            pred_class = -1

        # Only append non-attack traffic if not blocked
        if block_state['blocked'] and pred_class == 1:
            time.sleep(BACKGROUND_TRAFFIC_INTERVAL)
            continue

        new_entry = {
            'timestamp': now,
            'src_bytes': src,
            'dst_bytes': dst,
            'count': count,
            'predictions': pred_class,
            'attack_type': label,
            'source_ip': latest_ip,
            'is_attack': pred_class == 1,
            **lookup_ip(latest_ip)
        }

        with live_data_lock:
            live_data.append(new_entry)
        
        time.sleep(BACKGROUND_TRAFFIC_INTERVAL)

@server.route('/log_attack', methods=['POST'])
def log_attack():
    global current_attack, last_attack_expiry, latest_ip
    
    if block_state['blocked']:
        return jsonify({'status': 'blocked', 'message': 'Attack blocked due to active IP blocking'}), 200

    try:
        data = request.json
        attack_entry = {
            'timestamp': datetime.fromisoformat(data['timestamp']),
            'src_bytes': data['src_bytes'],
            'dst_bytes': data['dst_bytes'],
            'count': data['count'],
            'predictions': data.get('prediction', -1),
            'attack_type': data['attack_label'],
            'source_ip': data.get('source_ip', '127.0.0.1'),
            'is_attack': True,
            **lookup_ip(data.get('source_ip', '127.0.0.1'))
        }
        
        with live_data_lock:
            live_data.append(attack_entry)
            current_attack = attack_entry['attack_type']
            latest_ip = attack_entry['source_ip']
            last_attack_expiry = datetime.now() + timedelta(seconds=ATTACK_DISPLAY_DURATION)

        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@server.route('/history')
@login_required
@admin_required
def history_page():
    with live_data_lock:
        attacks = [entry for entry in reversed(live_data) if entry.get('is_attack')]
        last_10_attacks = attacks[:10]

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack History</title>
        <style>
            body {
                font-family: 'Segoe UI', Arial, sans-serif;
                background-color: #0f0f1a;
                color: #ecf0f1;
                padding: 20px;
            }
            h1 {
                text-align: center;
                color: #ff2e63;
                margin-bottom: 30px;
                text-shadow: 0 0 5px rgba(255, 46, 99, 0.5);
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                background-color: #1a1a2e;
                border-radius: 8px;
                overflow: hidden;
            }
            th, td {
                padding: 12px;
                border: 1px solid #2d2d3f;
                text-align: center;
            }
            th {
                background-color: #2c2c3f;
                font-weight: bold;
                color: #ffffff;
            }
            tr:nth-child(even) {
                background-color: #252535;
            }
            a {
                color: #17a2b8;
                text-decoration: none;
                display: inline-block;
                margin-bottom: 20px;
                transition: color 0.3s;
            }
            a:hover {
                color: #2bc4db;
            }
            .admin-badge {
                background-color: #dc3545;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 10px;
            }
        </style>
    </head>
    <body>
        <h1>🛡 Attack Logs History <span class="admin-badge">ADMIN</span></h1>
        <a href='/'>⬅ Back to Dashboard</a>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Attack Type</th>
                <th>Source IP</th>
                <th>Country</th>
                <th>City</th>
                <th>Src Bytes</th>
                <th>Dst Bytes</th>
                <th>Count</th>
            </tr>
            {% for attack in attacks %}
            <tr>
                <td>{{ attack.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                <td>{{ attack.attack_type }}</td>
                <td>{{ attack.source_ip }}</td>
                <td>{{ attack.country }}</td>
                <td>{{ attack.city }}</td>
                <td>{{ attack.src_bytes }}</td>
                <td>{{ attack.dst_bytes }}</td>
                <td>{{ attack.count }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """
    return render_template_string(html_template, attacks=last_10_attacks)

@server.route('/download_logs')
@login_required
@admin_required
def download_logs():
    with live_data_lock:
        if not live_data:
            return "No data to export", 404
        df = pd.DataFrame(live_data)
    csv = df.to_csv(index=False)
    return csv, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=attack_logs.csv"
    }

traffic_thread = threading.Thread(target=generate_background_traffic)
traffic_thread.daemon = True
traffic_thread.start()

# Dashboard layout
def create_layout():
    layout_elements = [
        html.H1('Real-Time IoT Attack Detection Dashboard', style={
            'textAlign': 'center',
            'color': '#ff2e63',
            'textShadow': '0 0 10px rgba(255, 46, 99, 0.5)',
            'marginBottom': '20px'
        }),
        html.Div([
            html.Span(f"Logged in as: {current_user.username} ({current_user.role})", style={
                'marginRight': '20px',
                'fontWeight': 'bold',
                'color': '#ecf0f1'
            }),
            html.A('🔒 Logout', href='/logout', style={
                'padding': '10px 20px',
                'backgroundColor': '#6c757d',
                'color': '#ffffff',
                'borderRadius': '5px',
                'textDecoration': 'none',
                'transition': 'all 0.3s ease',
                'margin': '0 10px'
            })
        ], style={'textAlign': 'right', 'marginBottom': '20px'}),
        html.Div([
            html.A('📊 Attack History', href='/history', target='_blank', style={
                'display': 'inline-block' if current_user.role == 'supervisor' else 'none',
                'margin': '0 10px',
                'padding': '10px 20px',
                'backgroundColor': '#007bff',
                'color': '#ffffff',
                'borderRadius': '5px',
                'textDecoration': 'none',
                'transition': 'all 0.3s ease'
            }),
            html.A('⬇ Export Logs', href='/download_logs', target='_blank', style={
                'display': 'inline-block' if current_user.role == 'supervisor' else 'none',
                'margin': '0 10px',
                'padding': '10px 20px',
                'backgroundColor': '#28a745',
                'color': '#ffffff',
                'borderRadius': '5px',
                'textDecoration': 'none',
                'transition': 'all 0.3s ease'
            })
        ], style={'textAlign': 'right', 'marginTop': '10px', 'marginBottom': '20px'}),
        dcc.Graph(id='live-traffic-graph', style={'height': '500px', 'marginBottom': '20px'}),
        html.Div(id="predicted-traffic", style={
            'fontSize': '20px',
            'padding': '10px',
            'backgroundColor': '#1a1a2e',
            'borderRadius': '5px',
            'margin': '10px',
            'color': '#ecf0f1'
        }),
        html.Div(id='attack-alert', children="Initializing...", style={
            'fontSize': '24px',
            'fontWeight': 'bold',
            'padding': '20px',
            'textAlign': 'center',
            'color': '#ecf0f1'
        }),
        html.Div([
            html.Div([
                html.H3("Total Attacks Detected", style={'textAlign': 'center', 'color': '#ecf0f1'}),
                html.H2(id='total-attacks', style={
                    'textAlign': 'center',
                    'color': '#dc3545',
                    'fontSize': '3rem'
                })
            ], style={'width': '30%', 'padding': '10px'}),
            dcc.Graph(id='attack-pie', style={'width': '70%', 'height': '300px'})
        ], style={'display': 'flex', 'marginBottom': '20px'}),
        dcc.Graph(id='live-geo-map', style={'height': '400px', 'marginBottom': '20px'}),
        html.Div([
            dcc.Graph(id='confusion-matrix', style={'width': '49%', 'display': 'inline-block'}),
            dcc.Graph(id='roc-curve', style={'width': '49%', 'display': 'inline-block'})
        ], style={'marginBottom': '20px'}),
        html.Div([
            html.Button('Block Suspicious IPs', id='block-button', n_clicks=0, style={
                'display': 'inline-block' if current_user.role == 'supervisor' else 'none',
                'backgroundColor': '#dc3545',
                'color': '#ffffff',
                'padding': '15px 30px',
                'border': 'none',
                'borderRadius': '5px',
                'margin': '10px',
                'cursor': 'pointer',
                'transition': 'background-color 0.3s'
            }),
            html.Button('Explain Latest Prediction', id='explain-button', n_clicks=0, style={
                'backgroundColor': '#17a2b8',
                'color': '#ffffff',
                'padding': '15px 30px',
                'border': 'none',
                'borderRadius': '5px',
                'margin': '10px',
                'cursor': 'pointer',
                'transition': 'background-color 0.3s'
            })
        ], style={'display': 'flex', 'justifyContent': 'center', 'margin': '20px'}),
        html.Div(id='block-status', style={'fontSize': '16px', 'color': '#6c757d'}),
        html.Div(id='explanation-output', style={'display': 'none', 'padding': '20px', 'marginTop': '20px', 'backgroundColor': '#1a1a2e', 'color': '#ecf0f1'}),
        dcc.Interval(id='interval-component', interval=1000, n_intervals=0),
        dcc.Store(id='block-state', data={'blocked': False})
    ]
    
    return html.Div(layout_elements, style={
        'padding': '20px',
        'fontFamily': 'Segoe UI, Arial',
        'backgroundColor': '#0f0f1a',
        'color': '#ecf0f1',
        'minHeight': '100vh'
    })

app.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    html.Div(id='page-content')
], style={
    'backgroundColor': '#0f0f1a',
    'minHeight': '100vh'
})

@app.callback(Output('page-content', 'children'),
              [Input('url', 'pathname')])
def display_page(pathname):
    if not current_user.is_authenticated:
        return redirect('/login')
    return create_layout()

@app.callback(
    [Output('block-state', 'data'),
     Output('block-button', 'children'),
     Output('block-status', 'children')],
    [Input('block-button', 'n_clicks')],
    [State('block-state', 'data')]
)
def toggle_block(n_clicks, data):
    global block_state
    if current_user.role != 'supervisor':
        return data, 'Block IPs', "Unauthorized - Analyst cannot block IPs"
    
    blocked = data.get('blocked', False)
    if n_clicks > 0:
        blocked = not blocked
        block_state['blocked'] = blocked  # Update global block state
        button_text = 'Unblock IPs' if blocked else 'Block IPs'
        status = "🛡 Blocking Active - Alerts Suppressed" if blocked else "🟢 Blocking Inactive - Monitoring"
        return {'blocked': blocked}, button_text, status
    return data, 'Block IPs', "System Status: Monitoring"

@app.callback(
    [Output('live-traffic-graph', 'figure'),
     Output('attack-alert', 'children'),
     Output('predicted-traffic', 'children'),
     Output('total-attacks', 'children'),
     Output('attack-pie', 'figure'),
     Output('live-geo-map', 'figure')],
    [Input('interval-component', 'n_intervals')],
    [State('block-state', 'data')]
)
def update_dashboard(n, block_state):
    global current_attack, last_attack_expiry
    
    with live_data_lock:
        if not live_data:
            empty_df = pd.DataFrame(columns=['timestamp', 'src_bytes'])
            empty_fig = px.line(empty_df, x='timestamp', y='src_bytes')
            empty_fig.update_layout(template='plotly_dark')
            empty_pie = px.pie(values=[1], names=['No Attacks'], title='Attack Distribution', hole=0.3)
            empty_pie.update_layout(
                template='plotly_dark',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#ecf0f1')
            )
            empty_geo = px.scatter_geo(title='🌍 Global Attack Origins', projection='natural earth')
            empty_geo.update_layout(
                template='plotly_dark',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#ecf0f1'),
                geo=dict(
                    showland=True,
                    landcolor='rgb(40, 40, 40)',
                    countrycolor='rgb(80, 80, 80)',
                    showocean=True,
                    oceancolor='rgb(20, 20, 50)'
                )
            )
            return (empty_fig, "🔍 Initializing system...", "No traffic data yet", "0", empty_pie, empty_geo)
        
        live_df = pd.DataFrame(live_data[-200:])
    
    current_time = datetime.now()
    alert_text = "✅ No Attacks Detected"
    alert_style = {'color': '#28a745'}
    
    if current_time < last_attack_expiry and current_attack:
        alert_text = f"🚨 {current_attack} Detected from {latest_ip}!"
        alert_style = {'color': '#dc3545', 'animation': 'blinker 1.5s linear infinite'}
    
    if block_state.get('blocked', False) and current_user.role == 'supervisor':
        alert_text = "🛡 Active Protection - No Alerts"
        alert_style = {'color': '#ffc107'}

    fig = px.line(live_df, x='timestamp', y='src_bytes', color='is_attack',
                  title='Live Traffic Monitoring',
                  labels={'src_bytes': 'Data Volume (bytes)', 'timestamp': 'Time'},
                  color_discrete_map={True: '#dc3545', False: '#007bff'})
    
    fig.update_layout(
        template='plotly_dark',
        hovermode='x unified',
        showlegend=False,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ecf0f1')
    )

    last_traffic = live_df['src_bytes'].iloc[-1] if not live_df.empty else 0
    traffic_text = f"📶 Current Traffic: {last_traffic} bytes/s | Total Entries: {len(live_df)}"

    # Total Attacks Detected
    attack_df = live_df[live_df['is_attack']].copy()
    total_attacks = len(attack_df)

    # Attack Distribution Pie Chart
    if not attack_df.empty:
        attack_pie = px.pie(attack_df, names='attack_type', title='Attack Distribution', hole=0.3)
        attack_pie.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ecf0f1')
        )
    else:
        attack_pie = px.pie(values=[1], names=['No Attacks'], title='Attack Distribution', hole=0.3)
        attack_pie.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ecf0f1')
        )

    # Global Attack Origins Map
    if not attack_df.empty and 'lat' in attack_df.columns and 'lon' in attack_df.columns:
        geo_fig = px.scatter_geo(
            attack_df.dropna(subset=['lat', 'lon']).query('lat != 0 and lon != 0'),
            lat='lat',
            lon='lon',
            hover_name='source_ip',
            color='attack_type',
            title='🌍 Global Attack Origins',
            projection='natural earth'
        )
        geo_fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ecf0f1'),
            geo=dict(
                showland=True,
                landcolor='rgb(40, 40, 40)',
                countrycolor='rgb(80, 80, 80)',
                showocean=True,
                oceancolor='rgb(20, 20, 50)'
            )
        )
    else:
        geo_fig = px.scatter_geo(title='🌍 Global Attack Origins', projection='natural earth')
        geo_fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ecf0f1'),
            geo=dict(
                showland=True,
                landcolor='rgb(40, 40, 40)',
                countrycolor='rgb(80, 80, 80)',
                showocean=True,
                oceancolor='rgb(20, 20, 50)'
            )
        )

    return (fig, html.Div(alert_text, style=alert_style), traffic_text, str(total_attacks), attack_pie, geo_fig)

@app.callback(
    [Output('explanation-output', 'children'),
     Output('explanation-output', 'style')],
    [Input('explain-button', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('explanation-output', 'style')]
)
def update_explanation(n_clicks, n_intervals, current_style):
    ctx = callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0]

    # Determine if explanation should be visible
    is_visible = current_style.get('display', 'none') == 'block'
    if triggered_id == 'explain-button':
        is_visible = not is_visible if n_clicks > 0 else is_visible

    if not is_visible:
        return '', {'display': 'none', 'padding': '20px', 'marginTop': '20px', 'backgroundColor': '#1a1a2e', 'color': '#ecf0f1'}

    # Update explanation with latest data
    with live_data_lock:
        if not live_data:
            return html.Div("No prediction data available."), {
                'display': 'block',
                'padding': '20px',
                'marginTop': '20px',
                'backgroundColor': '#1a1a2e',
                'color': '#ecf0f1'
            }
        latest_entry = live_data[-1]

    # Mock SHAP and LIME explanations
    shap_explanation = [
        {"feature": "src_bytes", "contribution": random.uniform(0.1, 0.5), "value": latest_entry['src_bytes']},
        {"feature": "dst_bytes", "contribution": random.uniform(0.1, 0.4), "value": latest_entry['dst_bytes']},
        {"feature": "count", "contribution": random.uniform(0.1, 0.3), "value": latest_entry['count']}
    ]
    lime_explanation = [
        (f"src_bytes > {latest_entry['src_bytes']-100}", random.uniform(0.2, 0.5)),
        (f"count > {latest_entry['count']-10}", random.uniform(0.1, 0.4)),
        (f"dst_bytes < {latest_entry['dst_bytes']+100}", random.uniform(0.1, 0.3))
    ]

    content = html.Div([
        html.H3("Prediction Explanation", style={'color': '#ecf0f1'}),
        html.H4("SHAP Explanation", style={'color': '#ecf0f1'}),
        html.Ul([html.Li(f"Feature: {exp['feature']}, Contribution: {exp['contribution']:.2f}, Value: {exp['value']}", style={'color': '#ecf0f1'}) for exp in shap_explanation]),
        html.H4("LIME Explanation", style={'color': '#ecf0f1'}),
        html.Ul([html.Li(f"Condition: {exp[0]}, Weight: {exp[1]:.2f}", style={'color': '#ecf0f1'}) for exp in lime_explanation]),
        html.P(f"Predicted as: {latest_entry['attack_type']} (Attack: {latest_entry['is_attack']})", style={'color': '#ecf0f1'})
    ])

    return content, {
        'display': 'block',
        'padding': '20px',
        'marginTop': '20px',
        'backgroundColor': '#1a1a2e',
        'color': '#ecf0f1'
    }

@app.callback(
    [Output('confusion-matrix', 'figure'),
     Output('roc-curve', 'figure')],
    [Input('interval-component', 'n_intervals')]
)
def update_metrics(n):
    with live_data_lock:
        live_df = pd.DataFrame(live_data[-200:])

    # Confusion Matrix
    y_true = np.random.choice([0, 1], 100, p=[0.85, 0.15])
    y_pred = np.random.choice([0, 1], 100, p=[0.9, 0.1])
    cm = confusion_matrix(y_true, y_pred)
    
    cm_fig = ff.create_annotated_heatmap(
        z=cm, 
        x=['Normal', 'Attack'],
        y=['Normal', 'Attack'],
        colorscale='Blues',
        showscale=True
    )
    cm_fig.update_layout(
        title='Threat Detection Accuracy',
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ecf0f1'),
        margin=dict(l=100, r=20, t=50, b=50)
    )

    # ROC Curve
    y_true = np.random.randint(0, 2, 100)
    y_scores = np.random.rand(100)
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    
    roc_fig = px.area(
        x=fpr, y=tpr,
        title=f'Detection Performance (AUC = {roc_auc:.2f})',
        labels={'x': 'False Positive Rate', 'y': 'True Positive Rate'}
    )
    roc_fig.add_shape(type='line', line=dict(dash='dash', color='#ffffff'), x0=0, x1=1, y0=0, y1=1)
    roc_fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ecf0f1'),
        margin=dict(l=50, r=20, t=50, b=50)
    )

    return cm_fig, roc_fig

if __name__ == '__main__':
    app.run_server(debug=True, port=8051, dev_tools_ui=False)
