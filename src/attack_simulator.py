from flask import Flask, render_template_string, request, redirect
import requests
import datetime
import random
import threading
import time

app = Flask(__name__)

attack_map = {
    0: {"name": "TCP Flood", "proto": "tcp", "service": "http"},
    1: {"name": "UDP Flood", "proto": "udp", "service": "dns"},
    2: {"name": "ICMP Flood", "proto": "icmp", "service": "ping"},
    3: {"name": "Slowloris", "proto": "tcp", "service": "http"},
    4: {"name": "SSL Garbage", "proto": "tcp", "service": "https"},
    5: {"name": "HTTP Smuggling", "proto": "tcp", "service": "http"},
    6: {"name": "XSS Attack", "proto": "tcp", "service": "http"},
    7: {"name": "SQL Injection", "proto": "tcp", "service": "mysql"},
    8: {"name": "DNS Amplification", "proto": "udp", "service": "dns"},
    9: {"name": "FTP Abuse", "proto": "tcp", "service": "ftp"},
    10: {"name": "SMTP Abuse", "proto": "tcp", "service": "smtp"},
    11: {"name": "HTTP GET Flood", "proto": "tcp", "service": "http"},
    12: {"name": "HTTP POST Flood", "proto": "tcp", "service": "http"},
    13: {"name": "SSL Renegotiation", "proto": "tcp", "service": "https"},
    14: {"name": "Brute Force", "proto": "tcp", "service": "ssh"},
    15: {"name": "Outbound Flood", "proto": "tcp", "service": "http"},
    16: {"name": "Large Download", "proto": "tcp", "service": "ftp"},
    17: {"name": "SSL Flood", "proto": "tcp", "service": "https"},
    18: {"name": "HTTP Flood", "proto": "tcp", "service": "http"},
    19: {"name": "Slow Read", "proto": "tcp", "service": "http"},
    20: {"name": "Malformed Packets", "proto": "udp", "service": "dns"}
}

SOURCE_IPS = [
    "103.228.168.0", "103.228.168.1", "103.228.168.2",  # Pondicherry IPs (Class A)
    "103.228.169.0", "103.228.169.1", "103.228.169.2",
    "203.200.100.0", "203.200.100.1", "203.200.100.2",  # Pondicherry IPs (Class B)
    "172.16.0.1", "172.16.0.2"  # Additional Class B for variety
]

auto_simulate = False
auto_simulate_lock = threading.Lock()

def simulate_attack(attack_id):
    attack_details = attack_map.get(attack_id)
    if not attack_details:
        return
    try:
        source_ip = random.choice(SOURCE_IPS)
        payload = {
            "timestamp": datetime.datetime.now().isoformat(),
            "src_bytes": random.randint(10000, 50000),
            "dst_bytes": random.randint(5000, 25000),
            "count": random.randint(100, 500),
            "attack_label": attack_details['name'],
            "source_ip": source_ip,
            "prediction": 1
        }
        response = requests.post(
            "http://127.0.0.1:8051/log_attack",
            json=payload,
            timeout=2
        )
        if response.status_code != 200:
            print(f"❌ Failed to log attack: {response.text}")
        else:
            print(f"✅ Attack logged successfully: {attack_details['name']} from {source_ip}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

def auto_simulate_attacks():
    attack_id = 0
    while True:
        with auto_simulate_lock:
            if not auto_simulate:
                time.sleep(1)
                continue
        simulate_attack(attack_id)
        attack_id = (attack_id + 1) % len(attack_map)  # Cycle through all 21 attacks
        time.sleep(2)  # Fixed 2-second interval

auto_thread = threading.Thread(target=auto_simulate_attacks)
auto_thread.daemon = True
auto_thread.start()

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Cyber Attack Simulator</title>
    <style>
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes pulse {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(255, 46, 99, 0.7); }
            70% { transform: scale(1.05); box-shadow: 0 0 0 10px rgba(255, 46, 99, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(255, 46, 99, 0); }
        }
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0px); }
        }
        @keyframes typing {
            from { width: 0; }
            to { width: 100%; }
        }
        @keyframes blink {
            50% { border-color: transparent; }
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(-45deg, #0f0f1a, #1a1a2e, #2d2d3f);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
            color: #ecf0f1;
            margin: 0;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
        }
        .particle {
            position: absolute;
            background: rgba(255, 46, 99, 0.3);
            border-radius: 50%;
            animation: float 6s infinite ease-in-out;
        }
        .header {
            text-align: center;
            padding: 4rem 2rem;
            position: relative;
            z-index: 1;
        }
        .header h1 {
            font-size: 2.5rem;
            color: #ff2e63;
            text-shadow: 0 0 10px rgba(255, 46, 99, 0.5);
            display: inline-block;
            overflow: hidden;
            white-space: nowrap;
            border-right: 3px solid #ff2e63;
            animation: typing 3s steps(30, end), blink 0.75s step-end infinite;
        }
        .header p {
            color: #a0a0a0;
            font-size: 1.2rem;
        }
        .controls {
            text-align: center;
            margin-bottom: 20px;
        }
        .auto-toggle {
            padding: 10px 20px;
            background: {{ 'rgba(40, 167, 69, 0.8)' if auto else 'rgba(220, 53, 69, 0.8)' }};
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        .auto-toggle:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px {{ 'rgba(40, 167, 69, 0.4)' if auto else 'rgba(220, 53, 69, 0.4)' }};
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 1;
        }
        form {
            margin: 0;
            height: 100%;
        }
        .attack-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            height: 140px;
            width: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
            cursor: pointer;
            text-align: center;
            color: inherit;
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
        }
        .attack-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: radial-gradient(circle at center, rgba(255, 46, 99, 0.2) 0%, transparent 70%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        .attack-card:hover::before {
            opacity: 1;
        }
        .attack-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(255, 46, 99, 0.3);
            animation: pulse 1.5s infinite;
        }
        .attack-name {
            font-size: 1.3rem;
            margin-bottom: 0.8rem;
            line-height: 1.2;
            padding: 0 10px;
            width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            color: #ecf0f1;
        }
        .protocol-badge {
            display: inline-block;
            padding: 0.4rem 1rem;
            border-radius: 20px;
            font-size: 0.9rem;
            background: rgba(255, 46, 99, 0.3);
            white-space: nowrap;
            flex-shrink: 0;
            color: #ecf0f1;
        }
        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
                padding: 15px;
            }
            .attack-card {
                height: 120px;
                padding: 20px;
            }
            .attack-name {
                font-size: 1.2rem;
            }
        }
    </style>
    <script>
        function createParticle() {
            const particle = document.createElement('div');
            particle.className = 'particle';
            const size = Math.random() * 5 + 2;
            particle.style.width = `${size}px`;
            particle.style.height = `${size}px`;
            particle.style.left = `${Math.random() * 100}vw`;
            particle.style.top = `${Math.random() * 100}vh`;
            particle.style.animationDelay = `${Math.random() * 5}s`;
            document.querySelector('.particles').appendChild(particle);
            setTimeout(() => particle.remove(), 10000);
        }
        setInterval(createParticle, 300);
    </script>
</head>
<body>
    <div class="particles"></div>
    <div class="header">
        <h1>⚡ CYBER RANGE SIMULATOR</h1>
        <p>Select threat vectors to test security systems</p>
    </div>
    <div class="controls">
        <form method="POST" action="/toggle_auto">
            <button type="submit" class="auto-toggle">
                {{ "Stop Auto Simulation" if auto else "Start Auto Simulation" }}
            </button>
        </form>
    </div>
    <div class="grid">
        {% for attack_id, details in attacks.items() %}
        <form method="POST" action="/simulate">
            <input type="hidden" name="attack_id" value="{{ attack_id }}">
            <button type="submit" class="attack-card">
                <div class="attack-name">{{ details.name }}</div>
                <div class="protocol-badge">
                    {{ details.proto|upper }} • {{ details.service|upper }}
                </div>
            </button>
        </form>
        {% endfor %}
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    with auto_simulate_lock:
        auto_status = auto_simulate
    return render_template_string(HTML_TEMPLATE, attacks=attack_map, auto=auto_status)

@app.route('/simulate', methods=['POST'])
def simulate():
    attack_id = int(request.form['attack_id'])
    simulate_attack(attack_id)
    return redirect('/')

@app.route('/toggle_auto', methods=['POST'])
def toggle_auto():
    global auto_simulate
    with auto_simulate_lock:
        auto_simulate = not auto_simulate
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, port=6060, threaded=True)
