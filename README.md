# 🔐 AI-Based Real-Time Detection of IoT Application-Layer Attacks using Ensemble Temporal Decision Forest (ETDF)

An intelligent, real-time intrusion detection system for IoT networks using machine learning. This project implements the **Ensemble Temporal Decision Forest (ETDF)** algorithm to identify and respond to **application-layer attacks** with high precision and transparency. Designed for both academic research and real-world application.

---

## 📌 Table of Contents

- Overview
- Key Features
- Tech Stack
- Usage
- Screenshots
- Project Structure
- Contributions

---

## 📖 Overview

With the rise of IoT deployments in critical systems, **application-layer attacks** are becoming a growing threat. This system detects attacks such as HTTP Flood, SQL Injection, XSS, and others **in real time**, empowering analysts to act immediately using AI-driven insights and automated mitigation.

Developed as part of my **M.Tech Final Year Project**, this solution blends **cybersecurity, AI, and system design** for practical, scalable, and explainable protection.

---

## 🚀 Key Features

- ✅ ETDF-based Detection Engine – High-accuracy classification for known & unknown application-layer threats.
- 🌐 Live Monitoring Dashboard – Built with Flask + Dash for real-time insights.
- 🧪 Cyber Range Simulator – Simulate 20+ IoT-specific attacks with a user-friendly UI.
- 🧠 SHAP & LIME Explainability – Transparent ML decision-making for audit readiness.
- 📍 IP Geolocation & Traceback – Displays attacker’s IP info: Country, City, Org (via IP-API).
- 🛡️ Role-Based Access Control – Admin (full control) vs Analyst (view-only).
- 🔁 Attack Replay & IP Blocking – Re-test and block attackers with a click.
- 📈 Analytics & Metrics – Pie charts, time series, and heatmaps of attack trends.
- 📁 Export Logs – Save incident data to CSV for external analysis.
- 📡 Edge Compatibility (Planned) – MQTT/CoAP integration for low-power IoT.

---

## 🛠️ Tech Stack

| Category | Tools / Frameworks |
|----------|--------------------|
| Backend  | Python, Flask |
| Frontend | Dash (Plotly), HTML/CSS |
| ML/AI    | Scikit-learn, SHAP, LIME |
| Visualization | Plotly, Dash Graphs |
| Geolocation | IP-API |
| Storage  | CSV-based logs |
| Security | Role-based auth (Flask-Login) |

---

## ⚙️ Installation

> ⚠️ Prerequisites: Python 3.8+, pip, virtualenv recommended

```
git clone https://github.com/<your-username>/iot-attack-detection-etdf.git
cd iot-attack-detection-etdf
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

---

## 📁 Download Dataset and Model 

> Large files were excluded from this GitHub repo due to file size limits. You can download them from the links below:

- [📥 rf_model.pkl (trained model)](https://drive.google.com/file/d/1OwvFEruBPQBH7dAjPE-ppuViILzu8TVa/view?usp=drive_link)
- [📥 CICIDS2017 CSV files (attack dataset)](https://drive.google.com/drive/folders/1YUplygHCiXthLNB2EHfWxTV67m8k1NGG?usp=drive_link)

---

## Enable virtual env before running the files 

---
## ▶️ Usage

### 1. Run the Detection Dashboard

```
python interactive_dashboard.py
```

Dashboard will be available at: http://127.0.0.1:8051/

### 2. Access Roles

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| Analyst | analyst | analyst123 |

### 3. Simulate Attacks 

Run the simulator interface:

```
python attack_simulator.py
```

Select any of the 20+ application-layer attacks to simulate real-time activity.

### 4. model

Run model in background:

```
python app.py
```

---

## 🖼️ Screenshots

(Add actual screenshots or GIFs from your dashboard here)


---

## 🎓 Academic Note

This project was developed as part of my M.Tech research in Cybersecurity, focusing on early detection of IoT threats with explainable AI. The detection model is trained on labeled datasets simulating real-world IoT application-layer attacks.

---

## 🤝 Contributions

Pull requests are welcome! For major changes, please open an issue first to discuss what you’d like to change.

---

### 👨‍💻 Author

**Kishor S**  
Cybersecurity Analyst & M.Tech Researcher  
📫 kishorsekar1518@gmail.com  
📎 LinkedIn: https://www.linkedin.com/in/root-kishor-s/  
📂 GitHub: https://github.com/root-Kishor
