from flask import Flask, request, jsonify
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
import numpy as np

app = Flask(__name__)
model = joblib.load('models/etdf_model.pkl')
print("✅ ETDF model loaded.")

# Enhanced attack labels with simulation support
attack_labels = {
    0: "TCP Flood", 1: "UDP Flood", 2: "ICMP Flood", 3: "Slowloris", 
    4: "SSL Garbage Flood", 5: "HTTP Request Smuggling", 6: "XSS Attack",
    7: "SQL Injection", 8: "DNS Amplification", 9: "FTP Abuse",
    10: "SMTP Abuse", 11: "HTTP GET Flood", 12: "HTTP POST Flood",
    13: "SSL Renegotiation", 14: "Application Brute Force",
    15: "Outbound Pipe Saturation", 16: "Large File Download",
    17: "SSL Flood", 18: "HTTP Flood", 19: "Slow Read Attack",
    20: "Malformed Packet Attack", 21: "Normal Traffic"
}

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        
        # Direct simulation handling
        if 'attack_label' in data:
            return jsonify({
                'prediction': 21 if "Normal" in data['attack_label'] else int(data.get('attack_id', 18)),
                'label': data['attack_label'],
                'attack_label': data['attack_label'],
                'message': 'Simulated Attack'
            })

        # Regular prediction processing
        df = pd.DataFrame([data])
        
        # Feature engineering
        df['total_bytes'] = df['src_bytes'] + df['dst_bytes']
        
        # Categorical encoding with fallback
        categoricals = ['protocol', 'service', 'flag']
        for col in categoricals:
            if col not in df.columns:
                df[col] = 'missing'
                
        df = pd.get_dummies(df, columns=categoricals, drop_first=True)
        
        # Ensure model feature compatibility
        missing_features = set(model.feature_names_in_) - set(df.columns)
        for feature in missing_features:
            df[feature] = 0
            
        # Feature ordering
        df = df[model.feature_names_in_]
        
        # Scaling
        scaler = StandardScaler()
        numeric_cols = ['src_bytes', 'dst_bytes', 'count', 'total_bytes']
        for col in numeric_cols:
            if col in df.columns:
                df[col] = scaler.fit_transform(df[[col]])
                
        # Prediction
        prediction = model.predict(df)[0]
        label = attack_labels.get(int(prediction), "Unknown")
        
        return jsonify({
            'prediction': int(prediction),
            'label': label,
            'message': 'Attack Detected' if prediction != 21 else 'Normal Traffic'
        })

    except Exception as e:
        return jsonify({
            'error': str(e),
            'received_data': data,
            'expected_features': model.feature_names_in_.tolist()
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=8081)
