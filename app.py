from flask import Flask, render_template, request, jsonify
import subprocess
import pandas as pd
import joblib
import numpy as np
import os

app = Flask(__name__)

# Load model and scaler
model = joblib.load("random_forest_model.pkl")
scaler = joblib.load("scaler.pkl")

# Feature list
selected_features = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'count', 'same_srv_rate', 'diff_srv_rate', 'dst_host_srv_count'
]

# Dummy encodings for protocol, service, flag
proto_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
service_map = {'http': 0, 'private': 1, 'smtp': 2}
flag_map = {'SF': 0, 'REJ': 1, 'S0': 2}

def extract_features_from_packets(packets):
    # Simplified feature extractor from tshark data
    if not packets:
        return None

    frame_lengths = [int(p.split('\t')[1]) for p in packets if '\t' in p]
    if not frame_lengths:
        return None

    feature_dict = {
        'duration': 5,  # 5s capture window
        'protocol_type': proto_map.get('tcp', 0),
        'service': service_map.get('http', 0),
        'flag': flag_map.get('SF', 0),
        'src_bytes': np.mean(frame_lengths),
        'dst_bytes': np.std(frame_lengths),
        'count': len(frame_lengths),
        'same_srv_rate': 0.8,
        'diff_srv_rate': 0.2,
        'dst_host_srv_count': 50
    }

    df = pd.DataFrame([feature_dict])
    return df

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect', methods=['GET'])
def detect_intrusion():
    iface = request.args.get("iface")
    try:
        tshark_cmd = [
            "tshark",
            "-i", iface,
            "-a", "duration:5",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "frame.len"
        ]
        result = subprocess.run(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        packet_data = result.stdout.strip().split('\n')

        if not packet_data or len(packet_data) < 3:
            return jsonify({"result": "❌ No packet data captured. Try a different interface or generate traffic."})

        features_df = extract_features_from_packets(packet_data)
        if features_df is None:
            return jsonify({"result": "❌ Error: could not extract features from packets."})

        features_scaled = scaler.transform(features_df[selected_features])
        prediction = model.predict(features_scaled)[0]

        if prediction == 'anomaly':
            return jsonify({"result": "🚨 Intrusion Detected (Anomaly)"})
        else:
            return jsonify({"result": "✅ No Intrusion (Normal)"})

    except Exception as e:
        return jsonify({"result": f"❌ Error: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)
