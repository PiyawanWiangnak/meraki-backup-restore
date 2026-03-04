from flask import Flask, jsonify
import requests

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "service": "Meraki Monitoring API",
        "status": "running",
        "endpoint": "/monitor"
    })

API_KEY = "fe008837a4b536f86b53bdfc0a88d8768adfd498"
ORG_ID = "898102"

LOSS_THRESHOLD = 3      # %
LATENCY_THRESHOLD = 100 # ms

@app.route("/monitor", methods=["GET"])
def monitor():
    url = f"https://api.meraki.com/api/v1/organizations/{ORG_ID}/devices/uplinksLossAndLatency"

    headers = {
        "X-Cisco-Meraki-API-Key": API_KEY,
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers, timeout=30)
    data = response.json()

    alerts = []

    for device in data:
        serial = device.get("serial")
        uplink = device.get("uplink")
        time_series = device.get("timeSeries", [])

        if not uplink or not time_series:
            continue

        latest = time_series[-1]
        loss = latest.get("lossPercent") or 0
        latency = latest.get("latencyMs") or 0

        if loss > LOSS_THRESHOLD or latency > LATENCY_THRESHOLD:
            alerts.append({
                "serial": serial,
                "uplink": uplink,
                "lossPercent": loss,
                "latencyMs": latency,
                "status": "PROBLEM"
            })

    if alerts:
        return jsonify({
            "status": "PROBLEM",
            "alerts": alerts
        })
    else:
        return jsonify({
            "status": "OK",
            "alerts": []
        })

if __name__ == "__main__":
    print("Starting Meraki Monitoring API...")
    app.run(host="127.0.0.1", port=5000)
