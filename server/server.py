from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_API_KEYS = {"adabnet"}

@app.route("/verify", methods=["POST"])
def verify():
    api_key = request.json.get("api_key")
    if api_key in VALID_API_KEYS:
        return jsonify({"status": "valid"}), 200
    return jsonify({"status": "invalid"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
