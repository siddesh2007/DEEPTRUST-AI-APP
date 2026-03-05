from flask import Flask, request, jsonify
from inference import run_inference

app = Flask(__name__)


@app.get('/health')
def health():
    return jsonify({"ok": True, "service": "ai-service"})


@app.post('/analyze')
def analyze():
    payload = request.get_json(silent=True) or {}
    file_path = payload.get('file_path')
    if not file_path:
        return jsonify({"ok": False, "message": "file_path required"}), 400

    result = run_inference(file_path)
    return jsonify({"ok": True, **result})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7000, debug=True)
