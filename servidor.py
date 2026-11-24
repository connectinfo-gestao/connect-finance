import os
from flask import Flask, jsonify
import psycopg
app = Flask(__name__)
@app.get("/")
def index():
    return jsonify(app="Connect Finance", version="2.5-homologacao", sync=False)
@app.get("/health")
def health():
    try:
        with psycopg.connect(os.environ["DATABASE_URL"], connect_timeout=8) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                if cur.fetchone()[0] != 1: raise RuntimeError()
        return jsonify(status="ok", database="connected")
    except Exception:
        return jsonify(status="unavailable"), 503
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
