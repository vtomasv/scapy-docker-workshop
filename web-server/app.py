from __future__ import annotations

import os
import time
from flask import Flask, Response, make_response, request

app = Flask(__name__)


@app.get("/")
def index():
    return """
    <html>
      <head><title>Scapy Lab Web</title></head>
      <body>
        <h1>Scapy Lab Web Server</h1>
        <p>Servicio HTTP intencionalmente simple para laboratorio.</p>
        <form method="POST" action="/login">
          <label>Usuario <input name="username" value="demo"></label><br>
          <label>Password <input name="password" value="demo"></label><br>
          <button type="submit">Login lab</button>
        </form>
        <p><a href="/slow">/slow</a> mantiene una respuesta lenta para demos TCP.</p>
      </body>
    </html>
    """


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    print(f"[web-server] lab login received username={username!r} password={password!r}", flush=True)

    response = make_response(
        f"Login de laboratorio recibido para usuario={username}. "
        "No uses credenciales reales en este taller.\n"
    )
    response.set_cookie("lab_session", f"session-for-{username}", httponly=False, secure=False)
    return response


@app.get("/headers")
def headers():
    lines = [f"{k}: {v}" for k, v in request.headers.items()]
    return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain"}


@app.get("/slow")
def slow():
    def generate():
        for i in range(1, 31):
            yield f"chunk {i}: respuesta lenta para TCP/RST demo\n"
            time.sleep(1)

    return Response(generate(), mimetype="text/plain")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False)
