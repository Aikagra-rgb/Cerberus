import http.server
import os
import socketserver

PORT = 3000
BASE_DIR = os.path.dirname(__file__)
DIST_DIR = os.path.join(BASE_DIR, "frontend", "dist")
DIRECTORY = DIST_DIR if os.path.isdir(DIST_DIR) else os.path.join(BASE_DIR, "frontend")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)


print(f"🛡️ Cerberus Frontend running at http://localhost:{PORT} (serving {DIRECTORY})")
print("Tip: For live HMR during development, run `cd frontend && npm run dev`")
print("Press Ctrl+C to stop.")

with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    httpd.serve_forever()
