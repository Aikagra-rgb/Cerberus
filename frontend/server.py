import os
import http.server
import socketserver

PORT = int(os.environ.get("PORT", 5173))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        # Resolve path clean check
        clean_path = self.path.split("?")[0]
        target = os.path.join(DIRECTORY, clean_path.lstrip("/"))
        if not os.path.exists(target) or os.path.isdir(target):
            self.path = "/index.html"
        return super().do_GET()

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), SPAHandler) as httpd:
        print(f"Cerberus frontend listening on http://127.0.0.1:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
