from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get the length of the request body
        content_length = int(self.headers['Content-Length'])

        # Read the request body
        post_data = self.rfile.read(content_length)

        # Log the received data
        print(f"Received POST request:\n{post_data.decode('utf-8')}\n")

        # Send a response back to the client
        self.send_response(200)  # HTTP status code 200: OK
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"POST request received successfully")

# Server details
host = '0.0.0.0'  # Listen on all available interfaces
port = 8888       # Port to listen on

if __name__ == "__main__":
    server = HTTPServer((host, port), SimpleHTTPRequestHandler)
    print(f"Server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        server.server_close()
