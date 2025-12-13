from http.server import BaseHTTPRequestHandler, HTTPServer

class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/public/revoke.crl':
            self.send_response(200)
            self.end_headers()
            with open('public/revoke.crl', 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)

    def do_POST(self):
        pass

HTTPServer(('0.0.0.0', 8080), C2Handler).serve_forever()