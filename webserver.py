from http.server import BaseHTTPRequestHandler, HTTPServer


class WebServerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        try:
            if self.path.endswith("/hello"):
                self.send_response(200)
                self.send_header('Context-type', 'text/html')

                output = ""
                output = "<html><body>Hello!</body></html>"
                self.wfile.write(output)
                print(output)
                return

        except:
            self.send_error(404, "File Not Found %s" % self.path)


def main():
    try:
        port = 8080
        server = HTTPServer(('', port), WebServerHandler)
        print("Web server running in port %s" % port)
        server.serve_forever()

    except KeyboardInterrupt:
        print("^C entered, stopping server...")
        server.socket.close()


if __name__ == '__main__':
    main()
