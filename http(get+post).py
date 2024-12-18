import socket
import threading
import os
from urllib.parse import parse_qs

# Define HTTP response templates
HTTP_RESPONSES = {
    200: "HTTP/1.1 200 OK\r\n",
    404: "HTTP/1.1 404 Not Found\r\n",
    400: "HTTP/1.1 400 Bad Request\r\n"
}

ROOT_DIR = "./static"

def handle_client(client_socket, address):
    print(f"[INFO] New connection from {address}")
    try:
        request = client_socket.recv(1024).decode("utf-8")
        if not request:
            return

        print(f"[REQUEST]\n{request}")

        # Parse the request line
        request_line = request.split("\r\n")[0]
        headers, body = request.split("\r\n\r\n", 1)
        method, path, *_ = request_line.split()

        # Handle unsupported methods (400 Bad Request)
        if method not in ["GET", "POST"]:
            response = HTTP_RESPONSES[400] + "Unsupported HTTP Method\r\n\r\n"
            client_socket.send(response.encode("utf-8"))
            return

        # Handle GET request
        if method == "GET":
            response = handle_get(path)
        # Handle POST request
        elif method == "POST":
            response = handle_post(path, body)
        else:
            response = HTTP_RESPONSES[400] + "Unsupported HTTP Method\r\n\r\n"

        # Send HTTP response
        client_socket.send(response.encode("utf-8"))
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print(f"[INFO] Closing connection from {address}")
        client_socket.close()

def handle_get(path):
    if path == "/":
        path = "/index.html"

    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))

    if os.path.exists(file_path) and os.path.isfile(file_path):
        with open(file_path, "r") as file:
            content = file.read()
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(content)}\r\nContent-Type: text/html\r\n\r\n"
        return headers + content
    else:
        content = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(content)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + content

def handle_post(path, body):
    # Parse the body of the POST request
    post_data = parse_qs(body)
    print(f"[INFO] POST Data: {post_data}")

    # Respond based on path or data
    if path == "/submit":
        response_body = f"Received POST Data: {post_data}"
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body
    else:
        response_body = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body

def start_server(host="127.0.0.1", port=8080):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[INFO] Server started on {host}:{port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
            client_thread.start()
    except KeyboardInterrupt:
        print("[INFO] Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    os.makedirs(ROOT_DIR, exist_ok=True)
    start_server()
