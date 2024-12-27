
import socket
import threading
import os

# Constants
HTTP_RESPONSES = {
    200: "HTTP/1.1 200 OK\r\n",
    401: "HTTP/1.1 401 Unauthorized\r\n",
    404: "HTTP/1.1 404 Not Found\r\n",
    400: "HTTP/1.1 400 Bad Request\r\n",
    408: "HTTP/1.1 408 Request Timeout\r\n",
}

ROOT_DIR = "./static"
USER_CREDENTIALS = {"user1": "password123", "user2": "pass456"}

# HTTP request and response logic
def handle_client(client_socket, address, username=None):
    """
    Handle client requests over a single persistent connection.
    """
    print(f"[INFO] New connection from {address} (Authenticated as {username})")

    # Loop to handle multiple requests over the same connection
    while True:
        # Receive the HTTP/1.1 request (read until we encounter an empty line or timeout)
        client_socket.settimeout(30)  # Set timeout for each request (10 seconds)
        try:
            request = client_socket.recv(1024).decode("utf-8")
            if not request:
                break  # Close connection if no data received (client disconnected)
        except socket.timeout:
            print("[INFO] Connection timeout")
            break

        if not request:
            break

        print(f"[REQUEST]\n{request}")

        # Parse the request line
        request_line = request.split("\r\n")[0]
        headers, body = request.split("\r\n\r\n", 1) if "\r\n\r\n" in request else ("", "")
        method, path, *_ = request_line.split()

        # Handle GET request
        if method == "GET":
            response = handle_get(path)
            client_socket.send(response.encode("utf-8"))
            
            # Simulate server push if requested file is index.html
            if path == "/index.html":
                push_response = simulate_server_push("/extra_resource.html")
                client_socket.send(push_response.encode("utf-8"))
            
        # Handle POST request
        elif method == "POST":
            response = handle_post(path, body)
            client_socket.send(response.encode("utf-8"))
        else:
            response = HTTP_RESPONSES[400] + "Unsupported HTTP Method\r\n\r\n"
            client_socket.send(response.encode("utf-8"))

        # Check if client wants to keep the connection alive or close it
        if "Connection: close" in headers:
            print("[INFO] Closing connection as requested by client.")
            break

    # Close connection after the client disconnects or timeout
    client_socket.close()

def handle_get(path):
    """
    Handle GET requests with an HTTP/2-like response.
    """
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
    """
    Handle POST requests with an HTTP/2-like response.
    """
    post_data = body
    print(f"[INFO] POST Data: {post_data}")

    if path == "/submit":
        response_body = f"Received POST Data: {post_data}"
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body
    else:
        response_body = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body

def simulate_server_push(path):
    """
    Simulate a server push in HTTP/2 by sending an additional resource.
    """
    print(f"[INFO] Server pushing resource: {path}")
    content = f"Simulated content for {path}"
    headers = HTTP_RESPONSES[200] + f"Content-Length: {len(content)}\r\nContent-Type: text/html\r\n\r\n"
    return headers + content

# Start HTTP server for authenticated users
def start_http_server(host, port, username):
    """
    Starts the HTTP server for an authenticated user, handling multiple requests on a single connection.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"[INFO] HTTP server started on {host}:{port} for user {username}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address, username))
            client_thread.start()
    except KeyboardInterrupt:
        print("[INFO] HTTP server shutting down...")
    finally:
        server_socket.close()

# Authentication server to simulate user authentication before HTTP server
def authentication_server(host="127.0.0.1", auth_port=9090, http_port=8080):
    """
    Starts the authentication server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, auth_port))
    server_socket.listen(5)
    print(f"[INFO] Authentication server started on {host}:{auth_port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            print(f"[INFO] Connection received from {address}")
            username = authenticate_user(client_socket)
            if username:
                print(f"[INFO] User {username} authenticated.")
                # Start the HTTP server for this user
                print(f"[INFO] Starting HTTP server for {username}.")
                http_thread = threading.Thread(target=start_http_server, args=(host, http_port, username))
                http_thread.start()
    except KeyboardInterrupt:
        print("[INFO] Authentication server shutting down...")
    finally:
        server_socket.close()

def authenticate_user(client_socket):
    """
    Simple authentication logic to simulate user login.
    """
    client_socket.send(b"Welcome! Please authenticate.\n")
    client_socket.send(b"Send credentials in the format: username:password\n")

    credentials = client_socket.recv(1024).decode("utf-8").strip()

    if ":" not in credentials:
        client_socket.send(b"Invalid format. Use username:password.\n")
        return None

    username, password = credentials.split(":", 1)
    if USER_CREDENTIALS.get(username) == password:
        client_socket.send(b"Authentication successful!\n")
        return username
    else:
        client_socket.send(b"Authentication failed. Check your username and password.\n")
        return None

# Simulate client authentication:
def authenticate_to_server():
    host = '127.0.0.1'  # Server address
    port = 9090          # Server port

    # Create a socket connection to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Receive the initial greeting
        data = s.recv(1024)
        print(data.decode())

        # Send authentication credentials
        username = input("Enter username: ")
        password = input("Enter password: ")
        credentials = f"{username}:{password}"
        s.send(credentials.encode())
        
        # Receive the server response
        response = s.recv(1024)
        print(response.decode())

if __name__ == "__main__":
    os.makedirs(ROOT_DIR, exist_ok=True)

    # Start the authentication server in the background
    auth_thread = threading.Thread(target=authentication_server)
    auth_thread.start()

    # Simulate client authentication after server starts
    authenticate_to_server()

