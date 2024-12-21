
import socket
import threading
import os

# Define HTTP response templates
HTTP_RESPONSES = {
    200: "HTTP/1.1 200 OK\r\n",
    401: "HTTP/1.1 401 Unauthorized\r\n",
    404: "HTTP/1.1 404 Not Found\r\n",
    400: "HTTP/1.1 400 Bad Request\r\n",
}

ROOT_DIR = "./static"
AUTHENTICATED_SESSIONS = set()

# Mock user credentials for authentication
USER_CREDENTIALS = {"user1": "password123", "user2": "pass456"}

# The authentication function
def authenticate_user(client_socket):
    """
    Handles user authentication over a TCP connection.
    """
    try:
        client_socket.send(b"Welcome! Please authenticate.\n")
        client_socket.send(b"Send credentials in the format: username:password\n")

        credentials = client_socket.recv(1024).decode("utf-8").strip()
        
        # Validate credentials format
        if ":" not in credentials:
            client_socket.send(b"Invalid format. Use username:password.\n")
            return None

        # Parse username and password
        username, password = credentials.split(":", 1)  # Use maxsplit=1 to avoid extra splits if password contains ":"
        if USER_CREDENTIALS.get(username) == password:
            AUTHENTICATED_SESSIONS.add(username)
            client_socket.send(b"Authentication successful!\n")
            return username
        else:
            client_socket.send(b"Authentication failed. Check your username and password.\n")
            return None
    except ConnectionAbortedError:
        print("[ERROR] Connection aborted by the client.")
        return None
    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            client_socket.send(b"An error occurred during authentication.\n")
        except:
            pass
        return None
    finally:
        client_socket.close()

# HTTP handling functions (GET, POST)
def handle_client(client_socket, address, username=None):
    """
    Handles HTTP requests from an authenticated user.
    """
    print(f"[INFO] New connection from {address} (Authenticated as {username})")
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

# Handle GET and POST requests
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

# Start HTTP server for authenticated users
def start_http_server(host, port, username):
    """
    Starts the HTTP server for an authenticated user.
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

# Main authentication server
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
            username = authenticate_user(client_socket)
            if username:
                # Start the HTTP server for this user
                print(f"[INFO] User {username} authenticated. Starting HTTP server.")
                http_thread = threading.Thread(target=start_http_server, args=(host, http_port, username))
                http_thread.start()
    except KeyboardInterrupt:
        print("[INFO] Authentication server shutting down...")
    finally:
        server_socket.close()

# Add the following to simulate client authentication:
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
    auth_server_thread = threading.Thread(target=authentication_server)
    auth_server_thread.start()

    # Simulate client authentication after server starts
    authenticate_to_server()
