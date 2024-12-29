import socket
import threading
import os
import hashlib
import re



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

# Authentication logic
def authenticate_user(client_socket):
    """Simple authentication logic with retry on failure."""
    client_socket.send(b"Welcome! Please authenticate.\n")

    while True:
        try:
            credentials = client_socket.recv(1024).decode("utf-8").strip()

            if credentials:
                username, password = credentials.split(":", 1)
                if USER_CREDENTIALS.get(username) == password:
                    client_socket.send(b"Authentication successful!\n")
                    return username
                else:
                    # Send Unauthorized response if authentication fails
                    response_body = "Authentication failed. Check your username and password."
                    headers = HTTP_RESPONSES[401] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
                    client_socket.send(headers.encode("utf-8") + response_body.encode("utf-8"))
                    client_socket.send(b"Please try again.\n")
            else:
                client_socket.send(b"Invalid input. Please use the format username:password.\n")
        
        except ValueError:
            client_socket.send(b"Invalid input format. Please use the format username:password.\n")
        
        except ConnectionResetError:
            print("[ERROR] Client disconnected unexpectedly.")
            break

        except Exception as e:
            print(f"[ERROR] An error occurred during authentication: {e}")
            break

    return None

def authentication_server(host="127.0.0.1", auth_port=9090, http_port=8080):
    """Starts the authentication server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, auth_port))
    server_socket.listen(5)
    print(f"[INFO] Authentication server started on {host}:{auth_port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            print(f"[INFO] Connection received from {address}")
            username = None

            while username is None:  # Retry authentication until successful
                username = authenticate_user(client_socket)

                if username:
                    print(f"[INFO] User {username} authenticated.")
                    # Start the HTTP server for this user
                    print(f"[INFO] Starting HTTP server for {username}.")
                    http_thread = threading.Thread(target=start_http_server, args=(host, http_port, username))
                    http_thread.start()
                else:
                    print(f"[INFO] Authentication failed for {address}. Closing connection.")
                    break

    except KeyboardInterrupt:
        print("[INFO] Authentication server shutting down...")
    finally:
        server_socket.close()
        print("[INFO] Server socket closed.")

def start_http_server(host, port, username):
    """Starts the HTTP server for an authenticated user."""
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

# Handling different HTTP methods
def handle_client(client_socket, address, username=None):
    print(f"[INFO] New connection from {address} (Authenticated as {username})")

    while True:
        client_socket.settimeout(30)  # Set timeout for 30 seconds

        try:
            request = client_socket.recv(4096).decode("utf-8", errors="replace")  # Allow larger request size
            if not request:
                break
        except socket.timeout:
            print(f"[INFO] Connection timed out for {address}. Closing connection.")
            timeout_response = HTTP_RESPONSES[408] + "Connection Timeout\r\n\r\n"
            client_socket.send(timeout_response.encode("utf-8"))  # Send timeout response
            client_socket.close()
            return

        print(f"[REQUEST]\n{request}")

        # Parse request
        request_line = request.split("\r\n")[0]
        headers, body = request.split("\r\n\r\n", 1) if "\r\n\r\n" in request else ("", "")
        method, path, *_ = request_line.split()

        if method == "GET":
            response = handle_get(path)
        elif method == "POST":
            response = handle_post(path, body)
        elif method == "PUT":
            response = handle_file_upload(path, body)  # File upload handled here
        elif method == "DELETE":
            response = handle_delete(path)
        elif method == "HEAD":
            response = handle_head(path)
        elif method == "OPTIONS":
            response = handle_options(path)
        elif method == "PATCH":
            response = handle_patch(path, body)
        else:
            # Bad request response if unsupported method
            response_body = "Unsupported HTTP Method"
            headers = HTTP_RESPONSES[400] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
            client_socket.send(response.encode("utf-8"))  # Send response with 400 status code
            continue  # Proceed to the next iteration after sending the response
         # Extract status code for logging
        status_code = response.split(" ")[1]

        # Log the status code in the terminal
        print(f"[RESPONSE] Status Code: {status_code} - Method: {method} Path: {path}")

        # Send response to client
        client_socket.send(response.encode("utf-8"))


# Handling HTTP methods
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



def handle_put(path, body):
    # Extract the filename from the multipart form-data
    filename_match = re.search(r'filename="(.+?)"', body)
    if filename_match:
        filename = filename_match.group(1)
        file_path = os.path.join(ROOT_DIR, filename)
    else:
        file_path = os.path.join(ROOT_DIR, path.lstrip("/"))

    # Extract and save file content
    file_data = body.split("\r\n\r\n", 1)[-1].rstrip("--")
    with open(file_path, "w") as file:
        file.write(file_data)

    response_body = f"File uploaded successfully.\nFile Path: {file_path}"
    headers = HTTP_RESPONSES[201] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
    return headers + response_body




def calculate_file_hash(file_path, hash_func=hashlib.sha256):
    hash_obj = hash_func()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def handle_file_upload(path, body):
    # Ensure the "static" directory exists
    save_path = "static"
    os.makedirs(save_path, exist_ok=True)

    # Get the actual file name from the path
    file_name = os.path.basename(path)  # Extract the file name from the URL path
    file_path = os.path.join(save_path, file_name)  # Full path to save the file

    try:
        # Save the file content to the computed file path
        with open(file_path, 'wb') as f:
            f.write(body.encode("utf-8", errors="replace"))  # Save the body as the file content

        # Compute file hash for verification
        file_hash = calculate_file_hash(file_path)
        response_body = f"File uploaded successfully.\nFile Path: {file_path}\nFile Hash (SHA256): {file_hash}\n"
        return HTTP_RESPONSES[200] + "Content-Type: text/plain\r\n\r\n" + response_body
    except Exception as e:
        return HTTP_RESPONSES[500] + f"File upload failed: {e}\r\n\r\n"



def handle_delete(path):
    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))

    if os.path.exists(file_path):
        try:
            # Attempt to delete the file
            os.remove(file_path)

            # Confirm file deletion
            if not os.path.exists(file_path):
                response_body = "Resource deleted"
                headers = (
                    HTTP_RESPONSES[200]
                    + f"Content-Length: {len(response_body)}\r\n"
                    + "Content-Type: text/plain\r\n\r\n"
                )
                return headers + response_body
            else:
                # File still exists, possibly due to permission issues
                response_body = "Failed to delete resource"
                headers = (
                    HTTP_RESPONSES[500]
                    + f"Content-Length: {len(response_body)}\r\n"
                    + "Content-Type: text/plain\r\n\r\n"
                )
                return headers + response_body
        except Exception as e:
            # Handle unexpected errors during deletion
            response_body = f"Internal Server Error: {e}"
            headers = (
                HTTP_RESPONSES[500]
                + f"Content-Length: {len(response_body)}\r\n"
                + "Content-Type: text/plain\r\n\r\n"
            )
            return headers + response_body
    else:
        # File not found
        response_body = "Resource not found"
        headers = (
            HTTP_RESPONSES[404]
            + f"Content-Length: {len(response_body)}\r\n"
            + "Content-Type: text/plain\r\n\r\n"
        )
        return headers + response_body


def handle_head(path):
    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))
    if os.path.exists(file_path):
        content = open(file_path, "r").read()
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(content)}\r\nContent-Type: text/html\r\n\r\n"
        return headers
    else:
        response_body = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers

def handle_options(path):
    """Handle OPTIONS requests (return supported methods)."""
    methods = "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH"
    response_body = f"Supported methods: {methods}"
    headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
    return headers + response_body

def handle_patch(path, body):
    """Handle PATCH requests."""
    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))
    if os.path.exists(file_path):
        with open(file_path, "a") as file:  # Patch typically appends data
            file.write(body)
        response_body = "Resource patched"
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body
    else:
        response_body = "Resource not found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body

# Client-side simulation
def authenticate_to_server():
    host = '127.0.0.1'  # Server address
    port = 9090          # Server port

    # Create a socket connection to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
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

        except ConnectionAbortedError as e:
            print(f"[ERROR] Connection aborted: {e}")
        except Exception as e:
            print(f"[ERROR] An error occurred while connecting to the server: {e}")

if __name__ == "__main__":
    # Start the authentication server in the background
    auth_thread = threading.Thread(target=authentication_server)
    auth_thread.start()

    # Simulate client authentication after server starts
    authenticate_to_server()