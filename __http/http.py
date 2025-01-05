import socket
import threading
import os
import hashlib
import re
from hpack import Encoder, Decoder



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

# Create HPACK encoder and decoder instances
hpack_encoder = Encoder()
hpack_decoder = Decoder()

def compress_headers(headers_dict):
    """
    Compress headers using HPACK.
    :param headers_dict: Dictionary of HTTP headers.
    :return: Compressed binary representation of headers.
    """
    headers_list = [(key, value) for key, value in headers_dict.items()]
    return hpack_encoder.encode(headers_list)

def decompress_headers(encoded_headers):
    """
    Decompress headers using HPACK.
    :param encoded_headers: Compressed binary headers.
    :return: Dictionary of decompressed headers.
    """
    headers = hpack_decoder.decode(encoded_headers)
    return {key.decode(): value.decode() for key, value in headers}

# Example usage
def handle_client_with_hpack(client_socket):
    try:
        # Receive and decode headers
        request = client_socket.recv(4096)
        decompressed_headers = decompress_headers(request)
        print("[DECOMPRESSED HEADERS]:", decompressed_headers)

        # Prepare a response
        headers = {
            ":status": "200",
            "content-type": "text/plain",
            "content-length": "12",
        }
        compressed_response_headers = compress_headers(headers)

        # Send compressed response headers followed by the body
        client_socket.send(compressed_response_headers + b"Hello World!")
    except Exception as e:
        print("[ERROR] HPACK handling failed:", e)
    finally:
        client_socket.close()



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


PUSH_MANIFEST = {
    "/index.html": ["/style.css", "/script.js"],
    "/about.html": ["/about-style.css", "/about-image.jpg"],
}
# Handling different HTTP methods
def handle_client(client_socket, address, username=None):
    print(f"[INFO] New connection from {address} (Authenticated as {username})")

    while True:
        client_socket.settimeout(300)  # Set timeout for 300 seconds

        try:
            request = client_socket.recv(4096).decode("utf-8", errors="replace")
            if not request:
                break

            # Log the formatted request
            print(f"[REQUEST FROM {address}]\n{request}")

            # Process and respond to the request
            request_line = request.split("\r\n")[0]
            headers, body = request.split("\r\n\r\n", 1) if "\r\n\r\n" in request else ("", "")
            method, path, *_ = request_line.split()

            # Handle the request based on the method
            if method == "GET":
                response = handle_get(path)

                # Check if there are files to push for this resource
                if path in PUSH_MANIFEST:
                    push_files = PUSH_MANIFEST[path]
                    for push_file in push_files:
                        push_response = handle_get(push_file)
                        client_socket.send(push_response.encode("utf-8"))
                        print(f"[PUSH] Sent {push_file} to {address}")

            elif method == "POST":
                response = handle_post(path, body)
            elif method == "PUT":
                response = handle_put(path, headers, body)
            elif method == "DELETE":
                response = handle_delete(path)
            elif method == "HEAD":
                response = handle_head(path)
            else:
                response_body = "Unsupported HTTP Method"
                headers = HTTP_RESPONSES[405] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
                response = headers + response_body

            # Log and send the response
            status_code = response.split(" ")[1]
            print(f"[RESPONSE] Status Code: {status_code} - Method: {method} Path: {path}")
            client_socket.send(response.encode("utf-8"))

        except socket.timeout:
            print(f"[INFO] Connection timed out for {address}. Closing connection.")
            timeout_response = HTTP_RESPONSES[408] + "Connection Timeout\r\n\r\n"
            client_socket.send(timeout_response.encode("utf-8"))
            client_socket.close()
            return
        except Exception as e:
            print(f"[ERROR] Failed to process request from {address}: {e}")
            break

    client_socket.close()




# Handling HTTP methods
def handle_get(path):
    # Default to index.html if the root path is requested
    if path == "/":
        path = "/index.html"

    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))

    # Determine the content type based on the file extension
    if path.endswith(".css"):
        content_type = "text/css"
    elif path.endswith(".js"):
        content_type = "application/javascript"
    elif path.endswith(".html"):
        content_type = "text/html"
    else:
        content_type = "application/octet-stream"  # Default for binary files (like images, etc.)

    # Check if the requested file exists and is a file (not a directory)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            # Open and read the file
            with open(file_path, "r") as file:
                content = file.read()

            # Send the file with the correct content type and headers
            headers = HTTP_RESPONSES[200] + f"Content-Length: {len(content)}\r\nContent-Type: {content_type}\r\n\r\n"
            return headers + content

        except Exception as e:
            # Handle unexpected errors while reading the file
            content = f"Error reading file: {e}"
            headers = HTTP_RESPONSES[500] + f"Content-Length: {len(content)}\r\nContent-Type: text/plain\r\n\r\n"
            return headers + content
    else:
        # If the file doesn't exist, return a 404 error
        content = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(content)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + content
    
def handle_post(path, body):
    post_data = body
    print(f"[INFO] POST Data: {post_data}")

    if path == "/submit":
        response_body = f"{post_data}"
        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body
    else:
        response_body = "404 Not Found"
        headers = HTTP_RESPONSES[404] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body



def handle_put(path, headers, body):
    """Handle PUT requests for file uploads."""
    try:
        # Extract the filename from the path
        filename = os.path.basename(path.lstrip("/"))
        
        if not filename:
            return "HTTP/1.1 400 Bad Request\r\n\r\nFilename not specified."

        file_path = os.path.join(ROOT_DIR, filename)  # Save file with the actual filename

        # Save the file content
        with open(file_path, "wb") as file:
            file.write(body.encode("utf-8", errors="replace"))

        response_body = f"File '{filename}' uploaded successfully."
        headers = "HTTP/1.1 200 OK\r\n" + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body

    except Exception as e:
        response_body = f"File upload failed: {e}"
        headers = "HTTP/1.1 500 Internal Server Error\r\n" + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body





def calculate_file_hash(file_path, hash_func=hashlib.sha256):
    hash_obj = hash_func()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()


def handle_file_upload(path, body):
    """Handle file upload requests from both web and CLI."""
    save_path = "static"
    os.makedirs(save_path, exist_ok=True)

    try:
        # Check if this is a web (multipart form-data) or CLI request
        is_web_upload = "multipart/form-data" in body
        
        if is_web_upload:
            # Handle web upload
            boundary = body.split("boundary=")[1].split("\r\n")[0]
            parts = body.split(f"--{boundary}")
            
            for part in parts:
                if 'Content-Disposition: form-data' in part and 'filename=' in part:
                    filename_match = re.search(r'filename="(.+?)"', part)
                    if filename_match:
                        filename = filename_match.group(1)
                        content_start = part.find("\r\n\r\n") + 4
                        file_content = part[content_start:].rsplit("\r\n", 1)[0]
                        
                        file_path = os.path.join(save_path, filename)
                        with open(file_path, 'wb') as f:
                            f.write(file_content.encode('utf-8', errors='replace'))
                        
                        file_hash = calculate_file_hash(file_path)
                        response_body = f"File uploaded successfully.\nFile Path: {file_path}\nFile Hash (SHA256): {file_hash}\n"
                        headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
                        return headers + response_body
        else:
            # Handle CLI upload
            # Extract filename from path
            filename = os.path.basename(path.lstrip("/"))
            if not filename:
                filename = "uploaded_file"
            
            file_path = os.path.join(save_path, filename)
            
            # For CLI uploads, the body contains the raw file content
            with open(file_path, 'wb') as f:
                f.write(body.encode('utf-8', errors='replace'))
            
            file_hash = calculate_file_hash(file_path)
            response_body = f"File uploaded successfully.\nFile Path: {file_path}\nFile Hash (SHA256): {file_hash}\n"
            headers = HTTP_RESPONSES[200] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
            return headers + response_body

    except Exception as e:
        response_body = f"File upload failed: {e}"
        headers = HTTP_RESPONSES[500] + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body

def handle_delete(path):
    """Handle DELETE requests for file deletion."""
    try:
        # Extract the filename from the path
        filename = os.path.basename(path.lstrip("/"))
        
        if not filename:
            return "HTTP/1.1 400 Bad Request\r\n\r\nFilename not specified."

        file_path = os.path.join(ROOT_DIR, filename)

        # Check if the file exists and delete it
        if os.path.isfile(file_path):
            os.remove(file_path)
            response_body = f"File '{filename}' deleted successfully."
            headers = "HTTP/1.1 200 OK\r\n" + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
            return headers + response_body
        else:
            response_body = f"File '{filename}' not found."
            headers = "HTTP/1.1 404 Not Found\r\n" + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
            return headers + response_body

    except Exception as e:
        response_body = f"Failed to delete file: {e}"
        headers = "HTTP/1.1 500 Internal Server Error\r\n" + f"Content-Length: {len(response_body)}\r\nContent-Type: text/plain\r\n\r\n"
        return headers + response_body



def handle_head(path):
    """
    Handles HTTP HEAD requests and returns only the headers for the requested resource.
    """
    if path == "/":
        path = "/index.html"  # Default to index.html if the path is root

    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))

    if os.path.exists(file_path) and os.path.isfile(file_path):
        content_length = os.path.getsize(file_path)
        content_type = "text/html" if file_path.endswith(".html") else "text/plain"

        headers = (
            HTTP_RESPONSES[200]
            + f"Content-Length: {content_length}\r\n"
            + f"Content-Type: {content_type}\r\n\r\n"
        )
    else:
        # Handle file not found
        headers = (
            HTTP_RESPONSES[404]
            + f"Content-Length: 0\r\n"
            + "Content-Type: text/plain\r\n\r\n"
        )

    return headers



# Client-side simulation
def authenticate_to_server(auth_host, auth_port):
    """
    Handles user authentication with the server.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as auth_socket:
            auth_socket.connect((auth_host, auth_port))
            
            # Wait for server's authentication prompt
            server_greeting = auth_socket.recv(1024).decode("utf-8")
            print(server_greeting)
            
            # Send user credentials
            username = input("Enter username: ")
            password = input("Enter password: ")
            credentials = f"{username}:{password}"
            auth_socket.send(credentials.encode())
            
            # Receive server's authentication response
            response = auth_socket.recv(1024).decode("utf-8")
            print(response)
            
            return "Authentication successful" in response
    except Exception as e:
        print(f"[ERROR] Authentication error: {e}")
        return False
    
def cli_interface(auth_host="127.0.0.1", auth_port=9090, http_host="127.0.0.1", http_port=8080):
    """Command-line interface for interacting with the server."""
    if not authenticate_to_server(auth_host, auth_port):
        print("[ERROR] Failed to authenticate. Exiting CLI.")
        return

    print("[INFO] CLI interface ready. Type 'help' for available commands.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli_socket:
        try:
            cli_socket.connect((http_host, http_port))

            while True:
                command = input("CLI> ").strip()

                if command.lower() == "exit":
                    print("[INFO] Exiting CLI...")
                    break
                elif command.lower() == "help":
                    print("""
[CLI COMMANDS]
- GET <path>       : Perform an HTTP GET request (e.g., GET /index.html)
- POST <path> <data>: Send data with POST (e.g., POST /submit "data")
- PUT <file>       : Upload a local file to the server's static folder (e.g., PUT file.txt)
- DELETE <path>    : Delete a resource (e.g., DELETE /resource)
- HEAD <path>      : Retrieve headers for a resource (e.g., HEAD /index.html)
- OPTIONS <path>   : Get supported HTTP methods (e.g., OPTIONS /index.html)
- PATCH <path> <data>: Apply partial updates to a resource (e.g., PATCH /resource "data")
- exit            : Disconnect from the CLI
                    """)
                    continue

                # Construct formatted HTTP request
                if command.startswith(("GET", "POST", "DELETE", "HEAD", "OPTIONS", "PATCH")):
                    method, path, *body = command.split(" ", 2)
                    body = body[0] if body else ""
                    
                    # Common headers for all requests
                    headers = [
                        f"{method} {path} HTTP/1.1",
                        f"Host: {http_host}:{http_port}",
                        "User-Agent: CLI/1.0 (Python Custom Client)",
                        "Accept: */*",
                        "Accept-Language: en-US,en;q=0.9",
                        "Accept-Encoding: gzip, deflate, br",
                        "Connection: keep-alive",
                        "Cache-Control: no-cache",
                        "Pragma: no-cache",
                        "Sec-Fetch-Dest: empty",
                        "Sec-Fetch-Mode: cors",
                        "Sec-Fetch-Site: same-origin",
                        f"Content-Length: {len(body)}",
                        f"Origin: http://{http_host}:{http_port}",
                        f"Referer: http://{http_host}:{http_port}/"
                    ]

                    # Add method-specific headers
                    if method == "POST" or method == "PATCH":
                        headers.insert(-1, "Content-Type: application/x-www-form-urlencoded")
                    elif method == "OPTIONS":
                        headers.insert(-1, "Access-Control-Request-Method: POST, GET, OPTIONS")
                        headers.insert(-1, "Access-Control-Request-Headers: content-type")

                    request = "\r\n".join(headers) + "\r\n\r\n" + body

                elif command.startswith("PUT"):
                    parts = command.split(" ", 1)
                    if len(parts) < 2:
                        print("[ERROR] PUT requires a local file path (e.g., PUT file.txt).")
                        continue
                    local_file_path = parts[1]
                    if not os.path.isfile(local_file_path):
                        print(f"[ERROR] File '{local_file_path}' not found.")
                        continue
                    
                    filename = os.path.basename(local_file_path)
                    with open(local_file_path, "r") as f:
                        file_content = f.read()

                    headers = [
                        f"PUT /{filename} HTTP/1.1",
                        f"Host: {http_host}:{http_port}",
                        "User-Agent: CLI/1.0 (Python Custom Client)",
                        "Accept: */*",
                        "Accept-Language: en-US,en;q=0.9",
                        "Accept-Encoding: gzip, deflate, br",
                        "Connection: keep-alive",
                        "Cache-Control: no-cache",
                        "Pragma: no-cache",
                        "Sec-Fetch-Dest: empty",
                        "Sec-Fetch-Mode: cors",
                        "Sec-Fetch-Site: same-origin",
                        "Content-Type: application/octet-stream",
                        f"Content-Length: {len(file_content)}",
                        f"Origin: http://{http_host}:{http_port}",
                        f"Referer: http://{http_host}:{http_port}/",
                        f"X-Filename: {filename}"
                    ]

                    request = "\r\n".join(headers) + "\r\n\r\n" + file_content
                else:
                    print("[ERROR] Unsupported command format.")
                    continue

                # Send the request without logging it (server will handle logging)
                cli_socket.send(request.encode())

                # Receive and display the response
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")
        except Exception as e:
            print(f"[ERROR] CLI connection error: {e}")


if __name__ == "__main__":
    # Start the authentication server
    auth_thread = threading.Thread(target=authentication_server)
    auth_thread.start()

    # Start the CLI interface
    cli_interface()
