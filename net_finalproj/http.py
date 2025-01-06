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




# Authentication logic
def authenticate_user(client_socket):
    
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
        except Exception as e:
            print(f"[ERROR] An error occurred during authentication: {e}")
            break
    return None

def authentication_server(host="127.0.0.1", auth_port=9090, http_port=8080):
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                                                              
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)                                                                  
    server_socket.bind((host, auth_port))
    server_socket.listen(5)
    print(f"[INFO] Authentication server started on {host}:{auth_port}")

    try:
        while True:
            username = None

            while username is None:  
                client_socket, address = server_socket.accept()
                username = authenticate_user(client_socket)

                if username:
                    print(f"[INFO] User {username} authenticated.")
                    # Start the HTTP server for this user
                    print(f"[INFO] Starting HTTP server for {username}.")
                    http_thread = threading.Thread(target=start_http_server, args=(host, http_port, username))
                    http_thread.start()
                else:
                    print(f"[INFO] Authentication failed.")
                    break
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
    if path == "/":
        path = "/index.html"

    file_path = os.path.join(ROOT_DIR, path.lstrip("/"))
    content_types = {
        ".css": "text/css",
        ".js": "application/javascript",
        ".html": "text/html",
    }
    file_extension = os.path.splitext(path)[1]
    content_type = content_types.get(file_extension, "application/octet-stream")

    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path, "r") as file:
                content = file.read()
            headers = HTTP_RESPONSES[200] + f"Content-Length: {len(content)}\r\nContent-Type: {content_type}\r\n\r\n"
            return headers + content
        except Exception as e:
            content = f"Error reading file: {e}"
            headers = HTTP_RESPONSES[500] + f"Content-Length: {len(content)}\r\nContent-Type: text/plain\r\n\r\n"
            return headers + content
    else:
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
    """Complete CLI interface with web browser emulation and reconnection support."""
    if not authenticate_to_server(auth_host, auth_port):
        print("[ERROR] Failed to authenticate. Exiting CLI.")
        return

    print("[INFO] CLI interface ready. Type 'connect' to open a new connection or 'help' for commands.\n")
    cli_socket = None

    while True:
        try:
            if not cli_socket:
                command = input("CLI> ").strip().lower()
                if command == "exit":
                    print("[INFO] Exiting CLI...")
                    return
                elif command == "connect":
                    cli_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    cli_socket.settimeout(300)  # 5 minute timeout
                    cli_socket.connect((http_host, http_port))
                    print("[INFO] Connected to the server.")
                    
                    continue
                elif command == "help":
                    print("""[CLI COMMANDS]
- connect          : Open a new connection
- GET <path>       : GET request (e.g., GET /)
- POST             : Send name and email with POST
- PUT <file>       : Upload a local file
- DELETE <path>    : Delete a resource
- HEAD <path>      : Get resource headers
- exit             : Exit CLI
                    """)
                    continue
                else:
                    print("[INFO] No active connection. Type 'connect' to open a new connection.")
                    continue

            command = input("CLI> ").strip()

            if command.lower() == "exit":
                print("[INFO] Exiting CLI...")
                if cli_socket:
                    cli_socket.close()
                      
                return
            elif command.lower() == "help":
                print("""[CLI COMMANDS]
- connect          : Open a new connection
- GET <path>       : GET request (e.g., GET /)
- POST             : Send name and email with POST
- PUT <file>       : Upload a local file
- DELETE <path>    : Delete a resource
- HEAD <path>      : Get resource headers
- exit             : Exit CLI
                    """)
                continue
            elif command.lower().startswith("get"):
                parts = command.split(" ", 1)
                path = parts[1] if len(parts) > 1 else "/"
                
                headers = [
                    f"GET {path} HTTP/1.1",
                    f"Host: {http_host}:{http_port}",
                    "User-Agent: CLI/1.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language: en-US,en;q=0.5",
                    "Accept-Encoding: gzip, deflate, br, zstd",
                    "Connection: keep-alive",
                    "Upgrade-Insecure-Requests: 1",
                    "Sec-Fetch-Dest: document",
                    "Sec-Fetch-Mode: navigate",
                    "Sec-Fetch-Site: none",
                    "Sec-Fetch-User: ?1",
                    "Priority: u=0, i"
                ]
                request = "\r\n".join(headers) + "\r\n\r\n"
                cli_socket.send(request.encode())
                
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")
                
                if "text/html" in response and path in ["/", "/index.html"]:
                    print(f"\n[HTML RESPONSE]\n{response}")  # Print HTML response
                    for resource in ["/styles.css", "/script.js"]:
                        resource_headers = [
                            f"GET {resource} HTTP/1.1",
                            f"Host: {http_host}:{http_port}",
                            "User-Agent: CLI/1.0",
                            "Accept: text/css,*/*;q=0.1" if resource.endswith('.css') else "Accept: application/javascript,*/*;q=0.1",
                            "Accept-Language: en-US,en;q=0.5",
                            "Accept-Encoding: gzip, deflate, br, zstd",
                            "Connection: keep-alive",
                            f"Referer: http://{http_host}:{http_port}/",
                            "Sec-Fetch-Dest: style" if resource.endswith('.css') else "Sec-Fetch-Dest: script",
                            "Sec-Fetch-Mode: no-cors",
                            "Sec-Fetch-Site: same-origin",
                            "Priority: u=2"
                        ]
                        resource_request = "\r\n".join(resource_headers) + "\r\n\r\n"
                        cli_socket.send(resource_request.encode())
                        resource_response = cli_socket.recv(4096).decode()
                        if resource.endswith('.css'):
                            print(f"\n[CSS RESOURCE]\n{resource_response}")
                        else:
                            print(f"\n[JS RESOURCE]\n{resource_response}")


            elif command.lower().startswith("post"):
                name = input("Enter name: ")
                email = input("Enter email: ")
                body = f"name={name}&email={email}"
                
                headers = [
                    "POST /submit HTTP/1.1",
                    f"Host: {http_host}:{http_port}",
                    "User-Agent: CLI/1.0",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-Type: application/x-www-form-urlencoded",
                    f"Content-Length: {len(body)}",
                    "Connection: keep-alive"
                ]
                request = "\r\n".join(headers) + "\r\n\r\n" + body
                cli_socket.send(request.encode())
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")

            elif command.lower().startswith("put"):
                parts = command.split(" ", 1)
                if len(parts) < 2:
                    print("[ERROR] PUT requires a file path")
                    continue
                
                file_path = parts[1]
                if not os.path.isfile(file_path):
                    print(f"[ERROR] File not found: {file_path}")
                    continue

                with open(file_path, "r") as f:
                    content = f.read()
                
                filename = os.path.basename(file_path)
                headers = [
                    f"PUT /{filename} HTTP/1.1",
                    f"Host: {http_host}:{http_port}",
                    "User-Agent: CLI/1.0",
                    "Accept: */*",
                    "Content-Type: application/octet-stream",
                    f"Content-Length: {len(content)}",
                    "Connection: keep-alive"
                ]
                request = "\r\n".join(headers) + "\r\n\r\n" + content
                cli_socket.send(request.encode())
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")

            elif command.lower().startswith("delete"):
                parts = command.split(" ", 1)
                if len(parts) < 2:
                    print("[ERROR] DELETE requires a path")
                    continue
                
                path = parts[1]
                headers = [
                    f"DELETE {path} HTTP/1.1",
                    f"Host: {http_host}:{http_port}",
                    "User-Agent: CLI/1.0",
                    "Accept: */*",
                    "Connection: keep-alive"
                ]
                request = "\r\n".join(headers) + "\r\n\r\n"
                cli_socket.send(request.encode())
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")

            elif command.lower().startswith("head"):
                parts = command.split(" ", 1)
                path = parts[1] if len(parts) > 1 else "/"
                
                headers = [
                    f"HEAD {path} HTTP/1.1",
                    f"Host: {http_host}:{http_port}",
                    "User-Agent: CLI/1.0",
                    "Accept: */*",
                    "Connection: keep-alive"
                ]
                request = "\r\n".join(headers) + "\r\n\r\n"
                cli_socket.send(request.encode())
                response = cli_socket.recv(4096).decode()
                print(f"\n[SERVER RESPONSE]\n{response}")

            else:
                print("[ERROR] Unknown command. Type 'help' for available commands.")

        except socket.timeout:
            print("[INFO] Connection timed out. Type 'connect' to open a new connection.")
            if cli_socket:
                cli_socket.close()
            cli_socket = None
            
        except ConnectionResetError:
            print("[INFO] Server closed the connection. Type 'connect' to open a new connection.")
            if cli_socket:
                cli_socket.close()
            cli_socket = None
           
        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
            if cli_socket:
                cli_socket.close()
            cli_socket = None
            



if __name__ == "__main__":
    # Start the authentication server
    auth_thread = threading.Thread(target=authentication_server)
    auth_thread.start()

    # Start the CLI interface
    cli_interface()
