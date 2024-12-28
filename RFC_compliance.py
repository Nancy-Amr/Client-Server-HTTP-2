import socket
import threading
import os
import struct
from hpack import Encoder, Decoder

# Constants
HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS_FRAME = b"\x00\x00\x0c\x04\x00\x00\x00\x00\x00" + struct.pack(">IH", 0, 0)
GOAWAY_FRAME = b"\x00\x00\x08\x07\x00\x00\x00\x00\x00" + struct.pack(">II", 0, 0)
PUSH_PROMISE_FRAME = b"\x00\x00\x00\x05\x00\x00\x00\x00\x00"
FLOW_CONTROL_WINDOW_SIZE = 65535

ROOT_DIR = "./static"
os.makedirs(ROOT_DIR, exist_ok=True)

# Helper functions
def send_frame(sock, frame_type, flags, stream_id, payload):
    """Send an HTTP/2 frame."""
    frame = struct.pack(">I", len(payload))[1:] + bytes([frame_type, flags]) + struct.pack(">I", stream_id)[1:] + payload
    sock.sendall(frame)

# HTTP/2 Frame Handlers
def handle_settings(sock):
    """Handle SETTINGS frame."""
    send_frame(sock, 4, 0, 0, SETTINGS_FRAME)


def handle_headers(sock, stream_id, path):
    """Send HEADERS frame with requested resource."""
    encoder = Encoder()
    headers = encoder.encode([
        (":status", "200"),
        ("content-type", "text/html"),
        ("content-length", str(len(path))),
    ])
    send_frame(sock, 1, 4, stream_id, headers)


def handle_data(sock, stream_id, data):
    """Send DATA frame."""
    send_frame(sock, 0, 0, stream_id, data.encode("utf-8"))


def handle_goaway(sock):
    """Send GOAWAY frame."""
    send_frame(sock, 7, 0, 0, GOAWAY_FRAME)


def handle_push_promise(sock, stream_id, path):
    """Send PUSH_PROMISE frame."""
    encoder = Encoder()
    headers = encoder.encode([
        (":method", "GET"),
        (":path", path),
    ])
    send_frame(sock, 5, 0, stream_id, PUSH_PROMISE_FRAME + headers)


# Server implementation
def handle_client(client_socket, address):
    """Handle incoming HTTP/2 client."""
    print(f"[INFO] Connection from {address}")

    # Receive client preface
    preface = client_socket.recv(len(HTTP2_PREFACE))
    if preface != HTTP2_PREFACE:
        print("[ERROR] Invalid HTTP/2 preface received. Closing connection.")
        client_socket.close()
        return

    # Acknowledge SETTINGS
    handle_settings(client_socket)

    # Handle incoming frames
    while True:
        try:
            # Read frame header (9 bytes)
            header = client_socket.recv(9)
            if not header:
                break

            length, frame_type, flags, stream_id = struct.unpack(">3sB1B3s", header)
            length = int.from_bytes(length, "big")
            stream_id = int.from_bytes(stream_id, "big")

            # Read frame payload
            payload = client_socket.recv(length)

            # Handle frame types
            if frame_type == 1:  # HEADERS
                path = "/index.html"
                handle_headers(client_socket, stream_id, path)
                handle_data(client_socket, stream_id, "<html><body>Hello HTTP/2!</body></html>")
                handle_push_promise(client_socket, stream_id, "/extra_resource.html")
            elif frame_type == 0:  # DATA
                print(f"[INFO] DATA frame received: {payload}")
            elif frame_type == 7:  # GOAWAY
                print("[INFO] GOAWAY frame received. Closing connection.")
                break

        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            break

    handle_goaway(client_socket)
    client_socket.close()


def start_server(host="127.0.0.1", port=8080):
    """Start the HTTP/2 server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print(f"[INFO] HTTP/2 server started on {host}:{port}")

    try:
        while True:
            client_socket, address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, address)).start()
    except KeyboardInterrupt:
        print("[INFO] Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
