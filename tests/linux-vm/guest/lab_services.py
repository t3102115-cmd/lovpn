"""Lab-only responders that live on the SERVER guest's tunnel address (10.66.0.1).

A DNS answer or an HTTP reply from here can only reach a client through the tunnel, so
they prove that resolution and traffic really went through it. Never installed anywhere
except into the disposable lab VM.
"""
import socket
import struct
import sys
import threading

ADDRESS = sys.argv[1] if len(sys.argv) > 1 else "10.66.0.1"
ANSWER = socket.inet_aton("192.0.2.50")


def dns():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((ADDRESS, 53))
    while True:
        query, peer = server.recvfrom(512)
        if len(query) < 12:
            continue
        end = 12
        while end < len(query) and query[end] != 0:
            end += query[end] + 1
        question = query[12:end + 5]
        qtype = struct.unpack(">H", question[-4:-2])[0] if len(question) >= 5 else 0
        header = query[:2] + b"\x81\x80" + b"\x00\x01" + (b"\x00\x01" if qtype == 1 else b"\x00\x00") + b"\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" + ANSWER if qtype == 1 else b""
        server.sendto(header + question + answer, peer)


def http():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ADDRESS, 8080))
    server.listen(16)
    while True:
        client, _ = server.accept()
        try:
            client.recv(1024)
            body = b"tunnel-ok"
            client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        finally:
            client.close()


threading.Thread(target=dns, daemon=True).start()
http()
