import sys
import socket
import time
import matplotlib.pyplot as plt
import numpy as np

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = '0.0.0.0'
server_port = 8080

server = (server_address, server_port)
sock.bind(server)
sock.settimeout(2)
received_y = []
received_x = []
try:
  while True:
    payload, client_address = sock.recvfrom(1500)
    recv_seq = int.from_bytes(payload[200:], byteorder='big')
    received_y.append(recv_seq)
    received_x.append(time.monotonic_ns())
except Exception:
  pass

print(len(received_y), end='')

sys.stdout.flush()
received_x = (np.array(received_x)-received_x[0])/1000000000
plt.plot(received_x, received_y)
received_y.sort()
missed = []

j = 0
for i in range(received_y[-1]):
  while True:
    if received_y[j] > i:
      missed.append(received_x[j])
      break
    j += 1
    if received_y[j-1] == i:
      break
plt.hist(missed, bins=100)

plt.legend(("last received sequence","missed packets"))
plt.xlabel("time (s)")
plt.ylabel("last received sequence")
plt.savefig("result.png")