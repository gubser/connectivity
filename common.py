__author__ = 'Elio Gubser'

import time
import socket

def send_stream_throttled(sock, bitrate, data):
    sock.setblocking(True)

    # calculate amount to send in one slot_time.
    slot_time = 0.01
    slot_amount = int(bitrate/8 * slot_time)

    idx = 0
    while idx < len(data):
        slot_start = time.time()
        slot_sent = 0
        while slot_start+slot_time > time.time():
            if slot_sent < slot_amount and idx < len(data):
                buffer = data[idx:min(idx+(slot_amount-slot_sent), len(data))]
                bytes_sent = sock.send(buffer)

                slot_sent += bytes_sent
                idx += bytes_sent
            else:
                time.sleep(0.001)

def recv_stream(sock, expected_length, timeout):
    sock.settimeout(1)

    recvd_length = 0
    last_time = time.time()

    while recvd_length < expected_length and last_time + timeout > time.time():
        try:
            recvd = sock.recv(expected_length - recvd_length)
        except socket.timeout:
            continue
        else:
            if len(recvd) > 0:
                # received something, so reset timeout
                last_time = time.time()
                recvd_length += len(recvd)
            else:
                time.sleep(0.01)

    return recvd_length