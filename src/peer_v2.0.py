import math
import sys
import os

import matplotlib.pyplot as plt

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import argparse
import pickle
import time

"""
This code can pass all the 4 basic tests and the advanced test. Just for save. 
"""

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
OK. We will do that -- just for git test.
This is for the ssh test -- to check if it updates automatically.
hyhs test
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024
MAX_PAYLOAD = 1024
HEADER_LEN = struct.calcsize("HBBHHII")
TEAM_NUM = 58
HAS_SENT = 0
START_TIME = 0
TOTAL_CHUNK = 0
# Record that how many packets have been sent by this peer.
HAS_RECEIVED = 0
ALL_IHAVE = False
ALL_GET = False
BEGIN_DOWNLOAD = False
CONNECT_NUM = 0
config = None
# Note that the config will be initialized at the beginning of the procedure.
ex_output_file = None
ex_received_chunk = dict()
ex_downloading_chunkhash = []
# Consider that there are more than one chunkhashes to download, so we need a list.
get_chunk_dict = dict()
download_duty = dict()
connected = dict()
last_time = dict()
last_received = dict()
last_chunkhash = dict()
last_IHAVE_time = 0
crashed = dict()

send_time_dict = dict()
cwnd = dict()
ssthresh = dict()
conges_ct = dict()
state = dict()
# 0 stands for slow start
# 1 stands for congestion avoidance
# 2 stands for fast recovery
last_byte_sent = dict()
last_byte_acked = dict()
last_receiver_chunkhash = dict()
# Note: This is different from the last_chunkhash. This is used for sender, the above one is used for receiver.
timeout = dict()
Estimated_RTT = dict()
Dev_RTT = dict()
alpha = 0.125
beta = 0.25
dupACKcount = dict()
byte_to_receive = dict()
byte_has_received = dict()
buffer = dict()
cwnd_list = dict()
iteration = []


def get_dict_key(dic, value):
    key = list(dic.keys())[list(dic.values()).index(value)]
    return key


def draw_cwnd(sender):
    it_num = len(cwnd_list[sender])
    x = list(range(1, it_num + 1))
    y = cwnd_list[sender]
    print(x)
    print(y)
    plt.plot(x, y)
    plt.title('Line Plot')
    plt.xlabel('time')
    plt.ylabel('window size')

    plt.savefig('line_plot.png')


def initialize_sender(from_addr, cur_gethash):
    send_time_dict[from_addr] = {1: time.time()}

    last_byte_sent[from_addr] = 1
    last_byte_acked[from_addr] = 0
    last_receiver_chunkhash[from_addr] = cur_gethash
    timeout[from_addr] = 5
    Estimated_RTT[from_addr] = 4
    Dev_RTT[from_addr] = 0.25
    dupACKcount[from_addr] = 0
    cwnd[from_addr] = 1
    ssthresh[from_addr] = 64
    state[from_addr] = 0
    conges_ct[from_addr] = 0
    cwnd_list[from_addr] = []


def initialize_receiver(from_addr, cur_gethash):
    connected[from_addr] = True
    last_received[from_addr] = 0
    last_time[from_addr] = time.time()
    last_chunkhash[from_addr] = cur_gethash
    buffer[from_addr] = {-1: -1}
    byte_to_receive[from_addr] = 1
    byte_has_received[from_addr] = []


def distribute(chunkhash):
    global download_duty
    min_send = 100
    chosen_sender = None
    for sender in get_chunk_dict[chunkhash]:
        if crashed[sender]:
            continue
        cur_len = len(download_duty[sender])
        if cur_len < min_send:
            min_send = cur_len
            chosen_sender = sender
    if chosen_sender is not None:
        download_duty[chosen_sender].append(chunkhash)
    else:
        print("The distribution goes wrong. Because we cannot find any sender.")


def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash
    global get_chunk_dict
    global last_IHAVE_time
    global TOTAL_CHUNK
    global BEGIN_DOWNLOAD

    ex_output_file = outputfile
    BEGIN_DOWNLOAD = True
    # change the BEGIN_DOWNLOAD condition.

    # Step 1: read chunkhash to be downloaded from chunkfile
    with open(chunkfile, 'r') as cf:
        for line in cf.readlines():
            index, datahash_str = line.strip().split(" ")
            # The index is the num(not used now), the datahash_str is the chunkhash that need to be downloaded.
            ex_received_chunk[datahash_str] = bytes()  # Record in the dict.
            ex_downloading_chunkhash.append(datahash_str)  # Record in the list.
            TOTAL_CHUNK = TOTAL_CHUNK + 1
            get_chunk_dict[bytes.fromhex(datahash_str)] = []  # Initialize in this part.

    # Step2: make WHOHAS pkt
    whohas_pkt = []
    for cur_hash in ex_downloading_chunkhash:
        download_hash = bytes()
        datahash = bytes.fromhex(cur_hash)  # Change the hex to binary bytes.
        download_hash = download_hash + datahash  # Add the datahash.

        whohas_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 0, socket.htons(HEADER_LEN),
                                    socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
        whohas_pkt.append(whohas_header + download_hash)  # Make a whohas_pkt list.

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for pkt in whohas_pkt:
        for p in peer_list:
            if int(p[0]) != config.identity:  # Not myself
                sock.sendto(pkt, (p[1], int(p[2])))  # The parameters are ip_address, port_number.
                print('THE WHOHAS PACKET HAS BEEN SENT TO: ', p[0], p[1], int(p[2]))
    last_IHAVE_time = time.time()


def process_inbound_udp(sock):
    global config
    global HAS_SENT, HAS_RECEIVED, CONNECT_NUM, ALL_GET, BEGIN_DOWNLOAD
    global get_chunk_dict, download_duty, connected
    global last_time, last_received, last_chunkhash, last_IHAVE_time

    # 存放每个包的发送时间
    global send_time_dict
    global cwnd, ssthresh, conges_ct, state
    global last_byte_sent, last_byte_acked
    global Estimated_RTT, Dev_RTT, dupACKcount, timeout
    global alpha, beta

    global byte_to_receive, byte_has_received, buffer
    global cwnd_list

    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    # print(pkt, from_addr, Magic, Team, Type, hlen, plen, Seq, Ack, data)

    if Type == 0:  # Received an WHOHAS packet
        # see what chunk the sender has
        whohas_chunk_hash = data[:20]
        chunkhash_str = bytes.hex(whohas_chunk_hash)

        print(f"whohas: {chunkhash_str}, has: {list(config.haschunks.keys())}")
        if chunkhash_str in config.haschunks.keys():
            if HAS_SENT >= config.max_conn:
                # exceed the max send number, send back DENIED pkt
                denied_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 5, socket.htons(HEADER_LEN),
                                            socket.htons(HEADER_LEN + len(whohas_chunk_hash)), socket.htonl(0),
                                            socket.htonl(0))
                denied_pkt = denied_header + whohas_chunk_hash
                sock.sendto(denied_pkt, from_addr)
            else:
                # send back IHAVE pkt
                ihave_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 1, socket.htons(HEADER_LEN),
                                           socket.htons(HEADER_LEN + len(whohas_chunk_hash)), socket.htonl(0),
                                           socket.htonl(0))
                ihave_pkt = ihave_header + whohas_chunk_hash
                sock.sendto(ihave_pkt, from_addr)

    elif Type == 1:
        # 接受方
        # received an IHAVE pkt
        # see what chunk the sender has
        last_IHAVE_time = time.time()
        get_chunk_hash = data[:20]
        get_chunk_dict[get_chunk_hash].append(from_addr)

    elif Type == 2:
        # 发送方
        # received a GET pkt
        # 这里就应该直接按照窗口来发 但现在先不改
        cur_gethash = bytes.hex(data[:20])
        chunk_data = config.haschunks[cur_gethash][:MAX_PAYLOAD]

        # send back DATA pkt
        HAS_SENT = HAS_SENT + 1  # Update the HAS_SENT value when sending the DATA pkt.

        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(1), socket.htonl(0))
        sock.sendto(data_header + chunk_data, from_addr)
        initialize_sender(from_addr, cur_gethash)

    elif Type == 3:
        # receiver
        current_chunkhash = bytes.hex(last_chunkhash[from_addr])
        last_time[from_addr] = time.time()
        last_received[from_addr] = Seq
        # This part just for check whether the connection is constructed.

        seq_num = socket.ntohl(Seq)
        to_ack_num = byte_to_receive[from_addr] - 1

        if seq_num == byte_to_receive[from_addr]:
            ex_received_chunk[current_chunkhash] += data
            byte_to_receive[from_addr] += 1
            to_ack_num = byte_to_receive[from_addr] - 1

            if len(byte_has_received[from_addr]) != 0:
                for record in byte_has_received[from_addr]:
                    if byte_to_receive[from_addr] == record:
                        byte_has_received[from_addr].remove(record)
                        buffer_now = buffer[from_addr]
                        data_buffer = buffer_now[record]
                        ex_received_chunk[current_chunkhash] += data_buffer
                        print("buffer")
                        buffer_now[record] = bytes()
                        # data_buffer.pop(record)
                        byte_to_receive[from_addr] += 1
                        to_ack_num = byte_to_receive[from_addr] - 1
                    else:
                        break

        elif seq_num > byte_to_receive[from_addr]:
            to_ack_num = byte_to_receive[from_addr] - 1

            buffer[from_addr][seq_num] = data
            byte_has_received[from_addr].append(seq_num)

        elif seq_num < byte_to_receive[from_addr]:
            return

        # find the corresponding chunkhash, then add.
        # print("byte2re ")
        print(byte_to_receive[from_addr])
        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 4, socket.htons(HEADER_LEN),
                              socket.htons(HEADER_LEN + len(current_chunkhash)), socket.htonl(0),
                              socket.htonl(to_ack_num))
        sock.sendto(ack_pkt + bytes.fromhex(current_chunkhash), from_addr)

        # see if finished
        if len(ex_received_chunk[current_chunkhash]) == CHUNK_DATA_SIZE:
            # del byte_to_receive[from_addr]
            # del byte_has_received[from_addr]
            HAS_RECEIVED = HAS_RECEIVED + 1
            # finished downloading this chunkdata!
            # add to this peer's has-chunk:
            config.haschunks[current_chunkhash] = ex_received_chunk[current_chunkhash]
            cur_index = download_duty[from_addr].index(bytes.fromhex(current_chunkhash))
            # check whether there is more work.

            if cur_index < (len(download_duty[from_addr]) - 1):
                new_chunkhash = download_duty[from_addr][cur_index + 1]
                get_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 2, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(new_chunkhash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + new_chunkhash
                ALL_GET = False
                initialize_receiver(from_addr, new_chunkhash)
                sock.sendto(get_pkt, from_addr)
                print("Begin to deal with another work.")
                # send a new GET pkt, start the new work.

            else:
                # All the work of this sender has been done, clear it.
                connected[from_addr] = False
                last_received[from_addr] = 0
                CONNECT_NUM = CONNECT_NUM - 1

        if HAS_RECEIVED == TOTAL_CHUNK:
            # When all the chunkhash have been downloaded
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)
            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")
            BEGIN_DOWNLOAD = False

    elif Type == 4:
        # received an ACK pkt

        cur_gethash = bytes.hex(data[:20])
        ack_num = socket.ntohl(Ack)
        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            if from_addr in send_time_dict.keys():
                del send_time_dict[from_addr]

            # del last_byte_sent[from_addr], last_byte_acked[from_addr]
            # del timeout[from_addr], Estimated_RTT[from_addr], Dev_RTT[from_addr]
            # del dupACKcount[from_addr]
            # del cwnd[from_addr], ssthresh[from_addr], conges_ct[from_addr]
            last_receiver_chunkhash[from_addr] = ""

            draw_cwnd(from_addr)  # Draw the picture.
            # finished
            print(f"finished sending {cur_gethash}")

        else:

            seq_num = ack_num
            if last_byte_acked[from_addr] + 1 <= seq_num <= last_byte_sent[from_addr]:
                send_time = send_time_dict[from_addr][seq_num]
                del send_time_dict[from_addr][seq_num]
                SampleRTT = time.time() - send_time
                Estimated_RTT[from_addr] = (1 - alpha) * Estimated_RTT[from_addr] + alpha * SampleRTT
                Dev_RTT[from_addr] = (1 - beta) * Dev_RTT[from_addr] + beta * abs(
                    SampleRTT - Estimated_RTT[from_addr])
                timeout[from_addr] = Estimated_RTT[from_addr] + 4 * Dev_RTT[from_addr]
                # timeout[from_addr] = 1

                last_byte_acked[from_addr] = seq_num

                if state[from_addr] == 0:
                    dupACKcount[from_addr] = 0
                    cwnd[from_addr] += 1
                    if cwnd[from_addr] >= ssthresh[from_addr]:
                        state[from_addr] = 1
                elif state[from_addr] == 1:
                    dupACKcount[from_addr] = 0
                    conges_ct[from_addr] += 1
                    if conges_ct[from_addr] == cwnd[from_addr]:
                        conges_ct[from_addr] = 0
                        cwnd[from_addr] += 1

            elif seq_num == last_byte_acked[from_addr]:

                # 重复ack了
                dupACKcount[from_addr] += 1
                # 三次重传
                if dupACKcount[from_addr] == 3:
                    print("retransmission!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                    dupACKcount[from_addr] = 0

                    # print("re index")
                    if state[from_addr] == 1:
                        state[from_addr] = 0
                        conges_ct[from_addr] = 0

                    ssthresh[from_addr] = max(math.floor(cwnd[from_addr] / 2), 2)
                    cwnd[from_addr] = 1

                    retransmission_index = last_byte_acked[from_addr] + 1
                    # print(retransmission_index)
                    left = (retransmission_index - 1) * MAX_PAYLOAD
                    right = min(retransmission_index * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                    next_data = config.haschunks[cur_gethash][left: right]
                    # send next data
                    data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                              socket.htons(HEADER_LEN + len(next_data)),
                                              socket.htonl(retransmission_index),
                                              socket.htonl(0))
                    sock.sendto(data_header + next_data, from_addr)
                    send_time_dict[from_addr][retransmission_index] = time.time()

            cwnd_list[from_addr].append(cwnd[from_addr])
            print(last_byte_acked[from_addr])

            num_to_send = max(0, last_byte_acked[from_addr] + cwnd[from_addr] - last_byte_sent[from_addr])
            new_seq_num = last_byte_sent[from_addr]
            last_byte_sent[from_addr] = max(last_byte_acked[from_addr] + cwnd[from_addr], last_byte_sent[from_addr])

            if num_to_send > 0:
                for _ in range(num_to_send):
                    new_seq_num += 1
                    if new_seq_num * MAX_PAYLOAD <= CHUNK_DATA_SIZE:
                        left = (new_seq_num - 1) * MAX_PAYLOAD
                        right = min(new_seq_num * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[cur_gethash][left: right]
                        # send next data
                        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                                  socket.htons(HEADER_LEN + len(next_data)), socket.htonl(new_seq_num),
                                                  socket.htonl(0))
                        sock.sendto(data_header + next_data, from_addr)
                        send_time_dict[from_addr][new_seq_num] = time.time()
                    else:

                        break

    elif Type == 5:
        # received a DENIED pkt
        pass

    # print("SKELETON CODE HAS BEEN FILLED PARTIALLY.")


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def crash_check(config):
    global crashed
    print("Enter crash check.")
    current_time = time.time()
    for p in config.peers:
        target_addr = (p[1], int(p[2]))
        if not connected[target_addr]:
            continue
        if current_time - last_time[target_addr] > 5:
            #  The target peer is crashed.
            print("DETECTED: the ", target_addr, " has disconnected.")
            crashed[target_addr] = True
            current_chunkhash = last_chunkhash[target_addr]
            ex_received_chunk[current_chunkhash] = bytes()  # clear the received chunk.
            cur_index = download_duty[target_addr].index(current_chunkhash)  # check whether there is more work.
            for i in range(cur_index, len(download_duty[target_addr])):
                target_chunkhash = download_duty[target_addr][i]
                distribute(target_chunkhash)


def first_GET(sock):
    # only when all the chunkhashes have received IHAVE pkt from all the peers, then send back all GET packets.
    # First initialize the dicts.
    global CONNECT_NUM
    print("Enter first_GET")
    for p in config.peers:
        peer = (p[1], int(p[2]))
        download_duty[peer] = []
        crashed[peer] = False
        # connected[peer] = False

    # After receiving all IHAVE pkt, distribute the work.
    for cur_get_hash in get_chunk_dict.keys():
        distribute(cur_get_hash)

    for sender in download_duty.keys():
        if len(download_duty[sender]) == 0:
            continue
        current_hash = download_duty[sender][0]
        get_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 2, socket.htons(HEADER_LEN),
                                 socket.htons(HEADER_LEN + len(current_hash)), socket.htonl(0),
                                 socket.htonl(0))
        get_pkt = get_header + current_hash
        initialize_receiver(from_addr=sender, cur_gethash=current_hash)
        CONNECT_NUM = CONNECT_NUM + 1
        sock.sendto(get_pkt, sender)
        # Get the first duty of each sender. The rest duty is dealt when the last one is totally received.


def GET_check(sock):
    global ALL_GET
    cnt = 0
    if CONNECT_NUM == 0:
        return

    print("Enter GET_check.")
    for sender in connected.keys():
        if not connected[sender]:
            continue
        current_time = time.time()
        if last_received[sender] == 0:
            if current_time - last_time[sender] <= 2.0:
                continue
            get_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 2, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN + len(last_chunkhash[sender])), socket.htonl(0),
                                     socket.htonl(0))
            get_pkt = get_header + last_chunkhash[sender]
            sock.sendto(get_pkt, sender)
        else:
            cnt = cnt + 1

    if cnt == CONNECT_NUM:
        ALL_GET = True


def IHAVE_check(config, sock):
    global ALL_IHAVE

    current_time = time.time()
    cnt = 0
    if current_time - last_IHAVE_time > 1.0:
        print("Begin IHAVE_check")
        for chunkhash in get_chunk_dict.keys():
            if len(get_chunk_dict[chunkhash]) > 0:
                cnt = cnt + 1
                continue
            whohas_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 0, socket.htons(HEADER_LEN),
                                        socket.htons(HEADER_LEN + len(chunkhash)), socket.htonl(0), socket.htonl(0))
            pkt = whohas_header + chunkhash
            for p in config.peers:
                if int(p[0]) != config.identity:  # Not myself
                    sock.sendto(pkt, (p[1], int(p[2])))  # Resend the WHOHAS pkt.
        if cnt == TOTAL_CHUNK:
            ALL_IHAVE = True
            first_GET(sock)
    else:
        pass


def peer_run(config):
    global START_TIME
    START_TIME = time.time()
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            # The ready part keeps listening to both sock and sys.stdin, then deal with the pkt/input.
            read_ready = ready[0]

            if BEGIN_DOWNLOAD:
                # crash_check(config)
                if not ALL_IHAVE:
                    IHAVE_check(config, sock)
                if not ALL_GET:
                    GET_check(sock)

            # print(send_time_dict)
            # 超时检查
            for addr, value in send_time_dict.items():
                for seq, time_bf in value.items():
                    if time.time() - time_bf > timeout[addr]:
                        print("timeout!")
                        if state[addr] == 1:
                            state[addr] = 0
                            conges_ct[addr] = 0

                        ssthresh[addr] = max(math.floor(cwnd[addr] / 2), 2)
                        cwnd[addr] = 1

                        left = (seq - 1) * MAX_PAYLOAD
                        right = min(seq * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[last_receiver_chunkhash[addr]][left: right]
                        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                                  socket.htons(HEADER_LEN + len(next_data)),
                                                  socket.htonl(seq),
                                                  socket.htonl(0))
                        sock.sendto(data_header + next_data, addr)
                        send_time_dict[addr][seq] = time.time()

            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)

            else:
                # No pkt nor input arrives during this period
                pass

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. 
        The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. 
        If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. 
        If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=0)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    for p in config.peers:
        peer = (p[1], int(p[2]))
        connected[peer] = False
    peer_run(config)
