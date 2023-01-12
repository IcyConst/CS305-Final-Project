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
import hashlib
import argparse
import pickle
import time

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
# Record that how many packets have been sent by this peer.
HAS_RECEIVED = 0
config = None
# Note that the config will be initialized at the beginning of the procedure.
ex_output_file = None
ex_received_chunk = dict()
ex_sending_chunkhash = ""
# Todo: Do we need to consider the condition that one peer send more than one chunks? Change it to a list?
ex_downloading_chunkhash = []
# Consider that there are more than one chunkhashes to download, so we need a list.
get_chunk_dict = dict()

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


def process_download(sock, chunkfile, outputfile):
    """
    if DOWNLOAD is used, the peer will keep getting files until it is done
    """
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash

    ex_output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile

    with open(chunkfile, 'r') as cf:
        for line in cf.readlines():
            index, datahash_str = line.strip().split(" ")
            # print(index, datahash_str)
            # The index is the num(not used now), the datahash_str is the chunkhash that need to be downloaded.
            ex_received_chunk[datahash_str] = bytes()  # Record in the dict.
            ex_downloading_chunkhash.append(datahash_str)  # Record in the list.

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte type |1byte team|
    # |2byte  header len  |2byte pkt len |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_pkt = []
    for cur_hash in ex_downloading_chunkhash:
        download_hash = bytes()
        # hex_str to bytes
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


def process_inbound_udp(sock):
    global config
    global ex_sending_chunkhash
    # global ex_received_chunk
    # global ex_downloading_chunkhash
    global HAS_SENT
    global HAS_RECEIVED
    global get_chunk_dict
    # 存放每个包的发送时间
    global send_time_dict

    global cwnd
    global ssthresh
    global conges_ct
    global state
    global last_byte_sent
    global last_byte_acked
    global timeout
    global Estimated_RTT
    global Dev_RTT
    global dupACKcount
    global alpha
    global beta

    global byte_to_receive
    global byte_has_received
    global buffer

    global cwnd_list
    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Team, Type, hlen, plen, Seq, Ack = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    # print(pkt, from_addr, Magic, Team, Type, hlen, plen, Seq, Ack, data)

    if Type == 0:  # Received an WHOHAS packet
        # see what chunk the sender has
        whohas_chunk_hash = data[:20]
        # bytes to hex_str
        chunkhash_str = bytes.hex(whohas_chunk_hash)
        # ex_sending_chunkhash = chunkhash_str

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
                ex_sending_chunkhash = chunkhash_str  # When send back IHAVE pkt, then change ex_sending.
                sock.sendto(ihave_pkt, from_addr)



    elif Type == 1:
        # 接受方
        # received an IHAVE pkt
        # see what chunk the sender has
        get_chunk_hash = data[:20]
        if get_chunk_hash in get_chunk_dict.keys():
            pass
        else:
            get_chunk_dict[get_chunk_hash] = from_addr

        # send back GET pkt
        # only when all the chunkhashes have received IHAVE pkt, then send back all GET packets.
        if len(get_chunk_dict) == len(ex_downloading_chunkhash):
            for cur_get_hash in get_chunk_dict.keys():
                get_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 2, socket.htons(HEADER_LEN),
                                         socket.htons(HEADER_LEN + len(cur_get_hash)), socket.htonl(0),
                                         socket.htonl(0))
                get_pkt = get_header + cur_get_hash
                sock.sendto(get_pkt, get_chunk_dict[cur_get_hash])  # The values in the dict save the from_addr.
                buffer[get_chunk_dict[cur_get_hash]] = {-1: -1}

        byte_to_receive[from_addr] = 1
        byte_has_received[from_addr] = []

    elif Type == 2:
        # 发送方
        # received a GET pkt
        # 这里就应该直接按照窗口来发 但现在先不改
        chunk_data = config.haschunks[ex_sending_chunkhash][:MAX_PAYLOAD]
        # chunk_data = config.haschunks[data[:20]][:MAX_PAYLOAD]  # Use the information that from the pkt.

        # send back DATA pkt

        HAS_SENT = HAS_SENT + 1  # Update the HAS_SENT value when sending the DATA pkt.

        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(1), socket.htonl(0))
        # data_header = struct.pack("HBBHHII", socket.htons(52305), 58, 3, socket.htons(HEADER_LEN),
        #                           socket.htons(HEADER_LEN + len(chunk_data)), socket.htonl(1), socket.htonl(0))
        sock.sendto(data_header + chunk_data, from_addr)
        send_time_dict[from_addr] = {1: time.time()}

        last_byte_sent[from_addr] = 1
        last_byte_acked[from_addr] = 0
        timeout[from_addr] = 5
        Estimated_RTT[from_addr] = 4
        Dev_RTT[from_addr] = 0.25
        # alpha[from_addr] = 0.125
        # beta[from_addr] = 0.25
        dupACKcount[from_addr] = 0
        cwnd[from_addr] = 1
        ssthresh[from_addr] = 64
        state[from_addr] = 0
        conges_ct[from_addr] = 0
        cwnd_list[from_addr] = []


    elif Type == 3:
        # receiver
        current_chunkhash = bytes.hex(get_dict_key(get_chunk_dict, from_addr))
        # see if finished
        if len(ex_received_chunk[current_chunkhash]) < CHUNK_DATA_SIZE:
            seq_num = socket.ntohl(Seq)
            to_ack_num = byte_to_receive[from_addr] - 1

            # buffer[from_addr][seq_num] = data
            # print(buffer)
            to_seq_num = 0
            if seq_num == byte_to_receive[from_addr]:
                ex_received_chunk[current_chunkhash] += data
                byte_to_receive[from_addr] += 1
                to_ack_num = byte_to_receive[from_addr] - 1

                buffer_now = buffer[from_addr]
                if seq_num in buffer_now:
                    buffer_now[seq_num] = bytes()

                if len(byte_has_received[from_addr]) != 0:
                    title = min(byte_has_received[from_addr]) - 1
                    while True:
                        title += 1
                        if title == byte_to_receive[from_addr] and title in byte_has_received[from_addr]:
                            byte_has_received[from_addr].remove(title)
                            buffer_now = buffer[from_addr]
                            data_buffer = buffer_now[title]
                            ex_received_chunk[current_chunkhash] += data_buffer
                            print("the data stored in buffer has been added!")
                            buffer_now[title] = bytes()
                            byte_to_receive[from_addr] += 1
                            to_ack_num = byte_to_receive[from_addr] - 1
                        else:
                            break
                # for record in byte_has_received[from_addr]:
                #     print(f'{byte_to_receive[from_addr]}vs{record}')
                #     if byte_to_receive[from_addr] == record:
                #         byte_has_received[from_addr].remove(record)
                #         buffer_now = buffer[from_addr]
                #         data_buffer = buffer_now[record]
                #         ex_received_chunk[current_chunkhash] += data_buffer
                #         print("the data stored in buffer has been added!")
                #         buffer_now[record] = bytes()
                #         # data_buffer.pop(record)
                #         byte_to_receive[from_addr] += 1
                #         to_ack_num = byte_to_receive[from_addr] - 1
                #     else:
                #         break
            elif seq_num > byte_to_receive[from_addr]:
                to_seq_num = seq_num
                to_ack_num = byte_to_receive[from_addr] - 1

                buffer[from_addr][seq_num] = data
                byte_has_received[from_addr].append(seq_num)
            elif seq_num < byte_to_receive[from_addr]:
                return

            # find the corresponding chunkhash, then add.
            # print("byte2re ")
            print(f'The receiver wants to get package {byte_to_receive[from_addr]}')
            print(f'the buffer in receiver stores {byte_has_received[from_addr]} pkts')
            # send back ACK
            ack_pkt = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 4, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN), socket.htonl(to_seq_num), socket.htonl(to_ack_num))
            sock.sendto(ack_pkt, from_addr)
            print('')

        if len(ex_received_chunk[current_chunkhash]) == CHUNK_DATA_SIZE:
            # print(f'{len(ex_received_chunk[current_chunkhash])} vs {CHUNK_DATA_SIZE}')
            if from_addr in byte_to_receive:
                print("finish receiving the chunk")
                del byte_to_receive[from_addr]
                del byte_has_received[from_addr]
                HAS_RECEIVED = HAS_RECEIVED + 1
                # finished downloading this chunkdata!
                # add to this peer's has-chunk:
                config.haschunks[current_chunkhash] = ex_received_chunk[current_chunkhash]

                if HAS_RECEIVED == len(ex_downloading_chunkhash):
                    # When all the chunkhash have been downloaded
                    # dump your received chunk to file in dict form using pickle
                    with open(ex_output_file, "wb") as wf:
                        pickle.dump(ex_received_chunk, wf)
                    # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
                    print(f"GOT {ex_output_file}")

    elif Type == 4:
        print(f'the state of the sender is {state[from_addr]}')

        # received an ACK pkt
        # Note that in Type 4, because there is only one file now, so we just use ex_sending_chunkhash is OK.
        cwnd_list[from_addr].append(cwnd[from_addr])
        ack_num = socket.ntohl(Ack)
        if_dup_seq_num = socket.ntohl(Seq)
        if ack_num * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            print(send_time_dict[from_addr])

            del send_time_dict[from_addr]

            del last_byte_sent[from_addr]
            del last_byte_acked[from_addr]
            del timeout[from_addr]
            del Estimated_RTT[from_addr]
            del Dev_RTT[from_addr]
            # del alpha[from_addr]
            # del beta[from_addr]
            del dupACKcount[from_addr]
            del cwnd[from_addr]
            del ssthresh[from_addr]
            del conges_ct[from_addr]
            print(f'the sender received ack {ack_num}')
            # finished
            print(f"finished sending {ex_sending_chunkhash}")
            it_num = len(cwnd_list[from_addr])
            x = list(range(1, it_num + 1))
            y = cwnd_list[from_addr]
            print(x)
            print(y)

            plt.plot(x, y)
            plt.title('Line Plot')
            plt.xlabel('time')
            plt.ylabel('window size')

            plt.savefig('line_plot.png')

        else:
            # 这个包当时发过去时的seq
            seq_num = ack_num
            # if last_byte_acked[from_addr] + 1 <= seq_num <= last_byte_sent[from_addr]:
            if last_byte_acked[from_addr] + 1 <= seq_num <= last_byte_sent[from_addr]:
                # update timeout refreshing

                # send_time = send_time_dict[from_addr][seq_num]
                # del send_time_dict[from_addr][seq_num]

                acked_num = seq_num - last_byte_acked[from_addr]

                # 本次ack正常更新
                if seq_num in send_time_dict[from_addr]:
                    print(f'timeout is previously {timeout[from_addr]}')
                    send_time = send_time_dict[from_addr][seq_num]
                    del send_time_dict[from_addr][seq_num]
                    SampleRTT = time.time() - send_time
                    Estimated_RTT[from_addr] = (1 - alpha) * Estimated_RTT[from_addr] + alpha * SampleRTT
                    Dev_RTT[from_addr] = (1 - beta) * Dev_RTT[from_addr] + beta * abs(
                        SampleRTT - Estimated_RTT[from_addr])
                    timeout[from_addr] = Estimated_RTT[from_addr] + 4 * Dev_RTT[from_addr]
                    # timeout[from_addr] = 1
                    print(f'received new ack, sampleRTT is {SampleRTT}')
                    print(f'timeout is updated to {timeout[from_addr]}')


                # 收到逐一增加的ack
                if acked_num == 1:
                    pass
                # 返回的ack表示接受方使用了缓存
                else:
                    min_num_in_dict = min(send_time_dict[from_addr])
                    send_time_problem = send_time_dict[from_addr][min_num_in_dict]
                    del send_time_dict[from_addr][min_num_in_dict]

                    SampleRTT = time.time() - send_time_problem
                    Estimated_RTT[from_addr] = (1 - alpha) * Estimated_RTT[from_addr] + alpha * SampleRTT
                    Dev_RTT[from_addr] = (1 - beta) * Dev_RTT[from_addr] + beta * abs(
                        SampleRTT - Estimated_RTT[from_addr])
                    timeout[from_addr] = Estimated_RTT[from_addr] + 4 * Dev_RTT[from_addr]
                    print(f'buffered ack arrived, time is {SampleRTT}, timeout is updated to {timeout[from_addr]}')

                    # to_del = acked_num - 1
                    # for ct in range(to_del):
                    #     del send_time_dict[from_addr][ct + min_num_in_dict]

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
                elif state[from_addr] == 2:
                    state[from_addr] = 1
                    dupACKcount[from_addr] = 0
                    cwnd[from_addr] = ssthresh[from_addr]


            elif seq_num == last_byte_acked[from_addr]:
                # if_dup_ack_num
                print(f'dup time update timeout is previously {timeout[from_addr]}')
                send_time = send_time_dict[from_addr][if_dup_seq_num]
                del send_time_dict[from_addr][if_dup_seq_num]
                SampleRTT = time.time() - send_time
                Estimated_RTT[from_addr] = (1 - alpha) * Estimated_RTT[from_addr] + alpha * SampleRTT
                Dev_RTT[from_addr] = (1 - beta) * Dev_RTT[from_addr] + beta * abs(
                    SampleRTT - Estimated_RTT[from_addr])
                timeout[from_addr] = Estimated_RTT[from_addr] + 4 * Dev_RTT[from_addr]
                # timeout[from_addr] = 1
                print(f'received new ack, sampleRTT is {SampleRTT}')
                print(f'timeout is updated to {timeout[from_addr]}')


                # duplicated ACK
                if state[from_addr] == 0 or state[from_addr] == 1:
                    dupACKcount[from_addr] += 1
                elif state[from_addr] == 2:
                    print("DuplicatedACK in fast recovery")
                    cwnd[from_addr] = cwnd[from_addr] + 1
                # 三次重传
                if state[from_addr] != 2:
                    if dupACKcount[from_addr] == 3:
                        print("retransmission!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

                        # retransmission
                        if state[from_addr] == 0:
                            state[from_addr] = 2
                            ssthresh[from_addr] = max(math.floor(cwnd[from_addr] / 2), 2)
                            cwnd[from_addr] = ssthresh[from_addr] + 3
                        elif state[from_addr] == 1:
                            state[from_addr] = 2
                            ssthresh[from_addr] = max(math.floor(cwnd[from_addr] / 2), 2)
                            cwnd[from_addr] = ssthresh[from_addr] + 3
                            conges_ct[from_addr] = 0

                        dupACKcount[from_addr] += 1
                        # 加一个就是4了
                        retransmission_index = last_byte_acked[from_addr] + 1

                        left = (retransmission_index - 1) * MAX_PAYLOAD
                        right = min((retransmission_index) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[ex_sending_chunkhash][left: right]
                        # send next data
                        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                                  socket.htons(HEADER_LEN + len(next_data)),
                                                  socket.htonl(retransmission_index),
                                                  socket.htonl(0))
                        sock.sendto(data_header + next_data, from_addr)
                        send_time_dict[from_addr][retransmission_index] = time.time()
                        print(f'The sender sends pkt{retransmission_index} in retransmission')

            print(f'The sender has already received {last_byte_acked[from_addr]} packages')
            print(f'the sender received ack {seq_num}')
            print(f'the sender received real_ack(buffered){if_dup_seq_num}')
            print(f'the window size now is {cwnd[from_addr]}')
            print(f'the ssthresh is {ssthresh[from_addr]}')
            print(f'the EstimatedRTT is {Estimated_RTT[from_addr]}')
            print(f'the DevRTT is {Dev_RTT[from_addr]}')
            print(f'the timeout is set to{timeout[from_addr]}')

            num_to_send = max(0, last_byte_acked[from_addr] + cwnd[from_addr] - last_byte_sent[from_addr])
            new_seq_num = last_byte_sent[from_addr]
            last_byte_sent[from_addr] = max(last_byte_acked[from_addr] + cwnd[from_addr], last_byte_sent[from_addr])

            if num_to_send > 0:
                for _ in range(num_to_send):
                    new_seq_num += 1
                    if new_seq_num * MAX_PAYLOAD <= CHUNK_DATA_SIZE:
                        left = (new_seq_num - 1) * MAX_PAYLOAD
                        right = min((new_seq_num) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[ex_sending_chunkhash][left: right]
                        # send next data
                        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                                  socket.htons(HEADER_LEN + len(next_data)), socket.htonl(new_seq_num),
                                                  socket.htonl(0))
                        sock.sendto(data_header + next_data, from_addr)
                        send_time_dict[from_addr][new_seq_num] = time.time()
                        print(f'The sender sends pkt {new_seq_num}')
                    else:
                        break

            print('')
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
            # print(send_time_dict)

            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)

            else:
                # No pkt nor input arrives during this period
                pass

            # 超时检查
            for addr, value in send_time_dict.items():
                for seq, time_bf in value.items():
                    if time.time() - time_bf > timeout[addr]:
                        print("timeout!!!!!!!")
                        print(f'the timeout pkt is {seq}')
                        print(f'the actual time is {time.time() - time_bf}')
                        print(f'the timeout now is {timeout[addr]}')
                        # SampleRTT = time.time() - time_bf
                        # Estimated_RTT[addr] = (1 - alpha) * Estimated_RTT[addr] + alpha * SampleRTT
                        # Dev_RTT[addr] = (1 - beta) * Dev_RTT[addr] + beta * abs(SampleRTT - Estimated_RTT[addr])
                        # timeout[addr] = Estimated_RTT[addr] + 4 * Dev_RTT[addr]
                        timeout[addr] = timeout[addr] * 2
                        Estimated_RTT[addr] = Estimated_RTT[addr] * 2
                        Dev_RTT[addr] = Dev_RTT[addr] * 2
                        print(f'timeout is updated to {timeout[addr]}')

                        if state[addr] == 1:
                            state[addr] = 0
                            conges_ct[addr] = 0
                        if state[addr] == 2:
                            state[addr] = 0

                        ssthresh[addr] = max(math.floor(cwnd[addr] / 2), 2)
                        cwnd[addr] = 1
                        dupACKcount[addr] = 0

                        left = (seq - 1) * MAX_PAYLOAD
                        right = min((seq) * MAX_PAYLOAD, CHUNK_DATA_SIZE)
                        next_data = config.haschunks[ex_sending_chunkhash][left: right]
                        data_header = struct.pack("HBBHHII", socket.htons(52305), TEAM_NUM, 3, socket.htons(HEADER_LEN),
                                                  socket.htons(HEADER_LEN + len(next_data)),
                                                  socket.htonl(seq),
                                                  socket.htonl(0))
                        sock.sendto(data_header + next_data, addr)
                        send_time_dict[addr][seq] = time.time()
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
    peer_run(config)
