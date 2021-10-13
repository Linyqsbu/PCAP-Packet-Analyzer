import datetime

import dpkt
from dpkt.ip import IP
sender="130.245.145.12."
receiver="128.208.2.198."

win_scale={}
class Packet_Structure:

    def __init__(self, timestamp, ip_packet):
        self.timestamp=timestamp#when was this packet sent
        self.srcip=""
        for b in ip_packet.src:
            self.srcip+=str(b)+"."
        self.destip=""
        for b in ip_packet.dst:
            self.destip+=str(b)+"."
        tcp=ip_packet.data
        self.ack_num=tcp.ack
        self.seq_num=tcp.seq
        self.receive_win=tcp.win

        self.srcport=tcp.sport
        self.destport=tcp.dport

        self.data=tcp.data

        flags=bin(tcp.flags)[2:].zfill(6)
        self.syn_flag = int(flags[-2])
        self.ack_flag = int(flags[-5])
        self.fin_flag = int(flags[-1])

        self.length=len(tcp)

        self.data_length=len(tcp.data)
        if self.srcport not in win_scale:
            if tcp.opts:
                options=dpkt.tcp.parse_opts(tcp.opts)
                for opt in options:
                    if opt[0]==3:
                        if self.syn_flag==1 and self.ack_flag==1:
                            win_scale["receiver"] = 2 ** (int.from_bytes(opt[1], byteorder="big"))
                        else:
                            win_scale[self.srcport]=2**(int.from_bytes(opt[1], byteorder="big"))

            if self.srcip==receiver:
                win_scale[self.srcport]=win_scale["receiver"]

            elif self.srcport not in win_scale:
                win_scale[self.srcport]=0


if __name__=="__main__":
    #name="assignment2.pcap"
    name=input("Please enter the file name: ")
    packets=dpkt.pcap.Reader(open(name,"rb"))
    packet_list=[]
    for element in packets:
        eth=dpkt.ethernet.Ethernet(element[1])
        if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip=eth.data
        if (ip.p==6):
            packet=Packet_Structure(element[0],ip)
            #packet=Packet_Structure(element)
            packet_list.append(packet)

    tcp_flows={}
    for packet in packet_list:
        if packet.srcip==sender:#group the packets by unique ports on the sender side
            if packet.srcport not in tcp_flows:
                tcp_flows[packet.srcport]=[packet]

            else:
                tcp_flows[packet.srcport].append(packet)

        elif packet.destip==sender:#group the packets by unique ports on the sender side
            if packet.destport not in tcp_flows:
                tcp_flows[packet.destport] = [packet]

            else:
                tcp_flows[packet.destport].append(packet)



    list=[]

    for port in tcp_flows:
        total_bytes=0
        syn = False
        fin = False
        ack = False
        templist=[]
        for packet in tcp_flows[port]:

            if packet.srcip==sender:
                if packet.syn_flag==1:
                    syn=True

                if syn and ack:
                    total_bytes+=packet.length

                elif syn and not ack:
                    if packet.ack_flag==1:#in case the ack in the three way handshake is piggybacked
                        ack=True
                        if packet.data:
                            total_bytes+=packet.length

            if syn:
                templist.append(packet)

            #if there is a syn and fin, this means that a tcp flow is established
            if syn and fin:
                list.append((packet.srcport, packet.destport, templist, total_bytes))#make a 4-tuple of source port, dest port, all packets in the flow, and total sender throughput
                templist = []#refresh the list
                syn = False#start of a new flow
                fin = False#start of a new flow
                ack=False#start of a new flow
                total_bytes = 0

            if packet.srcip==receiver:
                if packet.fin_flag==1:
                    fin = True

    tcp_flows=list

    num_flows=len(tcp_flows)
    print("There are "+str(num_flows)+" tcp flows")
    print()
    i=1
    if num_flows>0:
        for flow in tcp_flows:
            print("Flow #"+str(i)+":")
            print("Source Port: "+str(flow[0]))
            print("Source IP: "+sender)
            print("Destination Port: "+str(flow[1]))
            print("Destination IP: "+receiver)
            print()


            count=0
            index=-1#the index of the packet from the sender in the first transaction
            syn=False
            ack=False
            for packet in flow[2]:
                index+=1
                if packet.srcip==sender:
                    if packet.syn_flag==1:
                        syn=True
                    if packet.ack_flag==1:
                        ack=True
                    if syn and ack:
                        break

            if not flow[2][index].data:
                index+=1

            while flow[2][index].srcip != sender:
                index+=1

            start=flow[2][index].timestamp
            #the first two transactions
            for j in range(index, len(flow[2])):

                if(flow[2][index].srcip==flow[2][j].destip):

                    print("Transaction #"+str(count+1)+":")
                    print(str(flow[2][index].srcport) + " -> " + str(flow[2][index].destport))
                    print("Sequence Number: "+str(flow[2][index].seq_num))
                    print("Ack Number: "+str(flow[2][index].ack_num))
                    print("Receive Window: "+str(flow[2][index].receive_win*(win_scale[flow[2][index].srcport]))+" bytes")
                    print()
                    print(str(flow[2][j].srcport)+" -> "+str(flow[2][j].destport))
                    print("Sequence Number: " + str(flow[2][j].seq_num))
                    print("Ack Number: " + str(flow[2][j].ack_num))
                    print("Receive Window: " + str(flow[2][j].receive_win*(win_scale[flow[2][j].srcport]))+" bytes")
                    index=index+1
                    count+=1
                    print()

                if(count>=2):
                    break

            #sender throughput
            time=flow[2][-1].timestamp-start
            print("Sender throughput: "+str(round(flow[3]/time))+" bytes/second")
            print()

            index = -1
            syn=False
            ack=False


            for packet in flow[2]:
                index += 1
                if packet.srcip==sender:#on the sender side, if there's a syn and an ack, then we know where the first transaction starts
                    if packet.syn_flag == 1:
                        syn = True
                    if packet.ack_flag == 1:
                        ack=True
                    if syn and ack:
                        break

            if not flow[2][index].data:
                index+=1

            while flow[2][index].srcip!=sender:
                index+=1

            #first three congestion window size
            cwnds=[]#list of congestion window sizes
            count=0
            first_unack_index=index
            acks=[]
            for x in range(index, len(flow[2])):
                if flow[2][x].srcip==sender:
                    acks.append(flow[2][x].data_length+flow[2][x].seq_num)

                if flow[2][x].destip==sender:
                    if flow[2][x].ack_num in acks:
                        cwnds.append(len(acks))
                        acks.clear()

                if len(cwnds)==3:
                    break

            print("First 3 congestion window sizes: ")
            for win in cwnds:
                print(str(win)+" packets")
            print()

            index = -1
            syn = False
            ack = False

            for packet in flow[2]:
                index += 1
                if packet.srcip == sender:  # on the sender side, if there's a syn and an ack, then we know where the first transaction starts
                    if packet.syn_flag == 1:
                        syn = True
                    if packet.ack_flag == 1:
                        ack = True
                    if syn and ack:
                        break

            if not flow[2][index].data:
                index += 1

            while flow[2][index].srcip != sender:
                index += 1

            #timeout retransmission and triple duplicate retransmission
            sender_retrsm={}#sender retransmission, key is seq number
            start_time = flow[2][0].timestamp
            for x in range(index, len(flow[2])):
                packet=flow[2][x]
                if packet.srcip==sender:
                    if packet.seq_num in sender_retrsm:
                        num=sender_retrsm[packet.seq_num]+1
                        sender_retrsm[packet.seq_num]=num

                    else:
                        sender_retrsm[packet.seq_num]=1



            triple_dup_loss=0
            time_out_loss=0


            for seq in sender_retrsm:
                num = sender_retrsm[seq]
                if num >= 2:
                    index=0
                    count=0
                    for packet in flow[2]:
                        if packet.seq_num==seq:
                            count+=1
                        if count==2:
                            break
                        index+=1

                    count=0
                    for x in range(index):
                        if flow[2][x].srcip==receiver:
                            if flow[2][x].ack_num==seq:
                                count+=1

                    if count>=3:
                        triple_dup_loss+=1

                    else:
                        time_out_loss+=1

            print("Retransmission due to triple duplicates: "+str(triple_dup_loss))
            print("Retransmission due to time out: "+str(time_out_loss))
            i += 1
            print("-------------------------------------------------------------------------")






