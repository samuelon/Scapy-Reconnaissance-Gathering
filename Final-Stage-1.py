# %%
import pandas as pd
from pandas import ExcelWriter
from pandas import ExcelFile
from scapy.all import *
import csv


#Author: Samuel On
#Email: Samuelon@my.yorku.ca
#Course: EECS 4482 
#Project: Scapy Programming Project


# %%
#A
#takes in packet with ICMP
#Device is responsive [yes/no]: <obtained answer>
def DeviceResponse(pkt):
    ansA, unans = sr(pkt,timeout=5)
    answerA="No"
    if (len(ansA)> 0):
        responseA = ansA[0][1].sprintf("%ICMP.type%")
        if responseA == "echo-reply":
            answerA = "Yes"
        else:
            answerA = "No"
    else:
        answerA="No"
        
    return answerA

#B
#takes in packet with ICMP
#IP-ID counter deployed by device (in ICMP pkts) [zero/incremental/random]: <obtained answer>
def ICMP_IP_ID(pkt):
    ansB, unB = srloop(pkt,count = 5)
    answerB="null"
    if (len(ansB)>3):
        diffOne = ansB[0][1].id - ansB[1][1].id
        diffTwo = ansB[1][1].id - ansB[2][1].id

        if (ansB[0][1].id == ansB[1][1].id and ansB[1][1].id == ansB[2][1].id):
            answerB = "zero"
        elif (diffOne == diffTwo and diffOne != None):
            answerB = "incremental"
        else:
            answerB = "random"
    else: 
        answerB="null"
    return answerB
#C
#takes in packet with TCP, dport=80, flags="S"
#Port 80 on device is open [yes/no]: <obtained answer>
def isPort80Open(pkt):
    ansC, unC = sr(pkt, timeout=10)
    isPort80Opened="No"
    if (len(ansC)>0):
        cResponse = ansC[0][1].sprintf("%TCP.flags%")
        if cResponse == "SA":
            isPort80Opened="Yes"
        else:
            isPort80Opened="No"
            
    return isPort80Opened

#D
#takes in packet with TCP, dport=80, flags="S"
#IP-ID counter deployed by device (in TCP pkts) [zero/incremental/random]: <obtained answer>
def TCP_IP_ID(pkt):
    ansD, unD = srloop(pkt,count = 5)
    answerD="null"
    if (len(ansD)>3):
        
        diffOneD = ansD[0][1].id - ansD[1][1].id
        diffTwoD = ansD[1][1].id - ansD[2][1].id
        if (ansD[0][1].id == ansD[1][1].id and ansD[1][1].id == ansD[2][1].id):
            answerD = "zero"
        elif (diffOneD == diffTwoD and diffOneD != None):
            answerD = "incremental"
        else:
            answerD = "random"
    else: 
        answerD="null"
    return answerD
#E
#takes in packet with TCP, dport=80, flags="S"
#SYN cookies deployed by device [yes/no]: <obtained answer>
def SYN_Cookie(pkt):
    ansE, unE = sr(pkt,timeout=60)
    answerE = "No"
    if (len(ansE)>0):
        if(len(ansE)>1):
            answerE= "Yes"
    return answerE

#F
#takes in packet with ICMP
#Likely OS system deployed on the device [Linux/Windows]: <obtained answer>
def OS_Check(pkt):
    ansF, unF = sr(pkt,timeout=5)
    answerF="null"
    WINDOWSTTL = 128
    LINUXTTL = 64
    CISCOTTL = 256
    if (len(ansF)>0):
        if (ansF[0][1].ttl<= LINUXTTL):
            answerF="Linux"
        elif (ansF[0][1].ttl <= WINDOWSTTL):
            answerF="Windows"
        else:
            answerF="Cisco"
    return answerF
            
#Append to file
def appendDataRow(ip,a,b,c,d,e,f):
    dataRow = [ip,a,b,c,d,e,f]
    with open('Stage-2.csv', 'a', newline='') as file:
        mywriter = csv.writer(file, delimiter=',')
        mywriter.writerow(dataRow)



# %%
def main():
    df = pd.read_excel('./shodan_data.xlsx')
    ipAddrs = df['IP']
    usedIpArray= []
    for i in df.index:
        if(ipAddrs[i] not in usedIpArray):
            print(ipAddrs[i])
            #rememeber to change the 0 to i
            pktA = IP(dst=ipAddrs[i])/ICMP()
            answerA = DeviceResponse(pktA)
            print(answerA)

            if (answerA == "Yes"):
                pktB = IP(dst=ipAddrs[i])/ICMP()
                answerB= ICMP_IP_ID(pktB)
                print(answerB)

                pktC = IP(dst=ipAddrs[i])/TCP(dport=80,flags="S")
                answerC= isPort80Open(pktC)
                print(answerC)

                if (answerC=="Yes"):
                    pktD = IP(dst=ipAddrs[i])/TCP(dport=80,flags="S")
                    answerD= TCP_IP_ID(pktD)
                    print(answerD)

                    pktE = IP(dst=ipAddrs[i])/TCP(dport=80,flags="S")
                    answerE= SYN_Cookie(pktE)
                    print(answerE)

                    pktF = IP(dst=ipAddrs[i])/ICMP()
                    answerF= OS_Check(pktF)
                    print(answerF)
                else:
                    pktF = IP(dst=ipAddrs[i])/ICMP()
                    answerF= OS_Check(pktF)
                    print(answerF)
            else:
                answerB=answerC=answerD=answerE=answerF="null"
            usedIpArray.append(ipAddrs[i])
            appendDataRow(ipAddrs[i],answerA,answerB,answerC,answerD,answerE,answerF)
    
if __name__ == "__main__":
    main()

# %%
