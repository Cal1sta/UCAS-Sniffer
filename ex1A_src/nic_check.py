from scapy.all import *
from scapy.arch.windows import get_windows_if_list
OPTIONS = []

NIC_list = get_windows_if_list()
#print(type(NIC_list))
#print(len(NIC_list))
for i in range(len(NIC_list)):
        OPTIONS.append(NIC_list[i]['description'])
        #print(NIC_list[i]['description'])




