from scapy.all import *

OPTIONS = [
        "eth0",
        "eth1",
        "eth2"
]

#print(type(ifaces))
#print(ifaces)
choose_nic = ifaces.dev_from_index(10)
ifaces.show()



