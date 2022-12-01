import scapy.all as scapy
import argparse

print('''░▒▓█►─═  N⋆E⋆T⋆ ⋆S⋆C⋆A⋆N⋆E⋆R⋆ ⋆B⋆Y⋆ ⋆T⋆H⋆O⋆U⋆F⋆E⋆E ═─◄█▓▒░''')

def pass_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="IP range")
    opts = parser.parse_args()
    return opts
def scan(ip):
    req = scapy.ARP(pdst = ip)
    mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = mac/req
    ans_pac = scapy.srp(arp_request,timeout=5,verbose=False)[0]

    print(" \nIP \t\t\t   Mac Address \n------------------------------------------------")
    for response in ans_pac:
        print(response[1].psrc + "\t\t" + response[1].hwsrc)
        print("------------------------------------------------")

opts = pass_args()
scan(opts.target)
