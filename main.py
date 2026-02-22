#       2026 - Elijah Martin, GNU General Public License v3.0 
#       SniffThis - A simple packet sniffer written in Python using Scapy
#       The intention of this program was to learn scapy and focus on low-level 
#       networking concepts. It is not intended to be a full-featured packet sniffer, 
#       but rather a learning tool for those interested in network programming and security.

''' IMPORTS'''
from scapy.all import *
import sys
import asyncio
import os
import psutil
import time
from tabulate import tabulate
from datetime import datetime
from colorama import init, Fore, Style
'''
DEFINITIONS
'''



CMD_LIST = ["help", "startsniffer", "stopsniffer", "exit", "iflist", "ifselect", "curif"]

CMD_EXPLANATIONS = ["help           <::>    Provides list of commands.  SYNTAX: help <command>", 
                    "startsniffer   <::>    Starts the packet sniffer.  SYNTAX: startsniffer <-t> <-n>",
                    "stopsniffer    <::>    Stops the packet sniffer.   SYNTAX: stopsniffer",
                    "exit           <::>    Exits our of the CLI.       SYNTAX: exit",
                    "iflist         <::>    Lists Network Interfaces.   SYNTAX: iflist",
                    "ifselect       <::>    Sets Active Interface.      SYNTAX: ifselect <interface>.",
                    "curif          <::>    Shows Active Interface.     SYNTAX: curif."
                    ]


'''
CREATE A CLASS FOR THE CLI.
'''
class SniffThisCLI:

    # INITIALIZE AND SET ENVIRONEMENT
    def __init__(self):
        global CMD_LIST
        global CMD_EXPLANATIONS
        init(autoreset=True)
        self.SYS_EXIT = False
        self.prefix = f'{Fore.GREEN} {os.getlogin()}{Fore.WHITE}@{Fore.BLUE}SniffThis:{Fore.WHITE}' # CLI Prefix
        self.interfaces = {0:"Wi-FI"}   # INIT with default value.
        self.selectedInterface = "Wi-Fi" # Active Interface

    # RUN LOOP
    async def run(self):
        
        while self.SYS_EXIT == False:
            cmd = input(f"{self.prefix} ")
            self.CmdHandler(cmd)
        
        # Exit on self.SYS_EXIT being True.
        else:
            print("Exiting SniffThis CLI.... Goodbye.")
            await asyncio.sleep(2)
            sys.exit()
    
    # COMMAND HANDLER
    def CmdHandler(self, cmd_raw):

        # Use our parser to remove spaces and separate arguments.
        cmd = self.parse(cmd_raw)
        
        # Error handling for commands not defined.
        if cmd[0] not in CMD_LIST:
            print(f"COMMAND NOT FOUND. TYPE 'help' for assistance...")
        
        # 'help' command.
        elif cmd[0] == CMD_LIST[0]:
            if len(cmd) == 2:
                print(cmd[1])
                self.help(cmd[1])
            elif len(cmd) > 2:
                print("Command 'help' takes 1 argument only.")
            else:
                self.help()
        # 'startSniffer' command
        elif cmd[0] == CMD_LIST[1]:
            num = 10
            vbs = True
            pcap = None
            t = None
            if '-n' in cmd:
                num = int(cmd[cmd.index("-n") + 1])
            if '-v' in cmd:
                vbs = True
            if '-pcap' in cmd:
                pcap = str(cmd[cmd.index("-pcap") + 1])
            if '-t' in cmd:
                t = str(cmd[cmd.index("-t") + 1])
                print(t)
            self.pcapture(num, vbs, pcap, t=t)

        # 'iflist' command
        elif cmd[0] == CMD_LIST[4]:
            self.iflist()
        
        # 'ifselect' command
        elif cmd[0] == CMD_LIST[5]:
            try:
                self.ifselect(int(cmd[1]))
            except:
                print("Incorrect Syntax")
                self.help("ifselect")

        # 'curif' command
        elif cmd[0] == CMD_LIST[6]:
            print(f"\nCurrent Interface: {self.selectedInterface}")
        
        # SYS EXIT handling.
        elif cmd[0] == CMD_LIST[3]:
            self.SYS_EXIT = True

    # Packet capture
    def pcapture(self, ct=10, verbose=True, pcap=None, save=False, t=None):
        result = None
        print(f"Capturing packets with the following arguments: {str(ct)} | {str(verbose)} | pcap: {str(pcap)}")
        #try:
        sniffer = AsyncSniffer(count=ct, iface=self.selectedInterface)
        time.sleep(1)
        sniffer.start()
        while sniffer.running:
            time.sleep(0.5)
        packets = sniffer.results
        parsedPackets = self.packetParse(packets)
        if parsedPackets:
            print(t)
            if t != None:
                if t == "ip":
                    print(f"\n{Style.NORMAL}===========Captured IP Packets===========\n")
                    print(Style.DIM + tabulate(parsedPackets[0], headers="keys", tablefmt="grid"))
                if t == "eth":
                    print(f"\n{Style.NORMAL}===========Captured Eth Packets===========\n")
                    print(Style.DIM + tabulate(parsedPackets[1], headers="keys", tablefmt="grid"))
                if t == "arp":
                    print(f"\n{Style.NORMAL}===========Captured ARP Packets===========\n")
                    print(Style.DIM + tabulate(parsedPackets[2], headers="keys", tablefmt="grid"))
                if t == "unk":
                    print(f"\n{Style.NORMAL}===========Captured Unkown Packets===========\n")
                print(Style.DIM + tabulate(parsedPackets[3], headers="keys", tablefmt="grid"))
            else:
                print(f"\n{Style.NORMAL}===========Captured IP Packets===========\n")
                print(Style.DIM + tabulate(parsedPackets[0], headers="keys", tablefmt="grid"))
                print(f"\n{Style.NORMAL}===========Captured Eth Packets===========\n")
                print(Style.DIM + tabulate(parsedPackets[1], headers="keys", tablefmt="grid"))
                print(f"\n{Style.NORMAL}===========Captured ARP Packets===========\n")
                print(Style.DIM + tabulate(parsedPackets[2], headers="keys", tablefmt="grid"))
                print(f"\n{Style.NORMAL}===========Captured Unkown Packets===========\n")
                print(Style.DIM + tabulate(parsedPackets[3], headers="keys", tablefmt="grid"))

    # Parse packet information into useful data.
    def packetParse(self, packets):
        pkt_ip = []
        pkt_eth = []
        pkt_arp = []
        pkt_unk = []
        for pkt in packets:
            if 'IP' in pkt:
                ip_entry = {
                    'time' : datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S'),
                    "src" : pkt['IP'].src,
                    "dst" : pkt['IP'].dst,
                    "proto" : pkt['IP'].proto,
                    "len" : pkt['IP'].len
                }
                
                if "TCP" in pkt:
                    ip_entry["sport"] = pkt["TCP"].sport
                    ip_entry["dport"] = pkt["TCP"].dport
                elif "UDP" in pkt:
                    ip_entry["sport"] = pkt["UDP"].sport
                    ip_entry["dport"] = pkt["UDP"].dport
                pkt_ip.append(ip_entry)

            elif pkt.haslayer("Ether") and not pkt.haslayer("IP"):
                eth_entry = {
                    'time' : datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S'),
                    "type": "L2-Ethernet",
                    "src_mac": pkt["Ether"].src,
                    "dst_mac": pkt["Ether"].dst,
                    "eth_type": hex(pkt["Ether"].type)
                    }
                pkt_eth.append(eth_entry)
                
            elif pkt.haslayer("ARP"):
                arp_entry = {
                    'time' : datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S'),
                    "type": "ARP",
                    "operation": "who-has" if pkt["ARP"].op == 1 else "is-at",
                    "source": pkt["ARP"].hwsrc,
                    "target_ip": pkt["ARP"].pdst
                }
                pkt_arp.append(arp_entry)
            else:
                unk_entry = {
                    'time' : datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S'),
                    'src' : pkt.src,
                    'dst' : pkt.dst,
                    'proto' : pkt.proto,
                    'payload' : pkt['Raw'].load.decode('utf-8', errors='ignore')
                }
                pkt_unk.append(unk_entry)
        return pkt_ip, pkt_eth, pkt_arp, pkt_unk

    # List Network Interfaces
    def iflist(self):
        x = 0
        self.interfaces = {}
        print("========Network Interfaces========")
        for iface in psutil.net_if_addrs().keys():
            print(f"|ID|{x}|---------------| {iface}")
            self.interfaces[x] = iface
            x += 1
        print("========Network Interfaces========")

    # Interface Selector, defaults to wifi
    def ifselect(self, arg=0):
        for scapy_iface in conf.ifaces.values():
            if scapy_iface.description == self.interfaces[arg] or scapy_iface.name == self.interfaces[arg]:
                self.selectedInterface = self.interfaces[arg]
                print(f"Selected interface: {self.selectedInterface}")
                return
        print(f"No scapy interfaces found matching: {arg}... Defaulting to interface 'Wi-Fi'.")
        self.selectedInterface = "Wi-Fi"
        print(f"Selected interface: {self.selectedInterface}")

    # Help Command
    def help(self, arg=None):
        print("\nSniffThis CLI - 2026 Elijah Martin GNU License\n")
        if arg:
            try:
                print(CMD_EXPLANATIONS[CMD_LIST.index(arg)])
            except:
                print(f"No help for command {arg} found.")
        else:
            for i in CMD_LIST:
                print(CMD_EXPLANATIONS[CMD_LIST.index(i)])
    
    # Simple parser for our commands, separates each argument into an array.
    def parse(self, cmd):
        cmdList = cmd.split()
        print(cmdList) # Print Debug
        return cmdList



# STARTS THE MAIN LOOP
if __name__ == "__main__":
    asyncio.run(SniffThisCLI().run()) # Start the loop