#!/usr/bin/env python

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# 1) Change the variable my_eth_address with your address                                           #
# 2) Execute and keep the script running with nohup: nohup python mining_fees_remover.py &          #
# 3) Offer me a coffee: 0xe25833086cf84239fb05ba10db30a54c30c7185a (Optional)                       #
# based on:                                                                                         #
# https://stackoverflow.com/questions/27293924/change-tcp-payload-with-nfqueue-scapy?rq=1           #
# https://github.com/DanMcInerney/cookiejack/blob/master/cookiejack.py                              #
# https://github.com/gkovacs/remove_miner_fees                                                      #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import nfqueue
from scapy.all import *
import os
import re
from os import path

os.system('iptables -A OUTPUT -o eth0 -p tcp --dport 4444 -j NFQUEUE --queue-num 0')
os.system('iptables -A FORWARD -p tcp --dport 4444 -j NFQUEUE --queue-num 0')

my_eth_address = '0xe25833086cf84239fb05ba10db30a54c30c7185a'

logfile = open('/var/log/remove_mining_fees_log.txt', 'w', 0)

def callback(arg1, payload):
  data = payload.get_data()
  pkt = IP(data)
  payload_before = len(pkt[TCP].payload)
  payload_text = str(pkt[TCP].payload)
  if "eth_submitLogin" in payload_text:
    if my_eth_address not in payload_text:
      payload_text = re.sub(r'0x.{40}', my_eth_address, payload_text)
  pkt[TCP].payload = payload_text
  payload_after = len(payload_text)
  payload_dif = payload_after - payload_before
  pkt[IP].len = pkt[IP].len + payload_dif
  pkt[IP].payload_textttl = 40

  del pkt[IP].chksum
  del pkt[TCP].chksum
  payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
  logfile.write(payload_text)
  logfile.write('\n')
  logfile.flush()
def main():
  q = nfqueue.queue()
  q.open()
  q.bind(socket.AF_INET)
  q.set_callback(callback)
  q.create_queue(0)
  try:
    q.try_run() # Main loop
  except KeyboardInterrupt:
    q.unbind(socket.AF_INET)
    q.close()
    if path.exists('./restart_iptables'):
      os.system('./restart_iptables')

main()
