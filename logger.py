import logging

logging.basicConfig(filename='firewall.log', level=logging.INFO)

def log_packet(packet, reason):
    logging.info(f"Blocked packet: {packet.summary()} | Reason: {reason}")
