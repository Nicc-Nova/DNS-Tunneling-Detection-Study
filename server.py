import  argparse
from email.mime import text
import socket
import json
import time
import os

def now_ms() -> int:
    return int(time.time() * 1000)

def log_event(path: str, event: dict) -> None:
    log_dir = os.path.dirname(path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    line = json.dumps(event, separators=(',', ':'), ensure_ascii=False)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(line + '\n')
        f.flush()

def parse_args():
    parser = argparse.ArgumentParser(description="Toy UDP server for DNS tunneling sim")
    parser.add_argument('--ip', default="127.0.0.1", help="IP address to bind (default: 127.0.0.1)")
    parser.add_argument('--port', type=int, default=53000, help="UDP Port to bind (default: 53000)")
    parser.add_argument('--log', default="logs/server.log", help="Path to JSONL log file (default: logs/server.log)")
    return parser.parse_args()

def main():
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.ip, args.port))

    print(f"[server] listening on UDP {args.ip}:{args.port}")
    print(f"[server] Logging to {args.log}")
 
    while True:
        data, addr = sock.recvfrom(65535)
        #source ip and port
        src = f"{addr[0]}:{addr[1]}"
        #parse into parts by '|', first part is type, rest is payload
        text = data.decode("utf-8", errors="replace")
        parts = text.split('|')
        ptype = parts[0] if parts else None
        #preview of text for logging
        preview = text[:50]

        print(f'[server] RX from {src}: bytes={len(data)} "{preview}"')

        #parse packet by type
        if ptype == "B": #beacon
            # expect: B|session|msg_id|ts|payload
            if len(parts) >= 5:
                session = parts[1]
                msg_id = parts[2]
                print(f'[server] BEACON session={session} msg_id={msg_id}')
            else:
                print(f'[server] Malformed BEACON')
        elif ptype == "D": #data
            # expect: D|session|msg-id|seq|total|crc|payload
            if len(parts) >= 7:
                session = parts[1]
                msg_id = parts[2]
                seq = parts[3]
                total = parts[4]
                print(f'[server] DATA session={session} msg_id={msg_id} seq={seq}/{total}')
                #Build ACK
                ack_text = f"A|{session}|{msg_id}|{seq}"
                ack_bytes = ack_text.encode("utf-8")
                sock.sendto(ack_bytes, addr)

                print(f'[server] TX ACK {ack_text}')
                log_event(args.log, {
                    "ts_ms": now_ms(),
                    "direction": "server_tx",
                    "dst": src,
                    "wire_bytes": len(ack_bytes),
                    "preview": ack_text,
                    "data": ack_bytes.hex()
                })
            else:
                print(f'[server] Malformed DATA')       
        elif ptype == "A": #ACK
            print(f'[server] RX ACK (unexpected for server)')
        else:
            print(f'[server] Unknown packet type: {ptype}')

        event = {
            "ts_ms": now_ms(),
            "direction": "server_rx",
            "src": src,
            "wire_bytes": len(data),
            "preview": preview,
            "data": data.hex()
        }
        log_event(args.log, event)

if __name__ == "__main__":
    main()