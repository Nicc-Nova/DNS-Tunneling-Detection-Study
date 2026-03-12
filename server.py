import os
import  argparse
import socket
import json
import time
import base64
import zlib

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
    parser.add_argument('--out', default="output", help="Directory to write complete messages (default: output)")
    return parser.parse_args()

def main():
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.ip, args.port))
    messages = {}

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
                crc_hex = parts[5]
                payload_b32 = parts[6]
                print(f'[server] DATA session={session} msg_id={msg_id} seq={seq}/{total}')
                #decode payload
                try:
                    payload_raw = base64.b32decode(payload_b32, casefold=True)
                except Exception as e:
                    print(f"[server] base32 decode failed: {e}")
                    payload_raw = None
                #check crc
                crc_calc = zlib.crc32(payload_raw) & 0xffffffff if payload_raw is not None else None
                crc_calc_hex = f"{crc_calc:08x}" if crc_calc is not None else None
                crc_ok = (crc_calc_hex == crc_hex)
                if not crc_ok:
                    print(f"[server] CRC mismatch: expected {crc_hex} calculated {crc_calc_hex}")
                    #TODO: log rx with crc_ok = false
                    continue
                #store chunk
                key = (session, msg_id)
                st = messages.get(key)
                if st is None:
                    st = {"total": int(total), "chunks": {}}
                    messages[key] = st
                    #total should match, if not prefer first seen
                if seq not in st["chunks"]:
                    st["chunks"][seq] = payload_raw
                else:
                    #duplicate chunk, ignore
                    pass
                #Build ACK
                ack_text = f"A|{session}|{msg_id}|{seq}"
                ack_bytes = ack_text.encode("utf-8")
                sock.sendto(ack_bytes, addr)
                # reassemble message if complete
                if len(st["chunks"]) == st["total"]:
                    data_out = b''.join(st["chunks"][str(i)] for i in range(1, st["total"]+1))
                    out_path = args.out
                    with open(out_path, 'ab') as f:
                        f.write(data_out)
                    print(f'[server] MESSAGE COMPLETE session={session} msg_id={msg_id} total_bytes={len(data_out)}')
                    del messages[key]
                #log ACK tx
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