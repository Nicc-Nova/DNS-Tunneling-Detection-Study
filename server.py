import os
import argparse
import socket
import json
import time
import base64
from typing import Optional
from dataclasses import dataclass, asdict
import zlib
import dnsish

PREFIX = [b"csc321", b"mastery", b"demo"]
PREFIX_LEN = len(PREFIX)

@dataclass
class LogEvent:
    ts_ms: int
    direction: str          # "server_rx" or "server_tx"
    wire_bytes: int
    data_hex: str
    # Optional fields (only set when relevant)
    src: Optional[str] = None
    dst: Optional[str] = None
    ver: Optional[int] = None
    flags: Optional[int] = None
    msg_id: Optional[int] = None
    seq: Optional[int] = None
    total: Optional[int] = None
    crc_ok: Optional[bool] = None
    payload_ok: Optional[bool] = None
    parse_ok: Optional[bool] = None

def now_ms() -> int:
    return int(time.time() * 1000)

def log_event(path: str, ev: LogEvent) -> None:
    log_dir = os.path.dirname(path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    line = json.dumps(asdict(ev), separators=(',', ':'), ensure_ascii=False)
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
        preview = data[:80]
        
        print(f'[server] RX from {src}: bytes={len(data)} "{preview}"')

        try:
            pkt = dnsish.parse_packet(data)
            parsed_ok = True
        except dnsish.ParseError as e:
            pkt = None
            parse_err = str(e)
            print(f"[server] RX (non-dnsish) from {src}: bytes={len(data)} err={parse_err}")
            # still log raw and continue
            ev = LogEvent(
                ts_ms=now_ms(),
                direction="server_rx",
                src=src,
                wire_bytes=len(data),
                data_hex=data.hex(),
                parse_ok=False
            )
            log_event(args.log, ev)
            continue
        #parse flags
        flags = pkt.flags if pkt is not None else 0
        is_ack = bool(flags & dnsish.FLAG_ACK)
        is_data = bool(flags & dnsish.FLAG_DATA)
        is_beacon = bool(flags & dnsish.FLAG_BEACON)
        #initialize payload parsing results
        payload_raw = None
        payload_decode_ok = False
        crc_calc = None
        crc_ok = None
        #attempt to decode payload if dnsish parsing succeeded
        try:
            payload_raw = dnsish.labels_to_payload(pkt.labels_raw, skip_prefix=PREFIX_LEN)
            payload_ok = True
            #check crc if payload decoded ok
            crc_calc = dnsish.crc32_u32(payload_raw)
            crc_ok = (crc_calc == pkt.crc32)
        except Exception as e:
            payload_raw = None
            payload_ok = False
            payload_err = str(e)            
        #log results NO MATTER WHAT!
        log_event(args.log, LogEvent(
            ts_ms=now_ms(),
            direction="server_rx",
            wire_bytes=len(data),
            data_hex=data.hex(),
            src=src,
            parse_ok=True,
            payload_ok=payload_ok,
            ver=pkt.ver,
            flags=pkt.flags,
            msg_id=pkt.msg_id,
            seq=pkt.seq,
            total=pkt.total,
            crc_ok=crc_ok,
        ))

        #parse packet by flag
        if is_beacon:
            if (payload_raw is None) or (not crc_ok):
                print(f"[server] BEACON drop msg_id={pkt.msg_id} crc_ok={crc_ok}")
                continue
            print(f"[server] BEACON msg_id={pkt.msg_id} payload_len={len(payload_raw)}")
        elif is_data:
            if (payload_raw is None) or (not crc_ok):
                print(f"[server] DATA drop msg_id={pkt.msg_id} seq={pkt.seq}/{pkt.total} crc_ok={crc_ok}")
                continue

            key = (src, pkt.msg_id)  #consider adding session label
            st = messages.get(key)
            if st is None:
                st = {"total": pkt.total, "chunks": {}}
                messages[key] = st

            # store chunk (dedupe)
            if pkt.seq not in st["chunks"]:
                st["chunks"][pkt.seq] = payload_raw

            # send ACK (dnsish)
            ack_bytes = dnsish.build_packet(
                flags=dnsish.FLAG_ACK,
                labels=PREFIX,
                msg_id=pkt.msg_id,
                seq=pkt.seq,
                total=pkt.total,
                payload=None,
            )
            sock.sendto(ack_bytes, addr)

            log_event(args.log, LogEvent(
                ts_ms=now_ms(),
                direction="server_tx",
                wire_bytes=len(ack_bytes),
                data_hex=ack_bytes.hex(),
                dst=src,
                msg_id=pkt.msg_id,
                seq=pkt.seq,
                total=pkt.total,
            ))
            # reassemble if complete (simple logic assumes all chunks arrive, doesn't handle duplicates or out-of-order)
            if len(st["chunks"]) == st["total"]:
                data_out = b"".join(st["chunks"][i] for i in range(st["total"]))
                with open(args.out, "ab") as f:
                    f.write(data_out)
                print(f"[server] MESSAGE COMPLETE src={src} msg_id={pkt.msg_id} bytes={len(data_out)}")
                del messages[key]       
        elif is_ack:
            print(f'[server] RX ACK (unexpected for server)')
        else:
            print(f'[server] Unknown packet type: flags={flags}')

if __name__ == "__main__":
    main()