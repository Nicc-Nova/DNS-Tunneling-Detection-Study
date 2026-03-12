import argparse
import os
import socket
import time

import dnsish


PREFIX = [b"csc321", b"mastery", b"demo"]
PREFIX_LEN = len(PREFIX)

def now_ms() -> int:
    return int(time.time() * 1000)


def require_localhost(ip: str, port: int) -> None:
    if ip not in ("127.0.0.1", "localhost"):
        raise SystemExit("Refusing to run: server must be 127.0.0.1/localhost for this lab.")
    if port == 53:
        raise SystemExit("Refusing to run: do not use port 53 for this lab. Pick 53000+.")


def send_packet(sock: socket.socket, server, pkt_bytes: bytes) -> None:
    sock.sendto(pkt_bytes, server)


def recv_ack(sock: socket.socket, expect_msg_id: int, expect_seq: int, timeout_s: float) -> bool:
    sock.settimeout(timeout_s)
    try:
        data, _ = sock.recvfrom(65535)
    except socket.timeout:
        return False

    try:
        p = dnsish.parse_packet(data)
    except dnsish.ParseError:
        return False

    if (p.flags & dnsish.FLAG_ACK) == 0:
        return False
    if p.msg_id != expect_msg_id:
        return False
    if p.seq != expect_seq:
        return False
    return True


def build_beacon(msg_id: int, text: str) -> bytes:
    payload = text.encode("utf-8")
    labels = dnsish.payload_to_labels(payload, PREFIX)
    return dnsish.build_packet(
        flags=dnsish.FLAG_BEACON,
        labels=labels,
        msg_id=msg_id,
        seq=0,
        total=1,
        payload=payload,
    )


def build_data_chunk(msg_id: int, seq: int, total: int, chunk: bytes) -> bytes:
    labels = dnsish.payload_to_labels(chunk, PREFIX)
    return dnsish.build_packet(
        flags=dnsish.FLAG_DATA,
        labels=labels,
        msg_id=msg_id,
        seq=seq,
        total=total,
        payload=chunk,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Localhost-only toy DNS-ish UDP agent (lab harness).")
    ap.add_argument("--server-ip", default="127.0.0.1")
    ap.add_argument("--server-port", type=int, default=53000)
    ap.add_argument("--file", default=None, help="File to send as DATA chunks (optional).")
    ap.add_argument("--chunk-size", type=int, default=120)
    ap.add_argument("--msg-id", type=int, default=1)
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--ack-timeout", type=float, default=0.5)
    ap.add_argument("--interactive", action="store_true", help="Press Enter to send file (if provided).")
    args = ap.parse_args()

    require_localhost(args.server_ip, args.server_port)
    server = (args.server_ip, args.server_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))  # ephemeral local port
    local = sock.getsockname()
    print(f"[agent] bound udp://{local[0]}:{local[1]} -> udp://{server[0]}:{server[1]}")

    # 1) Send one BEACON
    beacon_text = f"beacon ts_ms={now_ms()}"
    beacon_pkt = build_beacon(args.msg_id, beacon_text)
    send_packet(sock, server, beacon_pkt)
    print(f"[agent] TX BEACON msg_id={args.msg_id} bytes={len(beacon_pkt)}")

    # 2) Optionally send file as DATA chunks
    if not args.file:
        print("[agent] no --file provided; done.")
        return

    if args.interactive:
        input("[agent] press Enter to send file...")

    if not os.path.exists(args.file):
        raise SystemExit(f"[agent] file not found: {args.file}")

    data = open(args.file, "rb").read()
    chunks = [data[i:i + args.chunk_size] for i in range(0, len(data), args.chunk_size)]
    total = len(chunks)
    print(f"[agent] sending {args.file} bytes={len(data)} chunks={total} chunk_size={args.chunk_size}")

    # Stop-and-wait: send chunk i, wait for ACK i, retry if needed
    for seq, chunk in enumerate(chunks):
        pkt = build_data_chunk(args.msg_id, seq, total, chunk)

        ok = False
        for attempt in range(1, args.retries + 1):
            send_packet(sock, server, pkt)
            print(f"[agent] TX DATA msg_id={args.msg_id} seq={seq}/{total-1} bytes={len(pkt)} attempt={attempt}")

            if recv_ack(sock, args.msg_id, seq, timeout_s=args.ack_timeout):
                print(f"[agent] RX ACK msg_id={args.msg_id} seq={seq}")
                ok = True
                break

        if not ok:
            raise SystemExit(f"[agent] failed to get ACK for seq={seq} after {args.retries} retries")

    print("[agent] done.")


if __name__ == "__main__":
    main()