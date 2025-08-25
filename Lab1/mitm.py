#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MITM educativo SIN fuerza bruta:
- Reconstruye el mensaje desde ICMP Echo Request 'stealth' (1 char por paquete).
- Detecta la llave (corrimiento César) SIN probar 1..25 (usa mapeo de palabras de 1 letra).
- Opcional (--show-all): imprime TODAS las 25 opciones en orden (evidencia), resaltando en verde la correcta.

Requiere:
    pip install scapy
"""

import argparse
import sys
import re
from typing import List, Tuple, Optional, Dict
from scapy.all import rdpcap, ICMP, IP  # type: ignore

PING_TAIL_PATTERN = bytes(range(0x10, 0x38))  # 0x10..0x37 (16..55)

ANSI_GREEN = "\x1b[32m"
ANSI_RESET = "\x1b[0m"


# -------------------- Utilidades de payload/pcap --------------------

def is_ping_like_payload(payload: bytes, char_offset: int = 0x0F) -> bool:
    if len(payload) < 56:
        return False
    if not (0 <= char_offset < len(payload)):
        return False
    return payload[0x10:0x38] == PING_TAIL_PATTERN


def extract_stream_from_pcap(
    pcap_path: str,
    icmp_id: Optional[int] = None,
    char_offset: int = 0x0F,
) -> Tuple[str, List[Tuple[int, str]]]:
    """Reconstruye el mensaje (cifrado) y retorna (mensaje, [(seq, char)]) ordenado por seq."""
    pkts = rdpcap(pcap_path)
    candidates = []

    for p in pkts:
        if not (p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(IP)):
            continue
        raw = bytes(p[ICMP].payload)
        if not is_ping_like_payload(raw, char_offset):
            continue
        cid = p[ICMP].id
        seq = p[ICMP].seq
        ch = chr(raw[char_offset])
        candidates.append((cid, seq, ch))

    if not candidates:
        raise SystemExit("No se detectaron Echo Requests válidos con el patrón 'stealth'.")

    # Si no se especifica ID, tomar el más frecuente
    if icmp_id is None:
        from collections import Counter
        icmp_id = Counter([c[0] for c in candidates]).most_common(1)[0][0]

    stream = [(seq, ch) for cid, seq, ch in candidates if cid == icmp_id]
    if not stream:
        raise SystemExit(f"No hay paquetes con ICMP id=0x{icmp_id:04x}.")

    stream.sort(key=lambda x: x[0])
    message = "".join(ch for _, ch in stream)
    return message, stream


# -------------------- César y heurística --------------------

def caesar_decode(ciphertext: str, shift: int) -> str:
    out = []
    for c in ciphertext:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 - shift) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 - shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


COMMON_WORDS = [
    " el ", " la ", " de ", " en ", " y ", " que ",
    " los ", " las ", " un ", " una ", " por ", " con ", " para ", " se ", " es ",
    " criptografia", " seguridad", " redes", " mensaje", " claro"
]

def score_spanish(text: str) -> float:
    t = " " + text.lower() + " "
    score = 0.0
    for w in COMMON_WORDS:
        if w in t:
            score += 3.0
    vowels = sum(t.count(v) for v in "aeiouáéíóú ")
    score += vowels / max(len(t), 1)
    rare = sum(t.count(x) for x in "#$%{}[]|\\^~`")
    score -= rare * 2.0
    return score


# -------------------- Detección de llave sin brute-force --------------------

def detect_shift_no_bruteforce(ciphertext: str) -> Tuple[int, str, List[Dict[str, str]]]:
    """
    Detecta el shift SIN probar 1..25:
    - Busca palabras de 1 letra en el cifrado (p. ej. 'h').
    - Mapea esa letra a posibles palabras de 1 letra del español: ['y','a','o','e'].
    - A partir del mapeo calcula shift = (cifrado - plano) mod 26.
    - Puntea cada hipótesis y elige la mejor.
    Retorna: (best_shift, best_plain, evidencias)
    """
    tokens_1 = re.findall(r"(?<![A-Za-z])([A-Za-z])(?![A-Za-z])", ciphertext)
    tokens_1 = [t.lower() for t in tokens_1]

    if not tokens_1:
        raise SystemExit("No se detectaron palabras de 1 letra en el cifrado para inferir la llave.")

    one_letter_plains = ["y", "a", "o", "e"]

    evidencias = []
    mejores = []

    for ciph_letter in sorted(set(tokens_1)):
        for plain_letter in one_letter_plains:
            shift = (ord(ciph_letter) - ord(plain_letter)) % 26
            if shift == 0:
                continue
            plain = caesar_decode(ciphertext, shift)
            sc = score_spanish(plain)
            evidencias.append({
                "cifrado_1l": ciph_letter,
                "plano_1l": plain_letter,
                "shift": str(shift),
                "score": f"{sc:.3f}",
                "preview": plain[:80].replace("\n", " ")
            })
            mejores.append((sc, shift, plain))

    if not mejores:
        raise SystemExit("No fue posible inferir un corrimiento válido.")

    mejores.sort(reverse=True, key=lambda x: x[0])
    best_sc, best_shift, best_plain = mejores[0]
    return best_shift, best_plain, evidencias


# -------------------- CLI --------------------

def main():
    ap = argparse.ArgumentParser(description="MITM ICMP sin fuerza bruta (detección de llave)")
    ap.add_argument("pcap", help="Ruta a .pcap/.pcapng")
    ap.add_argument("--id", type=lambda x: int(x, 0), default=None,
                    help="ICMP identifier (ej. 0x9244). Si no se da, se detecta automáticamente.")
    ap.add_argument("--offset", type=lambda x: int(x, 0), default=0x0F,
                    help="Offset del carácter en el payload (default 0x0F).")
    ap.add_argument("--strip-last-b", action="store_true",
                    help="Si el mensaje termina en 'b' centinela, recórtala antes de detectar.")
    ap.add_argument("--show-options", action="store_true",
                    help="Muestra todas las hipótesis evaluadas (cifrado→plano de 1 letra).")
    ap.add_argument("--show-all", action="store_true",
                    help="Imprime TODAS las 25 opciones 1..25 en orden (solo evidencia).")
    args = ap.parse_args()

    ciphertext, _ = extract_stream_from_pcap(args.pcap, args.id, args.offset)

    if args.strip_last_b and ciphertext.endswith("b"):
        ciphertext = ciphertext[:-1]

    print("Reconstruido desde ICMP (cifrado):")
    print(ciphertext)
    print()

    tokens_1 = re.findall(r"(?<![A-Za-z])([A-Za-z])(?![A-Za-z])", ciphertext)
    tokens_1 = [t.lower() for t in tokens_1]
    if tokens_1:
        print(f"Palabras de 1 letra detectadas en el cifrado (evidencia): {sorted(set(tokens_1))}\n")

    best_shift, best_plain, evidencias = detect_shift_no_bruteforce(ciphertext)

    if args.show_options:
        print("Hipótesis evaluadas (cifrado→plano, shift, score, preview):")
        for e in evidencias:
            print(f"  {e['cifrado_1l']} → {e['plano_1l']}  shift={e['shift']:>2}  "
                  f"score={e['score']:>6}  {e['preview']}")
        print()

    print(f"Shift detectado (sin fuerza bruta): {ANSI_GREEN}{best_shift}{ANSI_RESET}")
    print("Texto plano estimado:")
    print(f"{ANSI_GREEN}{best_plain}{ANSI_RESET}")
    print()

    # --- Evidencia completa (sin usarla para detectar) ---
    if args.show_all:
        print("TODAS las opciones 1..25 (evidencia; la correcta en verde):")
        for s in range(1, 26):
            dec = caesar_decode(ciphertext, s)
            if s == best_shift:
                print(f"{ANSI_GREEN}{s:2d}: {dec}{ANSI_RESET}")
            else:
                print(f"{s:2d}: {dec}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
