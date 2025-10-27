import base64
import binascii
from typing import Tuple

from Crypto.Cipher import DES, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# ---- parametros por algoritmo segun especificaciones ----
# des: algoritmo histórico con clave de 8 bytes (64 bits, 56 efectivos + 8 paridad)
#      bloque de 8 bytes.
# aes-256: algoritmo moderno con clave de 32 bytes (256 bits), bloque de 16 bytes
# 3des: extension de des que aplica cifrado tres veces (ede: encrypt-decrypt-encrypt)
#       clave de 16 o 24 bytes.

# ---- Parametros por algoritmo ----
ALG_PARAMS = {
    "DES":   {"key_len": 8,  "iv_len": 8,  "block": 8},
    "AES256": {"key_len": 32, "iv_len": 16, "block": 16},
    "3DES":  {"key_len": (16, 24), "iv_len": 8, "block": 8},  # 2-key o 3-key
}

def _looks_like_hex(s: str) -> bool:
    # detecta si una cadena representa datos hexadecimales validos
    # permite formato con o sin prefijo 0x
    # permite entrada de claves/iv en formato hex
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def _to_bytes(user_input: str) -> bytes:
    # convierte entrada de usuario (texto o hex) a bytes
    # acepta claves/iv como texto plano o hexadecimal
    s = user_input.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if _looks_like_hex(s):
        return binascii.unhexlify(s)
    return s.encode("utf-8")

def _fit_length(data: bytes, needed: int) -> bytes:
    """Trunca o rellena con bytes aleatorios hasta 'needed'."""
    # ajusta longitud de clave/iv segun requisitos del algoritmo
    # - si es menor: completa con bytes aleatorios usando get_random_bytes
    # - si es mayor: trunca a la longitud necesaria
    # - si es exacta: la devuelve sin modificar
    if len(data) == needed:
        return data
    if len(data) > needed:
        return data[:needed]
    # es menor: rellenar con aleatorios
    missing = needed - len(data)
    return data + get_random_bytes(missing)

def _normalize_3des_key(key: bytes) -> bytes:
    """Ajusta key 3DES a 16 o 24 bytes y corrige paridad."""
    # ajusta clave para 3des con características especiales del algoritmo
    # 3des (triple des) aplica des tres veces con esquema ede (encrypt-decrypt-encrypt):
    # - 2-key (16 bytes): k1-k2-k1 (menos seguro pero compatible)
    # - 3-key (24 bytes): k1-k2-k3 (más seguro, recomendado)
    # requiere ajuste de paridad para compatibilidad con des original
    if len(key) < 16:
        key = _fit_length(key, 16)
    elif 16 <= len(key) < 24:
        # elegimos 24 para 3-key por defecto si el usuario supera 16
        key = _fit_length(key, 24)
    elif len(key) > 24:
        key = key[:24]

    # ajustar paridad y evitar claves debiles/ilegales especificas de des/3des
    # des requiere bits de paridad correctos y evita claves conocidas como debiles
    while True:
        try:
            key = DES3.adjust_key_parity(key)
            # Verifica que sea válida para DES3 (no weak/degenerate)
            DES3.new(key, DES3.MODE_ECB)
            return key
        except ValueError:
            # generar 1 byte aleatorio al final y reintentar
            key = key[:-1] + get_random_bytes(1)

def _prepare_key_iv(alg: str, key_in: str, iv_in: str) -> Tuple[bytes, bytes, int]:
    # prepara clave e iv para el algoritmo especificado
    # cvalidación y ajuste de clave para cada algoritmo
    # maneja casos especiales como la paridad en 3des
    params = ALG_PARAMS[alg]
    key_raw = _to_bytes(key_in)
    iv_raw = _to_bytes(iv_in)

    if alg == "3DES":
        # 3des requiere manejo especial por paridad y claves debiles
        key = _normalize_3des_key(key_raw)
        iv = _fit_length(iv_raw, params["iv_len"])
    else:
        # des y aes usan ajuste estandar de longitud
        key = _fit_length(key_raw, params["key_len"])
        iv  = _fit_length(iv_raw,  params["iv_len"])

    return key, iv, params["block"]

def encrypt_cbc(alg: str, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # funcion de cifrado para cada algoritmo usando modo cbc
    # - implementa funcion para cada algoritmo (des, aes-256, 3des)
    # - usa modo cbc para todos los algoritmos
    # - utiliza iv proporcionado por usuario
    #
    # modo cbc (cipher block chaining):
    # - cada bloque se xor con el anterior antes del cifrado
    # - el primer bloque se xor con el iv
    # - evita patrones repetitivos en el texto cifrado
    
    if alg == "DES":
        # des: algoritmo historico, clave 8 bytes, bloque 8 bytes
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    elif alg == "AES256":
        # aes-256: algoritmo moderno, clave 32 bytes, bloque 16 bytes
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif alg == "3DES":
        # 3des: aplica des tres veces (ede)
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    else:
        raise ValueError("Algoritmo no soportado.")

    # aplicar padding pkcs#7 y cifrar
    ct = cipher.encrypt(pad(plaintext, cipher.block_size))
    return ct

def decrypt_cbc(alg: str, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # funcion de descifrado para cada algoritmo usando modo cbc
    # - implementa función de descifrado para cada algoritmo
    # - usa modo cbc (mismo que cifrado pero inverso)
    # - utiliza mismo iv usado en cifrado
    #
    # descifrado cbc:
    # - descifra cada bloque individualmente
    # - aplica xor con bloque cifrado anterior (o iv para el primero)
    # - resultado es el texto plano original
    
    if alg == "DES":
        # des: proceso inverso de sustituciones y permutaciones
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    elif alg == "AES256":
        # aes-256: proceso inverso de rondas de transformación
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif alg == "3DES":
        # 3des: proceso ded (decrypt-encrypt-decrypt), inverso de ede
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    else:
        raise ValueError("Algoritmo no soportado.")

    # descifrar y remover padding pkcs#7
    pt = unpad(cipher.decrypt(ciphertext), cipher.block_size)
    return pt

def _hex(b: bytes) -> str:
    # convierte bytes a representación hexadecimal para mostrar al usuario
    return binascii.hexlify(b).decode("ascii")

def run_for_algorithm(alg_label: str):
    # ejecuta proceso completo para un algoritmo específico
    # 1. solicita key, iv y texto desde terminal
    # 2. valida y ajusta clave/iv 
    # 3. imprime clave final después de ajustes
    # 4. cifra y descifra usando funciones específicas
    # 5. imprime tanto texto cifrado como descifrado
    print("\n" + "=" * 64)
    print(f"[{alg_label}]  (Modo: CBC, Padding: PKCS#7)")
    print("=" * 64)

    #solicitar datos desde terminal
    key_in = input("Ingrese la KEY (texto o hex p.ej. 001122...): ").strip()
    iv_in  = input("Ingrese el IV  (texto o hex p.ej. 001122...): ").strip()
    txt_in = input("Ingrese el TEXTO a cifrar: ").rstrip("\n")

    #validacion y ajuste de clave
    key, iv, _ = _prepare_key_iv(alg_label, key_in, iv_in)
    print(f"Clave final usada ({len(key)} bytes): { _hex(key) }")
    print(f"IV final usado     ({len(iv)} bytes): { _hex(iv) }")

    #imprimir clave final después de ajustes
    plaintext = txt_in.encode("utf-8")
    ciphertext = encrypt_cbc(alg_label, key, iv, plaintext)

    # proceso de cifrado usando funcion especifica del algoritmo
    print("\n--- CIFRADO ---")
    print("Ciphertext (hex):", _hex(ciphertext))
    print("Ciphertext (Base64):", base64.b64encode(ciphertext).decode("ascii"))

    #imprimir texto cifrado
    decrypted = decrypt_cbc(alg_label, key, iv, ciphertext)
    print("\n--- DESCIFRADO ---")
    try:
        # proceso de descifrado usando funcion especifica del algoritmo
        print("Texto descifrado:", decrypted.decode("utf-8"))
    except UnicodeDecodeError:
        # Si el texto original no era UTF-8, mostramos hex
        print("Texto descifrado (hex):", _hex(decrypted))
    
    #imprimir texto descifrado

def main():
    print("=== CBC Tool: DES / AES-256 / 3DES ===")
    print("\nREQUERIMIENTOS DE TAMAÑO:")
    print("  DES:    key=8 bytes,  iv=8 bytes,  bloque=8")
    print("  AES-256:key=32 bytes, iv=16 bytes, bloque=16")
    print("  3DES:   key=16 o 24 bytes, iv=8 bytes, bloque=8")
    print("\nNOTA: Si la clave/IV son más cortos, se rellenan con bytes ALEATORIOS; si son más largos, se truncan.")
    print("      Clave/IV pueden ingresarse como texto o como hex (ej. 001122aabbcc...).")

    for alg in ("DES", "AES256", "3DES"):
        run_for_algorithm(alg)

if __name__ == "__main__":
    main()

