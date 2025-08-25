import sys

def cesar_cipher(texto, corrimiento):
    resultado = ""
    for char in texto.lower():  # pasamos todo a minúsculas
        if char.isalpha():  # solo letras
            # convertir a número 0-25
            base = ord('a')
            nuevo = (ord(char) - base + corrimiento) % 26
            resultado += chr(base + nuevo)
        else:
            # dejamos espacios y otros símbolos igual
            resultado += char
    return resultado

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py \"texto a cifrar\" corrimiento")
        sys.exit(1)

    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])

    print(cesar_cipher(texto, corrimiento))
