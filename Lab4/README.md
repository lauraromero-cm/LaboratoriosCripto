# Cifrado Simétrico CBC - Lab 4

Herramienta de cifrado simétrico que implementa DES, AES-256 y 3DES en modo CBC con padding PKCS#7.

## Requisitos

- Python 3.12 o superior
- pip (gestor de paquetes de Python)

## Instalación

### 1. Crear entorno virtual

```bash path=null start=null
python3 -m venv .venv
```

### 2. Activar entorno virtual

```bash path=null start=null
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash path=null start=null
pip install pycryptodome
```

## Ejecución

```bash path=null start=null
python cifrado_simetrico.py
```

## Uso

El programa solicita los siguientes datos para cada algoritmo (DES, AES-256, 3DES):

1. **KEY**: Clave de cifrado (texto plano o hexadecimal)
2. **IV**: Vector de inicialización (texto plano o hexadecimal)
3. **TEXTO**: Mensaje a cifrar

### Especificaciones de tamaño

| Algoritmo | Clave     | IV       | Bloque   |
|-----------|-----------|----------|----------|
| DES       | 8 bytes   | 8 bytes  | 8 bytes  |
| AES-256   | 32 bytes  | 16 bytes | 16 bytes |
| 3DES      | 16-24 bytes | 8 bytes | 8 bytes  |

**Nota**: Si la clave/IV son más cortos se rellenan con bytes aleatorios; si son más largos se truncan.

### Formato de entrada

- **Texto plano**: `mipassword`
- **Hexadecimal**: `001122aabbccddee` o `0x001122aabbccddee`

## Ejemplo

```bash path=null start=null
$ python cifrado_simetrico.py

=== CBC Tool: DES / AES-256 / 3DES ===

Ingrese la KEY: secretkey
Ingrese el IV: initvect
Ingrese el TEXTO a cifrar: Hola Mundo

Clave final usada (8 bytes): 73656372657463a1
IV final usado (8 bytes): 696e697476656374

--- CIFRADO ---
Ciphertext (hex): a1b2c3d4e5f60708
Ciphertext (Base64): obLD1OX2Bwg=

--- DESCIFRADO ---
Texto descifrado: Hola Mundo
```

## Desactivar entorno virtual

```bash path=null start=null
deactivate
```
