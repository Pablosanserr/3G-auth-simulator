from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib
import random

def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))
    
def rotate_bytes(val, r):
    return val[r:] + val[:r]
    
def algorithms_init():
    c1 = get_random_bytes(16)
    r1 = random.randint(0, 15)
    c2 = get_random_bytes(16)
    r2 = random.randint(0, 15)
    c3 = get_random_bytes(16)
    r3 = random.randint(0, 15)
    c4 = get_random_bytes(16)
    r4 = random.randint(0, 15)
    
    return c1, r1, c2, r2, c3, r3, c4, r4

# Función MAC
# Hay que truncar porque para f1 solo nos interesa los 64 primeros, MAC_A (el resto es para f1*, MAC_S)
def f1_algorithm(K, RAND, OPc, SQN, AMF, c1, r1): 
    cipher = AES.new(K, AES.MODE_ECB)
    
    val_rand = xor(RAND, OPc)
    val_rand = cipher.encrypt(val_rand)
    
    val = SQN + AMF + SQN + AMF
    val = xor(val, OPc)
    val = rotate_bytes(val, r1)
    
    val = xor(val, c1)
    val = xor(val, val_rand)
    
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    
    return val[:8]

# Funciones de derivación de clave
# Hay que separar la salida en AK (bit 0 a 47) y RES (bit 64 a 127). De f2_algorithm sacamos f2 y f5
def f2_algorithm(K, RAND, OPc, c2, r2): 
    cipher = AES.new(K, AES.MODE_ECB)
    
    val = xor(RAND, OPc)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    val = rotate_bytes(val, r2)
    val = xor(val, c2)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    
    return val
    
def f3_algorithm(K, RAND, OPc, c3, r3): 
    cipher = AES.new(K, AES.MODE_ECB)
    
    val = xor(RAND, OPc)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    val = rotate_bytes(val, r3)
    val = xor(val, c3)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    
    return val
    
def f4_algorithm(K, RAND, OPc, c4, r4): 
    cipher = AES.new(K, AES.MODE_ECB)
    
    val = xor(RAND, OPc)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    val = rotate_bytes(val, r4)
    val = xor(val, c4)
    val = cipher.encrypt(val)
    val = xor(val, OPc)
    
    return val

def foo():
    RAND = get_random_bytes(16)
    OPc = get_random_bytes(16)
    K = get_random_bytes(16)
    SQN = get_random_bytes(6)
    AMF = get_random_bytes(2)

    val = f1_algorithm(K, RAND, OPc, SQN, AMF)
    print(f"f1 val ({len(val)} bytes) = {val}")
        
    val = f2_algorithm(K, RAND, OPc)
    print(f"f2 val ({len(val)} bytes) = {val}")

    val = f3_algorithm(K, RAND, OPc)
    print(f"f3 val ({len(val)} bytes) = {val}")

    val = f4_algorithm(K, RAND, OPc)
    print(f"f4 val ({len(val)} bytes) = {val}")