from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib

from algorithms import *

def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

class UIM:
    def __init__(self, K):
        self.RAND = None
        self.AUTHN = None
        self.AUTHN_ = None
        self.K = K
        
        self.CON_SQN = None
        self.SQN = None
        self.AK = None
        self.AMF = None
        self.MAC = None
        
        self.RES = None
        self.CK = None
        self.IK = None
        
    # Funciones de intercambio de datos        
    def set_RAND(self, RAND):
        self.RAND = RAND
        
    def set_parameters(self, AUTHN):
        self.AUTHN = AUTHN
        # Se extraen los parámetros de AUTHN
        self.CON_SQN = AUTHN[:8]
        self.AMF = AUTHN[8:10]
        self.MAC = AUTHN[10:]
        
    def calc_parameters(self): # Tiene que haberse usado set_parameters previamente
        self.AK = self.f5_algorithm(self.K, self.RAND)
        self.SQN = xor(self.CON_SQN, self.AK)
        self.AUTHN_ = self.f1_algorithm(self.K, self.SQN, self.RAND, self.AMF)
        # Se comprueba que el AUTHN generado coincide con el recibido
        if self.AUTHN == self.AUTHN_:
            print("[UIM] AUTHN generado coincide con el recibido. SQN es correcto")
        else:
            print("[UIM] ERROR: AUTHN generado NO coincide con el recibido")
        # Calculamos los últimos parámetros
        self.RES = self.f2_algorithm(self.K, self.RAND)
        self.CK = self.f3_algorithm(self.K, self.RAND)
        self.IK = self.f4_algorithm(self.K, self.RAND)

class Movil:
    def __init__(self, IMSI):
        self.IMSI = IMSI
        self.RAND = None
        self.AUTHN = None
        
    def set_RAND(self, RAND):
        self.RAND = RAND
        
    def set_parameters(self, AUTHN_MAC):
        self.AUTHN = AUTHN

class Antena:
    def __init__(self):
        self.IMSI = None
        self.RAND = None
        self.XRES = None
        self.AUTHN = None
        self.CK = None
        self.IK = None
    
    def set_IMSI(self, IMSI):
        self.IMSI = IMSI
        
    def set_parameters(self, IMSI, RAND, XRES, AUTHN, CK, IK):
        self.RAND = RAND
        self.XRES = XRES
        self.AUTHN = AUTHN
        self.CK = CK
        self.IK = IK

class Operador:
    def __init__(self):
        self.IMSI = None
        self.RAND = None
        self.XRES = None
        self.AUTHN = None
        self.CK = None
        self.IK = None
        self.AV = None
        self.SQN = None
        self.CON_SQN = None
        
    def calcularCON_SQN(self, SQN, AK, K):
        CON_SQN = xor(SQN, AK) # XOR de SQN y AK
        return CON_SQN
        
    def calcularAUTHN(self, CON_SQN, AMF, MAC, K):
        AUTN = CON_SQN + AMF + MAC # 48 + 16 + 64 = 128 bits
        return AUTN
        
    def set_IMSI(self, IMSI):
        self.IMSI = IMSI
        if IMSI == "214050000000095":
            self.K = b'1234567890123456'
            self.generate_RAND()
            self.generate_SQN()
            self.AK = self.f5_algorithm(self.K, self.RAND)
            self.AMF = (33).to_bytes(2, byteorder='big') # Corresponde al IMSI
            self.MAC = self.f1_algorithm(self.K, self.SQN, self.RAND, self.AMF)
            
            # XRES
            self.XRES = self.f2_algorithm(self.K, self.RAND)
            # AUTHN
            self.CON_SQN = self.calcularCON_SQN(self.SQN, self.AK, self.K)
            self.AUTHN = self.calcularAUTHN(self.CON_SQN, self.AMF, self.MAC, self.K)
            # KEYS
            self.CK = self.f3_algorithm(self.K, self.RAND)
            self.IK = self.f4_algorithm(self.K, self.RAND)
        
    def generate_RAND(self):
        self.RAND = get_random_bytes(16)
        
    def generate_SQN(self):
        self.SQN = get_random_bytes(6)
        
    def get_parameters(self):
        return self.IMSI, self.RAND, self.XRES, self.AUTHN, self.CK, self.IK
    

# ------------------------ MAIN ------------------------

IMSI = "214050000000095"
K = b'1234567890123456'

uim = UIM(K=K)
movil = Movil(IMSI=IMSI)
antena = Antena()
operador = Operador()

# 1. Se envía el IMSI del móvil a la antena
antena.set_IMSI(movil.IMSI)

# 2. Se envía el IMSI de la antena al operador
operador.set_IMSI(antena.IMSI)

# 3. Se generan y envían los parámetros del operador a la antena
operador.set_IMSI(IMSI)
IMSI, RAND, XRES, AUTHN, CK, IK = operador.get_parameters()
antena.set_parameters(IMSI, RAND, XRES, AUTHN, CK, IK)

# 4. Se envían RAND y AUTHN->MAC de la antena al móvil
movil.set_RAND(antena.RAND)
movil.set_parameters(antena.AUTHN)

# 5. Se envían RAND y AUTHN->MAC del móvil al UIM
uim.set_RAND(movil.RAND)
uim.set_parameters(movil.AUTHN)
uim.calc_parameters()

# 6. Se generan todos los parámetros en UIM, y se envían RES, CK e IK al móvil


# 7. Se envía RES del móvil a la antena

# 8. La antena comprueba si RES == XRES y responde con OK (al móvil)

# 9. Se envía el mensaje "Hola" codificado del móvil a la antena

# 10. Se envía HMAC del móvil a la antena