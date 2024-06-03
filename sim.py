from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib

from algorithms import *

def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))

class UIM:
    def __init__(self, K, OPc, c1, r1, c2, r2, c3, r3, c4, r4):
        self.c1 = c1
        self.r1 = r1
        self.c2 = c2
        self.r2 = r2
        self.c3 = c3
        self.r3 = r3
        self.c4 = c4
        self.r4 = r4
        
        self.RAND = None
        self.AUTHN = None
        self.MAC_ = None
        self.K = K
        self.OPc = OPc
        
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
        self.AK = f2_algorithm(self.K, self.RAND, self.OPc, self.c2, self.r2)[:6] # Bits 0 a 47
        self.SQN = xor(self.CON_SQN, self.AK)
        self.MAC_ = f1_algorithm(self.K, self.RAND, self.OPc, self.SQN, self.AMF, self.c1, self.r1)
        # Se comprueba que el valor de MAC generado coincide con el recibido
        if self.MAC == self.MAC_:
            print("[UIM] El valor de la MAC generado coincide con el recibido. SQN es correcto")
        else:
            print("[UIM] ERROR: MAC generado NO coincide con el recibido")
            print(f"MAC_ = {self.MAC_}")
            print(f"MAC = {self.MAC}")
        # Calculamos los últimos parámetros
        self.RES = f2_algorithm(self.K, self.RAND, self.OPc, self.c2, self.r2)[8:] # Bits 64 a 127
        self.CK = f3_algorithm(self.K, self.RAND, self.OPc, self.c3, self.r3)
        self.IK = f4_algorithm(self.K, self.RAND, self.OPc, self.c4, self.r4)

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
    def __init__(self, OPc, c1, r1, c2, r2, c3, r3, c4, r4):
        self.c1 = c1
        self.r1 = r1
        self.c2 = c2
        self.r2 = r2
        self.c3 = c3
        self.r3 = r3
        self.c4 = c4
        self.r4 = r4
        
        self.IMSI = None
        self.RAND = None
        self.OPc = OPc
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
            self.AMF = (33).to_bytes(2, byteorder='big') # Corresponde al IMSI
            self.MAC = f1_algorithm(self.K, self.RAND, self.OPc, self.SQN, self.AMF, self.c1, self.r1)
            
            # XRES
            self.XRES = f2_algorithm(self.K, self.RAND, self.OPc, self.c2, self.r2)[8:] # Bits 64 a 127
            # AK
            self.AK = f2_algorithm(self.K, self.RAND, self.OPc, self.c2, self.r2)[:6] # Bits 0 a 47
            # AUTHN
            self.CON_SQN = self.calcularCON_SQN(self.SQN, self.AK, self.K)
            self.AUTHN = self.calcularAUTHN(self.CON_SQN, self.AMF, self.MAC, self.K)
            # KEYS
            self.CK = f3_algorithm(self.K, self.RAND, self.OPc, self.c3, self.r3)
            self.IK = f4_algorithm(self.K, self.RAND, self.OPc, self.c4, self.r4)
        
    def generate_RAND(self):
        self.RAND = get_random_bytes(16)
        
    def generate_SQN(self):
        self.SQN = get_random_bytes(6)
        
    def get_parameters(self):
        return self.IMSI, self.RAND, self.XRES, self.AUTHN, self.CK, self.IK
    

# ------------------------ MAIN ------------------------

IMSI = "214050000000095"
K = b'1234567890123456'
OPc = b'0106202401062024'

# Obtenemos los valores de c1, r1, c2... que compartirán UIM y Operador
c1, r1, c2, r2, c3, r3, c4, r4 = algorithms_init()

uim = UIM(K=K, OPc=OPc, c1=c1, r1=r1, c2=c2, r2=r2, c3=c3, r3=r3, c4=c4, r4=r4)
movil = Movil(IMSI=IMSI)
antena = Antena()
operador = Operador(OPc=OPc, c1=c1, r1=r1, c2=c2, r2=r2, c3=c3, r3=r3, c4=c4, r4=r4)

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