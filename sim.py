from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib

class UIM:
    def __init__(self, K):
        self.RAND = None
        self.AUTHN_MAC = None
        self.K = K
    
    # Función MAC
    def f1_algorithm(self, K, SQN, RAND, AMF):
        # Concatenar los parámetros de entrada
        data = SQN + RAND + AMF
        # Crear un objeto HMAC utilizando la clave secreta y el algoritmo SHA-256
        h = hmac.new(K, data, hashlib.sha256)
        # Calcular el MAC y devolverlo
        return h.digest()[:8] # MAC será de 64 bits (8 bytes)
    
    # Funciones de derivación de clave
    def f2_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        XRES = cipher.encrypt(RAND)[:4]  # SRES será de 32 bits (4 bytes)
        return XRES

    def f3_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        CK = cipher.encrypt(RAND)[:16]  # CK será de 128 bits (16 bytes)
        return CK

    def f4_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        IK = cipher.encrypt(RAND)[:16]  # IK será de 128 bits (16 bytes)
        return IK

    def f5_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        AK = cipher.encrypt(RAND)[:6]  # AK será de 48 bits (6 bytes)
        return AK
        
    # Funciones de intercambio de datos        
    def set_RAND(self, RAND):
        self.RAND = RAND
        
    def set_MAC(self, AUTHN_MAC):
        self.AUTHN_MAC = AUTHN_MAC

class Movil:
    def __init__(self, IMSI):
        self.IMSI = IMSI
        self.RAND = None
        self.AUTHN_MAC = None
        
    def set_RAND(self, RAND):
        self.RAND = RAND
        
    def set_MAC(self, AUTHN_MAC):
        self.AUTHN_MAC = AUTHN_MAC

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
        
    # Función MAC
    def f1_algorithm(self, K, SQN, RAND, AMF):
        # Concatenar los parámetros de entrada
        data = SQN + RAND + AMF
        # Crear un objeto HMAC utilizando la clave secreta y el algoritmo SHA-256
        h = hmac.new(K, data, hashlib.sha256)
        # Calcular el MAC y devolverlo
        return h.digest()[:8] # MAC será de 64 bits (8 bytes)
    
    # Funciones de derivación de clave
    def f2_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        XRES = cipher.encrypt(RAND)[:4]  # SRES será de 32 bits (4 bytes)
        return XRES

    def f3_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        CK = cipher.encrypt(RAND)[:16]  # CK será de 128 bits (16 bytes)
        return CK

    def f4_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        IK = cipher.encrypt(RAND)[:16]  # IK será de 128 bits (16 bytes)
        return IK

    def f5_algorithm(self, K, RAND):
        cipher = AES.new(K, AES.MODE_ECB)
        AK = cipher.encrypt(RAND)[:6]  # AK será de 48 bits (6 bytes)
        return AK
        
    def calcularCON_SQN(self, SQN,AK,K):
        datos = SQN + AK
        cipher = AES.new(K, AES.MODE_ECB)
        datos_padding = datos + b'0000' # Hay que meter relleno para que datos (12 bytes) sea de 16 bytes
        CON_SQN = cipher.encrypt(datos_padding)[:16] # CON_SQN será de 128 bits (16 bytes)
        return CON_SQN
        
    def calcularAUTHN(self, CON_SQN,AMF,MAC, K):
        datos = CON_SQN + AMF + MAC
        cipher = AES.new(K, AES.MODE_ECB)
        datos_trunc = datos[:16] # Hay que truncar para que los datos (176 bits) ocupen 128 bits
        AUTN = cipher.encrypt(datos_trunc)[:16] # AUTN será de 128 bits (16 bytes)
        return AUTN
        
    def set_IMSI(self, IMSI):
        self.IMSI = IMSI
        if IMSI == "214050000000095":
            self.K = b'1234567890123456'
            self.generate_RAND()
            self.generate_SQN()
            self.AK = self.f5_algorithm(self.K, self.RAND)
            self.AMF = b'3377331033083315' # Corresponde al IMSI
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
#movil.set_MAC(antena.AUTHN_MAC)

# 5. Se envían RAND y AUTHN->MAC del móvil al UIM
uim.set_RAND(movil.RAND)
#uim-set_MAC(movil.AUTHN_MAC)

# 6. Se generan todos los parámetros en UIM, y se envían RES, CK e IK al móvil

# 7. Se envía RES del móvil a la antena

# 8. La antena comprueba si RES == XRES y responde con OK (al móvil)

# 9. Se envía el mensaje "Hola" codificado del móvil a la antena

# 10. Se envía HMAC del móvil a la antena
