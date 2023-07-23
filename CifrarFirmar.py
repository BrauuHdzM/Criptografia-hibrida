from hash import *
from cryptography.fernet import Fernet
import os
from tkinter import messagebox
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def cifrarFirmar(archivoCifrarFirmar, archivoLlavePrivadaA, archivoLlavePublicaReceptor):

    #Archivo a cifrar, llave pública y privada
    cifrarFirmar = open(archivoCifrarFirmar, "rb")
    llavePrivada = open(archivoLlavePrivadaA, "rb")
    llavePublica = open(archivoLlavePublicaReceptor, "rb")

    #Cifrado del mensaje 
    llaveAES = Fernet.generate_key() #Fernet= AES 128, CBC
    mensaje = cifrarFirmar.read()
    cifrarFirmar.close() 
    mensajeCifrado = cifrarAES(mensaje, llaveAES)
    
    #Cifrado llave AES, con llave pública del receptor
    llaveP = llavePublica.read()
    llavePublica.close()
    llaveAESCifrada = cifrarRSA(llaveAES, llaveP)

    #Firma digital
    llavePriv = llavePrivada.read()
    llavePrivada.close()
    digesto = SHA256.new(); digesto.update(mensaje)
    firma = firmarRSA(digesto, llavePriv)

    #Archivo con mensaje cifrado, llave AES cifrada y firma digital
    file_name, file_extension = os.path.splitext(archivoCifrarFirmar) 
    outputFile = open(file_name+'_c'+file_extension, "wb")
    outputFile.write(mensajeCifrado)
    outputFile.write(b"\n--------------\n")
    outputFile.write(llaveAESCifrada)
    outputFile.write(b"\n--------------\n")
    outputFile.write(firma)
    outputFile.close()
    messagebox.showinfo("Cifrado correcto", "El documento se ha cifrado y firmado correctamente")

def cifrarAES(mensaje, llave):
        llave = Fernet(llave)
        cifrado = llave.encrypt(mensaje)
        return cifrado

def is_public_key(key):
    try:
        # Intentamos cargar la llave RSA
        serialization.load_pem_public_key(key.encode(), backend=default_backend())
        return True
    except (ValueError, TypeError, NotImplementedError):
        return False

def cifrarRSA(llaveAES, llave):
    if not is_public_key(llave.decode()):
        MesssageBox.showerror("Error", "Seleccione una llave RSA pública, no pudimos cifrar la llave AES")
        return None
    
    try:
        key = RSA.importKey(llave)
        output = PKCS1_OAEP.new(key).encrypt(llaveAES)
    except (ValueError, TypeError):
        MesssageBox.showerror("Error", "Seleccione una llave RSA adecuada, no pudimos cifrar la llave AES")
        return None
    
    return output

def is_private_key(key):
    try:
        # Intentamos cargar la llave RSA
        serialization.load_pem_private_key(key.encode(), password=None, backend=default_backend())
        return True
    except (ValueError, TypeError, NotImplementedError):
        return False

def firmarRSA(digesto, llave):
    if not is_private_key(llave.decode()):
        messagebox.showerror("Error", "Seleccione una llave RSA privada")
        return None
    
    try:
        key = RSA.importKey(llave)
        firma = pkcs1_15.new(key).sign(digesto)
        return firma
    except (TypeError, ValueError):
        messagebox.showerror("Error", "La llave privada introducida es incorrecta")
        return None
