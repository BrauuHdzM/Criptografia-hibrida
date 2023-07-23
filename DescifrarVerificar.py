from hash import *
from cryptography.fernet import Fernet
import os
from tkinter import messagebox
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def descifrarVerificar(archivoDescifrar, archivoLlavePrivada, archivoLlavePublica):
  
    #Archivo a descifrar, llave pública y privada
    descifrar = open(archivoDescifrar, "rb")
    llavePrivada = open(archivoLlavePrivada, "rb")
    llavePublica = open(archivoLlavePublica, "rb") 

    #Encontramos las partes del mensaje (Mensaje, llave AES cifrada, firma digital)
    bandera = 0
    mensajeCifrado = b''
    llaveCifrada = b''
    firma = b''
    for linea in descifrar.readlines():
        if linea == b"--------------\n":
            bandera = bandera + 1
            continue
        if bandera == 0:
            mensajeCifrado = mensajeCifrado + linea
        if bandera == 1:
            llaveCifrada = llaveCifrada + linea
        if bandera == 2:
            firma = firma + linea
    descifrar.close()

    llaveCifrada = llaveCifrada[:-1]

    #Descifrado de la llave AES
    llavePriv = llavePrivada.read()
    llavePrivada.close()
    llaveAES = descifrarRSA(llaveCifrada, llavePriv)

    #Descifrado del mensaje
    mensaje = descifrarAES(mensajeCifrado, llaveAES)

    #Verificación de la firma digital
    llaveP = llavePublica.read()
    if(verificarFirma(firma, llaveP, SHA256.new(mensaje))):
        messagebox.showinfo("=)", "El archivo ha sido autenticado correctamente")
        file_name, file_extension = os.path.splitext(archivoDescifrar)
        outputFile = open(file_name+"_d"+file_extension, "wb")
        outputFile.write(mensaje)
        outputFile.close()
    else:
        messagebox.showwarning("=(", "El archivo no ha sido autenticado")

def is_public_key(key):
    try:
        # Intentamos cargar la llave RSA
        serialization.load_pem_public_key(key.encode(), backend=default_backend())
        return True
    except (ValueError, TypeError, NotImplementedError):
        return False

def is_private_key(key):
    try:
        # Intentamos cargar la llave RSA
        serialization.load_pem_private_key(key.encode(), password=None, backend=default_backend())
        return True
    except (ValueError, TypeError, NotImplementedError):
        return False

def descifrarRSA(llaveAES, llave):

    if not is_private_key(llave.decode()):
        messagebox.showerror("Error", "Seleccione una llave RSA privada")
        return None
    
    #print("Llave AES:", llaveAES)
    #print("Llave:", llave)

    try:
        llave = RSA.importKey(llave)
        output = PKCS1_OAEP.new(llave).decrypt(llaveAES) 
        return output
    except (TypeError, ValueError):
        messagebox.showerror("Error", "La llave privada introducida es incorrecta o hay problemas con tu archivo. Asegurate de que seas tú la persona que debe recibir este archivo o que no ha sido modificado")
        


def descifrarAES(mensaje, llave):
    llave = Fernet(llave)
    mensaje = llave.decrypt(mensaje)
    return mensaje

def verificarFirma(firma, llave, digesto):

    if not is_public_key(llave.decode()):
        MesssageBox.showerror("Error", "Seleccione una llave RSA pública")
        return None
    
    llave = RSA.importKey(llave)
    try:
        pkcs1_15.new(llave).verify(digesto, firma)
        return True
    except (ValueError, TypeError):
        return False



