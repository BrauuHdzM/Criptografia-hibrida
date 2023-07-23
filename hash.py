from Crypto.PublicKey import RSA
from tkinter import messagebox as MesssageBox
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def signature(archivoFirmar, archivoLlavePrivada):
    f = open(archivoFirmar, "rb")
    digesto = SHA256.new()
    textoArchivo = f.read()
    digesto.update(textoArchivo)
    f.close()

    file_name, file_extension = os.path.splitext(archivoFirmar) 
    archivoFirmado = open(file_name+"_f"+file_extension, "wb")

    archivoFirmado.write(textoArchivo)
    try:
        llave = RSA.importKey(open(archivoLlavePrivada, "rb").read())
        firma = pkcs1_15.new(llave).sign(digesto)
    except (ValueError, TypeError):
        MesssageBox.showerror("Error", "Seleccione una llave correcta")
    
    archivoFirmado
    archivoFirmado.write(b"\n--------------\n")
    archivoFirmado.write(firma)
    archivoFirmado.close()