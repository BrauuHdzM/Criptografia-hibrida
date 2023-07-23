from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import font
from cryptography.fernet import Fernet
import os
from hash import *
from CifrarFirmar import *
from DescifrarVerificar import *

archivoCifrarFirmar = ['']
archivoLlavePrivadaA = ['']
archivoLlavePublicaReceptor = ['']
archivoCifrado = ['']
archivoLlavePrivadaB = ['']
archivoLlavePublicaEmisor = ['']

def generarLlaves():
    nombreLlavePrivada = "Private_Key.pem"
    nombreLlavePublica = "Public_Key.pem"
    generar_Llaves(nombreLlavePrivada, nombreLlavePublica)
    messagebox.showinfo("Llaves generadas", "Las llaves se han generado correctamente")

def generar_Llaves(nombreLlavePrivada, nombreLlavePublica):
    llave = RSA.generate(2048)
    llavePrivada = llave.export_key()
    f = open(nombreLlavePrivada, "wb")
    f.write(llavePrivada)
    f.close
    llavePublica = llave.publickey().export_key()
    f = open(nombreLlavePublica, "wb")
    f.write(llavePublica)
    f.close()

def getArchivo(path, extension):
    path[0] = filedialog.askopenfilename(title="Open key", filetypes=[("Files " + extension, "*." + extension),
                                                                    ("All files", "*.*")])


def Descifrar():
    messagebox.showinfo("", "Seleccione la llave para descifrar")
    archivoLlave = filedialog.askopenfilename()
    archivoLlave = open(archivoLlave, "rb")
    llave = archivoLlave.read()
    key = Fernet(llave)

    messagebox.showinfo("", "Seleccione los archivos a descifrar")
    archivosDescifrar = filedialog.askopenfilenames()

    for x in archivosDescifrar:
        with open(x, "rb") as archivo:
            texto = archivo.read()

        global descifrado
        descifrado = key.decrypt(texto)
        file_name, file_extension = os.path.splitext(x)
        with open(file_name + '_d' + file_extension, "wb") as archivoDescifrado:
            archivoDescifrado.write(descifrado)

    messagebox.showinfo("", "Descifrado exitoso")

raiz = Tk()

frame = Frame(raiz, width=600, height=400)
frame.config(bg="white")
frame.pack()

label = Label(frame, text="Práctica Final: Criptografía Híbrida", fg="black", font=("Arial", 14))
label.config(bg="white")
label.place(x=300, y=20, anchor="center")

label = Label(frame, text="Generación de llaves RSA", fg="black", font=("Arial", 14))
label.config(bg="white")
label.place(x=300, y=50, anchor="center")

botonLlave = Button(raiz, text="Generar llaves",
                    command=generarLlaves, font=('Arial', 10), background="white")
botonLlave.place(x=300, y=90, anchor="center")
botonLlave.config(bg="white")

label = Label(frame, text="Cifrar y Firmar", fg="black", font=('Arial', 14))
label.config(bg="white")
label.place(x=150, y=120, anchor="center")

botonArchivoCifrarFirmar = Button(raiz, text="Archivo a cifrar y firmar",
                                 command=lambda: [getArchivo(archivoCifrarFirmar, "txt"),
                                                  entryArchivoCifrarFirmar.insert(0, archivoCifrarFirmar[0])],
                                 font=('Arial', 10), background="white")
botonArchivoCifrarFirmar.place(x=150, y=150, anchor="center")
botonArchivoCifrarFirmar.config(bg="white")
entryArchivoCifrarFirmar = Entry(raiz, font=('Arial', 10))
entryArchivoCifrarFirmar.place(x=150, y=180, anchor="center", width=300)

botonArchivoLlavePrivadaA = Button(raiz, text="Tu llave privada",
                                  command=lambda: [getArchivo(archivoLlavePrivadaA, "pem"),
                                                   entryArchivoLlavePrivadaA.insert(0, archivoLlavePrivadaA[0])],
                                  font=('Arial', 10), foreground="black")
botonArchivoLlavePrivadaA.place(x=150, y=210, anchor="center")
botonArchivoLlavePrivadaA.config(bg="white")
entryArchivoLlavePrivadaA = Entry(raiz, font=('Arial', 10))
entryArchivoLlavePrivadaA.place(x=150, y=240, anchor="center", width=300)

botonArchivoLlavePublicaReceptor = Button(raiz, text="Llave pública de quien le envias",
                                          command=lambda: [getArchivo(archivoLlavePublicaReceptor, "pem"),
                                                           entryArchivoLlavePublicaReceptor.insert(0,
                                                                                                archivoLlavePublicaReceptor[
                                                                                                    0])],
                                          font=('Arial', 10), fg="black")
botonArchivoLlavePublicaReceptor.place(x=150, y=270, anchor="center")
botonArchivoLlavePublicaReceptor.config(bg="white")
entryArchivoLlavePublicaReceptor = Entry(raiz, font=('Arial', 10))
entryArchivoLlavePublicaReceptor.place(x=150, y=300, anchor="center", width=300)

botonCifrarFirmar = Button(raiz, text="¡Cifra y Firma!",
                           command=lambda: cifrarFirmar(archivoCifrarFirmar[0], archivoLlavePrivadaA[0],
                                                       archivoLlavePublicaReceptor[0]),
                           font=('Arial', 10), foreground="black")
botonCifrarFirmar.place(x=150, y=330, anchor="center")
botonCifrarFirmar.config(bg="white")

label = Label(frame, text="Descifrar y Verificar", fg="black", font=('Arial', 14))
label.config(bg="white")
label.place(x=450, y=120, anchor="center")

botonArchivoCifrado = Button(raiz, text="Archivo a descifrar y verificar",
                             command=lambda: [getArchivo(archivoCifrado, "txt"),
                                              entryArchivoCifrado.insert(0, archivoCifrado[0])],
                             font=('Arial', 10), background="white")
botonArchivoCifrado.place(x=450, y=150, anchor="center")
botonArchivoCifrado.config(bg="white")
entryArchivoCifrado = Entry(raiz, font=('Arial', 10))
entryArchivoCifrado.place(x=450, y=180, anchor="center", width=300)

botonArchivoLlavePrivadaB = Button(raiz, text="Tu llave privada",
                                  command=lambda: [getArchivo(archivoLlavePrivadaB, "pem"),
                                                   entryArchivoLlavePrivadaB.insert(0, archivoLlavePrivadaB[0])],
                                  font=('Arial', 10), background="white")
botonArchivoLlavePrivadaB.place(x=450, y=210, anchor="center")
botonArchivoLlavePrivadaB.config(bg="white")
entryArchivoLlavePrivadaB = Entry(raiz, font=('Arial', 10))
entryArchivoLlavePrivadaB.place(x=450, y=240, anchor="center", width=300)

botonArchivoLlavePublicaEmisor = Button(raiz, text="Llave publica de quien te envía",
                                        command=lambda: [getArchivo(archivoLlavePublicaEmisor, "pem"),
                                                         entryArchivoLlavePublicaEmisor.insert(0,
                                                                                              archivoLlavePublicaEmisor[
                                                                                                  0])],
                                        font=('Arial', 10), background="white")
botonArchivoLlavePublicaEmisor.place(x=450, y=270, anchor="center")
botonArchivoLlavePublicaEmisor.config(bg="white")
entryArchivoLlavePublicaEmisor = Entry(raiz, font=('Arial', 10))
entryArchivoLlavePublicaEmisor.place(x=450, y=300, anchor="center", width=300)

botonVerificar = Button(raiz, text="¡Verifica y firma!", font=('Arial', 10),
                        command=lambda: descifrarVerificar(archivoCifrado[0], archivoLlavePrivadaB[0],
                                                          archivoLlavePublicaEmisor[0]), foreground="black")
botonVerificar.place(x=450, y=330, anchor="center")
botonVerificar.config(bg="white")

raiz.title("Práctica Criptografía Híbrida")
raiz.config(bg="white")
raiz.mainloop()

