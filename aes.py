import pyaes


class AESEncryption:

    def encrypt(self, key: bytes, datas: str):
        """Chiffre les donnees avec la cle"""
        obj = pyaes.AESModeOfOperationCTR(key)
        ciphertext = obj.encrypt(datas)
        return ciphertext

    def decrypt(self, key: bytes, datas: bytes):
        """Dechiffre les donnees avec la cle"""
        obj = pyaes.AESModeOfOperationCTR(key)
        plaintext = obj.decrypt(datas)
        return plaintext