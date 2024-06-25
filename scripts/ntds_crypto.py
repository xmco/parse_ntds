import hashlib
from struct import unpack, pack
from binascii import unhexlify, hexlify
import struct
from six import b, PY2

from impacket.structure import Structure
from impacket.crypto import transformKey


from logging_config import logger

try:
    from Cryptodome.Cipher import DES, ARC4, AES
    from Cryptodome.Hash import HMAC, MD4
except ImportError:
    logger.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    logger.critical("See https://pypi.org/project/pycryptodomex/")

class CryptoCommon(object):

    # Common crypto stuff used over different classes
    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
        key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
        if PY2:
            return transformKey(b''.join(key1)),transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)),transformKey(bytes(key2))

    @staticmethod
    def decryptAES(key, value, iv=b'\x00'*16):
        plainText = b''
        if iv != b'\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == b'\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += b'\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText

class CryptoPEK(CryptoCommon):

    class PEKLIST_ENC(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedPek',':'),
        )

    class PEKLIST_PLAIN(Structure):
        structure = (
            ('Header','32s=b""'),
            ('DecryptedPek',':'),
        )

    class PEK_KEY(Structure):
        structure = (
            ('Header','1s=b""'),
            ('Padding','3s=b""'),
            ('Key','16s=b""'),
        )

    @classmethod
    def decrypt_PEK(cls, peklist, bootkey):

        PEK = list()
        if peklist is not None:
            encryptedPekList = cls.PEKLIST_ENC(peklist)
            if encryptedPekList['Header'][:4] == b'\x02\x00\x00\x00':
                # Up to Windows 2012 R2 looks like header starts this way
                md5 = hashlib.new('md5')
                md5.update(bootkey)
                for i in range(1000):
                    md5.update(encryptedPekList['KeyMaterial'])
                tmpKey = md5.digest()
                rc4 = ARC4.new(tmpKey)
                decryptedPekList = cls.PEKLIST_PLAIN(rc4.encrypt(encryptedPekList['EncryptedPek']))
                PEKLen = len(cls.PEK_KEY())
                for i in range(len( decryptedPekList['DecryptedPek'] ) // PEKLen ):
                    cursor = i * PEKLen
                    pek = cls.PEK_KEY(decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen])
                    logger.info("PEK # %d found and decrypted: %s", i, hexlify(pek['Key']).decode('utf-8'))
                    PEK.append(pek['Key'])

            elif encryptedPekList['Header'][:4] == b'\x03\x00\x00\x00':
                # Windows 2016 TP4 header starts this way
                # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
                # using AES:
                # Key: the bootKey
                # CipherText: PEKLIST_ENC['EncryptedPek']
                # IV: PEKLIST_ENC['KeyMaterial']
                decryptedPekList = cls.PEKLIST_PLAIN(
                    cls.decryptAES(bootkey, encryptedPekList['EncryptedPek'],
                                                   encryptedPekList['KeyMaterial']))

                # PEK list entries take the form:
                #   index (4 byte LE int), PEK (16 byte key)
                # the entries are in ascending order, and the list is terminated
                # by an entry with a non-sequential index (08080808 observed)
                pos, cur_index = 0, 0
                while True:
                    pek_entry = decryptedPekList['DecryptedPek'][pos:pos+20]
                    if len(pek_entry) < 20: break # if list truncated, should not happen
                    index, pek = unpack('<L16s', pek_entry)
                    if index != cur_index: break # break on non-sequential index
                    PEK.append(pek)
                    logger.info("PEK # %d found and decrypted: %s", index, hexlify(pek).decode('utf-8'))
                    cur_index += 1
                    pos += 20
        return PEK
    
class CryptoHash(CryptoCommon):

    def __init__(self, PEK):
        self.PEK = PEK

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash','16s=b""'),
        )

    class CRYPTED_HASHW16(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('Unknown','<L=0'),
            ('EncryptedHash','32s=b""'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash',':'),
        )

    class CRYPTED_BLOB(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash',':'),
        )

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        # PEK index can be found on header of each ciphered blob (pos 8-10)
        pekIndex = hexlify(cryptedHash['Header'])
        md5.update(self.PEK[int(pekIndex[8:10])])
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1,Key2 = self.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    def decrypt_blob(self, entry):
        if entry is not None:
            encryptedBlob = self.CRYPTED_BLOB(entry)
            if encryptedBlob['Header'][:4] == b'\x13\x00\x00\x00':
                pekIndex = hexlify(encryptedBlob['Header'])
                tmp_blob = self.decryptAES(self.PEK[int(pekIndex[8:10])],
                                                            encryptedBlob['EncryptedHash'][4:],
                                                            encryptedBlob['KeyMaterial'])
            else:
                tmp_blob = self.__removeRC4Layer(encryptedBlob)
        else:
            tmp_blob = None
        return tmp_blob

    def __decrypt_hash(self, encryptedNTHash, entry, rid):
        
        if encryptedNTHash['Header'][:4] == b'\x13\x00\x00\x00':
            # Win2016 TP4 decryption is different
            encryptedNTHash = self.CRYPTED_HASHW16(entry)
            pekIndex = hexlify(encryptedNTHash['Header'])
            tmp_hash = self.decryptAES(self.PEK[int(pekIndex[8:10])],
                                                        encryptedNTHash['EncryptedHash'],
                                                        encryptedNTHash['KeyMaterial'])
        else:
            tmp_hash = self.__removeRC4Layer(encryptedNTHash) 

        return tmp_hash       

    def decrypt_history(self, entry, rid):
        hashes = []
        if entry is not None:
            try:
                encryptedNTHash = self.CRYPTED_HISTORY(entry)
                tmpHistory =  self.__decrypt_hash(encryptedNTHash, entry, rid)
                for i in range(0, len(tmpHistory) // 16):
                    LMHash = self.__removeDESLayer(tmpHistory[i * 16:(i + 1) * 16], rid)
                    hashes.append(LMHash)
            except struct.error as err: 
                print("decrypt_history "+err)
        return hashes


    def decrypt(self, entry, rid):
        if entry is not None:
            encryptedNTHash = self.CRYPTED_HASH(entry)
            if encryptedNTHash['Header'][:4] == b'\x13\x00\x00\x00':
                # Win2016 TP4 decryption is different
                encryptedNTHash = self.CRYPTED_HASHW16(entry)
                pekIndex = hexlify(encryptedNTHash['Header'])
                tmp_hash = self.decryptAES(self.PEK[int(pekIndex[8:10])],
                                                            encryptedNTHash['EncryptedHash'][:16],
                                                            encryptedNTHash['KeyMaterial'])
            else:
                tmp_hash = self.__removeRC4Layer(encryptedNTHash)
            hash = self.__removeDESLayer(tmp_hash, rid)
        else:
            hash = None
        return hash

