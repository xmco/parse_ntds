from logging_config import logger

from binascii import unhexlify, hexlify
from struct import unpack
from six import b
from codecs import decode

from impacket.structure import Structure
from impacket import winregistry
from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket.dcerpc.v5.dtypes import ULONG, LONG

class OLD_LARGE_INTEGER(NDRSTRUCT):
    structure = (
        ('LowPart',ULONG),
        ('HighPart',LONG),
    )


class LINK_METADATA(NDRSTRUCT):
    structure = (
            ('timestamp',OLD_LARGE_INTEGER),
            ('count',LONG),
        )

class LDAP_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class LDAP_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',LDAP_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
        iter = self['SubAuthorityCount']
        '''
        The RID value is in big endian and not in little endian
        Exemple de valeur : \x15\x00\x00\x002\xef\xe3\xd3\xc6\x94\x8b\x90\x94\xc9M\x1f\x00\x00\x02\x05
        '''
        rid_detected = False
        if int(self['SubAuthorityCount']) == 5 or int(self['SubAuthorityCount']) == 2 or int(self['SubAuthorityCount']) == 1:
            rid_detected = True
            iter = self['SubAuthorityCount'] - 1
            i = iter
            rid = '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])

        for i in range(iter):
            fmt = '>L' if not rid_detected and i == 3 else '<L' # the last part of the domain SID is big endian
            ans += '-%d' % ( unpack(fmt,self['SubAuthority'][i*4:i*4+4])[0])
        if rid_detected:
            ans += rid
        return ans


class SAMR_RPC_SID(Structure):

    class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
        structure = (
            ('Value','6s'),
        )
    
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )
    

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
        for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
        return ans
    

def read_attm_array(entry):
    if isinstance(entry, bytes):
        pointer_s = []
        spn = []
        nb_string = 0

        nb_string = int(unpack("<H",unhexlify(entry[0:4]))[0])*2
        try:
            for i in range(0,nb_string-4,4):
                if len(entry[4+i:8+i]) < 4:
                    logger.debug("read_attm_array bad entry")
                    raise Exception("Bad entry")
                offset_s = int(unpack("<H",unhexlify(entry[4+i:8+i]))[0]*2)
                pointer_s.append(offset_s)

            off_a = nb_string
            for point in pointer_s:
                off_b = int(point)
                spn_name = decode(unhexlify(entry[off_a:off_b]),'utf16')
                off_a = off_b
                spn.append(spn_name)
            spn_name = decode(unhexlify(entry[off_a:]),'utf16')
            spn.append(spn_name)
        except Exception as e:
            logger.debug("Bad entry has been skipped")
            try:
                spn = decode(unhexlify(entry), 'utf16') #on retourne l'entrée entiere décodée
            except UnicodeDecodeError as e:
                spn = ["SPN could not be decoded"]
        return spn
    return entry


class LocalOperations:
    def __init__(self, systemHive):
        self.__systemHive = systemHive

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = b''
        tmpKey = b''
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD', 'Skew1', 'GBG', 'Data']:
            logger.debug('Retrieving class info for %s' % key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + b(digit)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        tmpKey = unhexlify(tmpKey)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        logger.info('Target system bootKey: 0x%s' % hexlify(bootKey).decode('utf-8'))

        return bootKey
