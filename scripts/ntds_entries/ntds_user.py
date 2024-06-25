from logging_config import logger

from binascii import unhexlify, hexlify
from impacket import ntlm
from datetime import datetime
from impacket.dcerpc.v5 import samr
import codecs
from ntds_entries.ntds_entry import NTDSEntry
from ntds_common import read_attm_array
#from ntdsxtract.extract_engine.ntds_entries.sddl import parse_ntSecurityDescriptor



USER_ATT_TO_INTERNAL = {

    'cn':'ATTm3', # name
    
    # login
    'sAMAccountName':'ATTm590045',
    'userPrincipalName':'ATTm590480',
    'primaryGroupID':'ATTj589922',

    'logonCount':'ATTj589993', # logoncount
    'adminCount':'ATTj589974', 
    'lDAPDisplayName':'ATTm131532', # displayname
    'badPwdCount':'ATTj589836', # badpasscount
    'Description':'ATTm13', # description
    'userPrincipalName':'ATTm590480', # fulldomainname
    'comment':'ATTm589980', 
    'info':'ATTm131153', # remark
    'operatingSystem':'ATTm590187', # os
    'operatingSystemVersion':'ATTm590188', # version
    'operatingSystemServicePack':'ATTm590189', #service pack
    ############
    # To process

    # UID
    'objectGUID':'ATTk589826',

    # Delegation Contrainte
    'allowedToDelegateTo': 'ATTm591611', 


    # SID
    'objectSID':'ATTr589970',
    'sIDHistory':'ATTr590433',
    'userAccountControl':'ATTj589832',

    # status
    'sAMAccountType':'ATTj590126',

    'servicePrincipalName':'ATTm590595',

    ############
    # To decrypt
    'unicodePwd':'ATTk589914',
    'dBCSPwd':'ATTk589879',
    'ntPwdHistory':'ATTk589918',
    'lmPwdHistory':'ATTk589984',

    'pekList':'ATTk590689',
    'supplementalCredentials':'ATTk589949',
    
    #'ms-Mcs-AdmPwd':'ATTf-2055856035',

    # primaryGroupID

    ############
    # Date
    # uSNCreated - ATTq131091
    #'uSNCreated':'ATTq131091',
    #'uSNChanged':'ATTq131192',
    'whenCreated': 'ATTl131074', #  create
    # uSNChanged
    'whenChanged':'ATTl131075', # change 
    'accountExpires': 'ATTq589983', # expired
    # pwdLastSet
    'pwdLastSet':'ATTq589920', # lastpasswordset
    'lastLogon':'ATTq589876', # lastlogon

    # Use less --> configured on the DC on the entries
    'maxPwdAge':'ATTq589898', # maxagepassword
    # lastLogonTimestamp
    'lastLogonTimestamp':'ATTq591520', # lastlogontimestamp
    'lastLogon':'ATTq589876', # lastlogon
    'ntSecurityDescriptor': 'ATTp131353',
    # LAPS
    #'ms-Mcs-AdmPwdExpirationTime': 'ATTq-2143529580',

    # TO IMPLEMENT
    # NOT REPLICATED
    # lastLogon, logonCount, badPwdCount, and badPasswordTime
    'badPasswordTime':'ATTq589873',
    # Value needed to be processed
    # Maybe need to be isolated ?
    #'tmp_primaryGroupID':'ATTj589922',

    ############
    # tmp 
    'tmp_domainID':'NCDNT_col',

    # Linking object OU / Orgs / Dom
    'PDNT_col':'PDNT_col',
}

UAC_VALUE_DISABLE = 'ACCOUNTDISABLE'

UAC_Values = {
    "SCRIPT": 0x00000001,
    UAC_VALUE_DISABLE : 0x00000002,
    "HOMEDIR_REQUIRED": 0x00000008,
    "LOCKOUT" : 0x00000010,
    "PASSWD_NOTREQD": 0x00000020,
    "PASSWD_CANT_CHANGE": 0x00000040,
    "ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080,
    "TEMP_DUPLICATE_ACCOUNT": 0x00000100,
    "NORMAL_ACCOUNT": 0x00000200,
    "INTERDOMAIN_TRUST_ACCOUNT": 0x00000800,
    "WORKSTATION_TRUST_ACCOUNT": 0x00001000,
    "SERVER_TRUST_ACCOUNT": 0x00002000,
    "DONT_EXPIRE_PASSWORD": 0x00010000,
    "MNS_LOGON_ACCOUNT": 0x00020000,
    "SMARTCARD_REQUIRED": 0x00040000,
    "TRUSTED_FOR_DELEGATION": 0x00080000,
    "NOT_DELEGATED": 0x00100000,
    "DONT_REQ_PREAUTH": 0x00400000,
    "PASSWORD_EXPIRED": 0x00800000,
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
    "PARTIAL_SECRETS_ACCOUNT": 0x04000000,
}

LAPS_LEGACY_ADMPWD_REF = 'msMcsAdmPwd'
LAPS_LEGACY_ADMPWDEXP_REF = 'msMcsAdmPwdExpirationTime'
LAPS_ADMPWD_REF = 'msLAPSPassword'
LAPS_ADMPWD_ENCRYPTED_REF = 'msLAPSPasswordEncrypted'
LAPS_ADMPWDEXP_REF = 'msLAPSPasswordExpirationTime'

LAPS_REFERENCES = {
    "LAPS_LEGACY": {
        "ADMPWD_REF": LAPS_LEGACY_ADMPWD_REF, #ATTf-XXXXXXXXX
        "ADMPWDEXP_REF": LAPS_LEGACY_ADMPWDEXP_REF, #ATTq-XXXXXXXXX
    },
    "LAPS": {
        "ADMPWD_REF": LAPS_ADMPWD_REF, #ATTf-XXXXXXXXX
        "ADMPWD_ENCRYPTED_REF": LAPS_ADMPWD_ENCRYPTED_REF, #ATTf-XXXXXXXXX
        "ADMPWDEXP_REF": LAPS_ADMPWDEXP_REF, #ATTq-XXXXXXXXX
    },
}
WINDOWS_2012_AND_FUTHER_ATTR = {
    'allowedToActOnBehalfOfOtherIdentity': 'ATTp592006', #Resource-based Constrained Delegation
}


class NTDSUsers(NTDSEntry):

    config = USER_ATT_TO_INTERNAL

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }

    def __init__(self,dnt_col, crypto_user, laps_references, win2k12 = False):
        super().__init__(dnt_col)
        self.entry = dict()
        self.groups = []
        self.primarygroup = None
        self.__crypto_user = crypto_user
        self.HashHistory = []
        self.LMHash = None
        self.NTHash = None
        self.domain = None
        self.groups_name = []
        self.groups_name_legacy = []
        self.uniq = None
        self.uniq_dom = None
        self.supplementalCredentials = None
        self.kerberosKeys = []
        self.clearTextPwds = []
        self.laps_installed = False
        self.laps_legacy_adm = laps_references["laps_legacy_admpwd"]
        self.laps_legacy_adm_expirationtime = laps_references["laps_legacy_admpwdexpirationtime"]
        self.laps_adm = laps_references["laps_admpwd"]
        self.laps_adm_encrypted = laps_references["laps_admpwd_encrypted"]
        self.laps_adm_expirationtime = laps_references["laps_admpwdexpirationtime"]
        self.win2k12 = win2k12
        self.config = {}

        # Update LAPS_TO_INTERNAL based on provided references
        for key_prefix in ["LAPS_LEGACY", "LAPS"]:
            adm_encrypted_value = None
            adm_value = getattr(self, key_prefix.lower() + "_adm")
            if key_prefix == "LAPS":
                adm_encrypted_value = getattr(self, key_prefix.lower() + "_adm_encrypted")
            adm_expirationtime_value = getattr(self, key_prefix.lower() + "_adm_expirationtime")
            
            if adm_value:
                self.update_laps_to_internal(key_prefix, adm_value, adm_expirationtime_value, adm_encrypted_value)
                self.config.update(USER_ATT_TO_INTERNAL)
                self.laps_installed = True

        if not self.laps_installed:
            self.config = USER_ATT_TO_INTERNAL

        if win2k12: # attributs spécifiques aux versions 2012 et supérieure
            self.config.update(WINDOWS_2012_AND_FUTHER_ATTR)
        

    def update_laps_to_internal(self, key_prefix, value, expiration_value, encrypted_value = None):
        self.config[LAPS_REFERENCES[key_prefix]["ADMPWD_REF"]] = 'ATTf' + str(value)
        self.config[LAPS_REFERENCES[key_prefix]["ADMPWDEXP_REF"]] = 'ATTq' + str(expiration_value)
        if encrypted_value: #type à vérifier. En attente d'exemple en prod
            self.config[LAPS_REFERENCES[key_prefix]["ADMPWD_ENCRYPTED_REF"]] = 'ATTk' + str(encrypted_value)




    def get_laps_pwd(self, version="legacy", encrypted = False):
        subkey = "ADMPWD_REF"
        key_prefix = "LAPS_LEGACY" if version == "legacy" else "LAPS"
        adm_ref = getattr(self, key_prefix.lower() + "_adm")
        if encrypted:
            adm_ref = getattr(self, key_prefix.lower() + "_adm_encrypted")
            subkey = "ADMPWD_ENCRYPTED_REF"
            
        if adm_ref:
            key = LAPS_REFERENCES[key_prefix][subkey]            
            try:
                if self.entry[key] is not None:
                    return self.entry[key].decode('utf-8')
            except KeyError as e:
                logger.debug("ntds_user get_laps_pwd %s" % e)
            # if self.entry[key] is not None:
            #     return str(codecs.decode(self.entry[key], 'hex').decode('utf-8'))
        return None
    
    def get_laps_pwd_exp(self, version="legacy"):
        key_prefix = "LAPS_LEGACY" if version == "legacy" else "LAPS"
        adm_ref = getattr(self, key_prefix.lower() + "_adm")
        
        if adm_ref:
            key = LAPS_REFERENCES[key_prefix]["ADMPWDEXP_REF"]
            try:
               if self.entry[key] is not None: 
                   return self.fileTimeToDateTime(self.entry[key])
            except KeyError as e:
                logger.debug("ntds_user get_laps_pwd_exp %s" % e)
            # if self.entry[key] is not None:
            #     return self.fileTimeToDateTime(self.entry[key])
        return None

    def get_allowedToDelegateTo(self):
        try:
            return self.show_list(read_attm_array(self.entry["allowedToDelegateTo"]))
        except:
            logger.debug("get_allowedToDelegateTo: no allowedToDelegateTo for %s", self.entry["cn"])

    def get_allowedToActOnBehalfOfOtherIdentity(self):
        if self.win2k12:
            return self.entry["allowedToActOnBehalfOfOtherIdentity"]
        return None

    def get_fullname(self):
        return f'{self.domain}|{self.entry["cn"]}'

    def get_RIDid(self):
        return self.rid

    def is_user(self):
        return True
    
    def is_disable(self):
        status = self.resolve_UAC()
        return UAC_VALUE_DISABLE in status

    def __get_servicePrincipalName(self):
        if self.is_useraccount():
            try:
                return read_attm_array(self.entry["servicePrincipalName"])
            except KeyError:
                logger.debug("__get_servicePrincipalName: no servicePrincipalName attribute for %s", self.entry["cn"])

        else:
            return None

    def is_useraccount(self):
        value = UAC_Values["NORMAL_ACCOUNT"]
        if ((self.entry["userAccountControl"] & value) == value):
            return True
        else:
            return False

    def get_hashlm(self):
        return hexlify(self.LMHash).decode('utf-8')

    def get_hashnt(self):
        return hexlify(self.NTHash).decode('utf-8')

    def get_SID(self):
        return self.entry["objectSID"]

    def get_login(self):
        try:
            return self.entry["sAMAccountName"]
        except KeyError:
            logger.debug("get_login: no sAMAccountName for %s", self.entry["cn"])

    def get_comment(self):
        try:
            return self.entry["comment"]
        except KeyError:
            logger.debug("get_comment: no comment for %s", self.entry["cn"])

    def get_info(self):
        try:
            return self.entry["info"]
        except KeyError:
            logger.debug("get_info: no info for %s", self.entry["cn"])

    def get_os(self):
        try:
            return self.entry["operatingSystem"]
        except KeyError:
            logger.debug("get_os: no operatingSystem for %s", self.entry["cn"])

    def get_osversion(self):
        try:
            return self.entry["operatingSystemVersion"]
        except KeyError:
            logger.debug("get_osversion: no operatingSystemVersion for %s", self.entry["cn"])

    def get_osservicepack(self):
        try:
            return self.entry["operatingSystemServicePack"]
        except KeyError:
            logger.debug("get_osservicepack: no operatingSystemServicePack for %s", self.entry["cn"])            

    def get_sidhistory(self):
        try:
            return self.show_list(self.decode_sidhistory(self.entry["sIDHistory"]))
        except KeyError:
            logger.debug("get_sidhistory: no sIDHistory for %s", self.entry["cn"])   

    def get_lastLogonTimestamp(self):
        try:
            return self.fileTimeToDateTime(self.entry["lastLogonTimestamp"])
        except KeyError:
            logger.debug("get_lastLogonTimestamp: no lastLogonTimestamp for %s", self.entry["cn"])  

    def get_admincount(self):
        try:
            return self.entry["adminCount"]
        except KeyError:
            logger.debug("get_adminCount: no adminCount for %s", self.entry["cn"])  

    def get_description(self):
        try:
            return self.entry["Description"]
        except KeyError:
            logger.debug("get_description: no Description for %s", self.entry["cn"])  

    def get_logoncount(self):
        try:
            return self.entry["logonCount"]
        except KeyError:
            logger.debug("get_logoncount: no logonCount for %s", self.entry["cn"])  

    def get_badpasscount(self):
        try:
            return self.entry["badPwdCount"]
        except KeyError:
            logger.debug("get_badpasscount: no badPwdCount for %s", self.entry["cn"]) 

    def get_created(self):
        try:
            return self.fileTimeToDateTime(self.entry["whenCreated"]* 10000000)
        except KeyError:
            logger.debug("get_created: no whenCreated for %s", self.entry["cn"]) 

    def get_changed(self):
        try:
            return self.fileTimeToDateTime(self.entry["whenChanged"]* 10000000)
        except KeyError:
            logger.debug("get_changed: no whenChanged for %s", self.entry["cn"]) 

    def get_lastlogon(self):
        try:
            return self.fileTimeToDateTime(self.entry["lastLogon"])
        except KeyError:
            logger.debug("get_lastlogon: no lastLogon for %s", self.entry["cn"]) 

    def get_expired(self):
        try:
            return self.ad_time_to_unix(self.entry["accountExpires"])
        except KeyError:
            logger.debug("get_expired: no accountExpires for %s", self.entry["cn"])   

    def get_lastpasswordset(self):
        try:
            return self.fileTimeToDateTime(self.entry["pwdLastSet"])
        except KeyError:
            logger.debug("get_lastpasswordset: no pwdLastSet for %s", self.entry["cn"])        

    def debug(self):
        logger.debug("******* DEBUG - USERS *******")
        logger.debug("Name : %s" % self.entry["sAMAccountName"])
        logger.debug("Groups : %s" % self.groups)

    def __ad_time_to_seconds(self, ad_time):
        return -(int(ad_time) / 10000000)

    def __ad_seconds_to_unix(self, ad_seconds):
        return  ((int(ad_seconds) + 11644473600) if int(ad_seconds) != 0 else 0)


    def ad_time_to_unix(self, ad_time):
        #  A value of 0 or 0x7FFFFFFFFFFFFFFF (9223372036854775807) indicates that the account never expires
        # or 9223372032559808511 on Windows server 2022 et Windows server 2025
        # FIXME: Better handling of account-expires!
        if ad_time != None:
            if int(ad_time) == 9223372036854775807 or int(ad_time) == 9223372032559808511:
                ad_time = "0"
            ad_seconds = self.__ad_time_to_seconds(ad_time)
            t = -self.__ad_seconds_to_unix(ad_seconds)

            dt = datetime.fromtimestamp(t)
            dt_string = dt.strftime("%Y-%m-%d %H:%M")

            return dt.strftime("%Y-%m-%d %H:%M")
            # return -self.__ad_seconds_to_unix(ad_seconds)
        else:
            return None

    def dump_john_history(self, writer):
        for hash in self.HashHistory:
            line = "%s:%s:%s::history:\n" % (self.entry['sAMAccountName'], self.rid, hash)
            writer.write(line)
    
    def get_john_history(self):
        line = ""
        for hash in self.HashHistory:
            line = "%s:%s:%s::history:\n" % (self.entry['sAMAccountName'], self.rid, hash)
        return line

    def dump_john(self, writer):
        line = "%s:%s:%s:%s:::\n" % (self.entry['sAMAccountName'], self.rid, self.get_hashlm(), self.get_hashnt())
        writer.write(line)

    def get_john(self):
        line = "%s:%s:%s:%s:::\n" % (self.entry['sAMAccountName'], self.rid, self.get_hashlm(), self.get_hashnt())
        return line
    
    
    def get_entry(self):
        csv_entry = {
            "domain": self.domain,
            "login": self.get_login(),
            "uid": self.uid,
            "SID": self.sid,
            "hashlm": self.get_hashlm(),
            "hashnt": self.get_hashnt(),
            #"password": "",
            #"pwdstat": "",
            #"policy": None,
            "kerberosKeys": self.show_list(self.kerberosKeys),
            "clearTextPwds": self.show_list(self.clearTextPwds),
            "servicePrincipalName": self.show_list(self.__get_servicePrincipalName()),
            #"displayname": self.entry["lDAPDisplayName"], for attributes only?
            "primarygroup": self.primarygroup,
            "groups": self.show_list(self.groups_name),
            "groups_c": len(self.groups_name),
            "groups_legacy": self.show_list(self.groups_name_legacy),
            "logoncount": self.get_logoncount(),
            "badpasscount": self.get_badpasscount(),
            "description": self.get_description(),
            "created": self.get_created(),
            "change": self.get_changed(),
            "lastlogon": self.get_lastlogon(),
            "lastLogonTimestamp": self.get_lastLogonTimestamp(),
            "expired": self.get_expired(),
            "lastpasswordset": self.get_lastpasswordset(),
            #"maxagepassword": self.ad_time_to_unix(self.entry["maxPwdAge"]),
            #"fulldomainname": self.entry["userPrincipalName"],
            "status": self.resolve_UAC(),
            "allowedToDelegateTo": self.get_allowedToDelegateTo(),
            "allowedToActOnBehalfOfOtherIdentity": self.get_allowedToActOnBehalfOfOtherIdentity(),
            "comment": self.get_comment(),
            "remark": self.get_info(),
            "os": self.get_os(),
            "version":self.get_osversion(),
            "operatingSystemServicePack": self.get_osservicepack(),
            LAPS_LEGACY_ADMPWD_REF: self.get_laps_pwd(version = "legacy"),
            LAPS_LEGACY_ADMPWDEXP_REF:self.get_laps_pwd_exp(version = "legacy"),
            #LAPS_ADMPWD_REF: self.get_laps_pwd(version = "new"),
            LAPS_ADMPWD_ENCRYPTED_REF: self.get_laps_pwd(version = "new", encrypted=True),
            LAPS_ADMPWDEXP_REF:self.get_laps_pwd_exp(version = "new"),
            "sIDHistory": self.get_sidhistory(),
            "uniq":self.uniq,  
            "uniq_dom":self.uniq_dom,
            "adminCount":self.get_admincount(), 
            "ntSecurityDescriptor": self.get_security_descriptor(self.entry["ntSecurityDescriptor"]),
            #"isadmin":None,
            #"uniq":None,
            #"uniq_dom":None
        }
        return csv_entry


    def resolve_UAC(self):

        status = []
        report_status = ""
        first = True
        for key, value in UAC_Values.items():
            if ((self.entry["userAccountControl"] & value) == value):
                if first == True:
                    report_status = "%s" % key
                    first = False
                else:
                    report_status = "%s , %s" %(report_status, key)
                status.append(key)

        return report_status

    # Extracted from impacket - credsdump
    def __dump_suppCreds(self):

        plainText = self.supplementalCredentials
        try:
            userProperties = samr.USER_PROPERTIES(plainText)
        except:
            # On some old w2k3 there might be user properties that don't
            # match [MS-SAMR] structure, discarding them
            return
        propertiesData = userProperties['UserProperties']
        for propertyCount in range(userProperties['PropertyCount']):
            try:
                userProperty = samr.USER_PROPERTY(propertiesData)
            except:
                logger.debug("Erreur de parsing dans les propriétés du compte " + self.entry['sAMAccountName'])
                break
            propertiesData = propertiesData[len(userProperty):]
            # For now, we will only process Newer Kerberos Keys and CLEARTEXT

            if NTDSUsers.isutf_16le(userProperty['PropertyName']):  # TO prevent the UnicodeDecodeError error
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                        if  keyDataNew['KeyType'] in self.KERBEROS_TYPE:
                            answer =  "%s:%s" % (self.KERBEROS_TYPE[keyDataNew['KeyType']],hexlify(keyValue).decode('utf-8'))
                        else:
                            answer =  "%s:%s" % (hex(keyDataNew['KeyType']),hexlify(keyValue).decode('utf-8'))
                        # We're just storing the keys, not printing them, to make the output more readable
                        # This is kind of ugly... but it's what I came up with tonight to get an ordered
                        # set :P. Better ideas welcomed ;)
                        self.kerberosKeys.append(answer)

                elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                    try:
                        answer = "%s" % (unhexlify(userProperty['PropertyValue']).decode('utf-16le'))
                    except UnicodeDecodeError:
                        # This could be because we're decoding a machine password. Printing it hex
                        answer = "0x%s" % (userProperty['PropertyValue'].decode('utf-8'))
                    self.clearTextPwds.append(answer)
            else:
                logger.debug("Error decoding PropertyName for " + self.entry['sAMAccountName'] + " account")

    def decryptHash(self, prefixTable=None):

        rid = self.rid
        try:
            self.LMHash = self.__crypto_user.decrypt(self.entry['dBCSPwd'], rid)
        except KeyError:
            logger.debug("decryptHash: no dBCSPwd attribute for user %s", self.entry['cn'])
        try:
            self.NTHash = self.__crypto_user.decrypt(self.entry['unicodePwd'], rid)
        except KeyError:
            logger.debug("decryptHash: no unicodePwd attribute for user %s", self.entry['cn'])
        try:
            if self.entry['supplementalCredentials'] is not None:
                if len(self.entry['supplementalCredentials']) > 24:
                    self.supplementalCredentials = self.__crypto_user.decrypt_blob(self.entry['supplementalCredentials'])
                    self.__dump_suppCreds()
        except KeyError:
            logger.debug("decryptHash: no supplementalCredentials attribute for user %s", self.entry['cn'])                    

        if self.LMHash == None:
            self.LMHash = ntlm.LMOWFv1('', '')

        if self.NTHash == None:
            self.NTHash = ntlm.NTOWFv1('', '')

        try:
            if self.entry['lmPwdHistory'] is not None:
                LMHistory = self.__crypto_user.decrypt_history(self.entry['lmPwdHistory'], rid)

            if self.entry['ntPwdHistory'] is not None:
                NTHistory = self.__crypto_user.decrypt_history(self.entry['ntPwdHistory'], rid)

            for i, (LMHash, NTHash) in enumerate(map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):

                if self.entry['lmPwdHistory'] is None:
                    LMHash = ntlm.LMOWFv1('', '')
                else:
                    LMHash = hexlify(LMHash).decode('utf-8')

                if NTHash == None:
                    NTHash = ntlm.NTOWFv1('', '')
                else:
                    NTHash = hexlify(NTHash).decode('utf-8')
                
                fullhash = "%s:%s" % (LMHash, NTHash)
                self.HashHistory.append(fullhash)
        except KeyError:
            logger.debug("decryptHash: no lmPwdHistory or ntPwdHistory attribute for user %s", self.entry['cn'])        

    def print_userstatus(self):
        if self.entry['userAccountControl'] is not None:
            if '{0:08b}'.format(self.entry['userAccountControl'])[-2:-1] == '1':
                userAccountStatus = 'Disabled'
            elif '{0:08b}'.format(self.entry['userAccountControl'])[-2:-1] == '0':
                userAccountStatus = 'Enabled'
        else:
            userAccountStatus = 'N/A'
        return userAccountStatus

    def get_passwordlastset(self):
        if self.entry['pwdLastSet'] is not None:
            pwdLastSet = self.fileTimeToDateTime(self.entry['pwdLastSet'])
        else:
            pwdLastSet = 'N/A'
        return pwdLastSet

    def get_fullname(self):
        return f'{self.domain}|{self.entry["sAMAccountName"]}'

    def get_full_username(self):
        if self.entry['userPrincipalName'] is not None:
            domain = self.entry['userPrincipalName'].split('@')[-1]
            username = '%s\\%s' % (domain, self.entry['sAMAccountName'])
        else:
            username = '%s' % self.entry['sAMAccountName']
        return username


