# -*- coding: utf-8 -*-
from logging_config import logger
from binascii import unhexlify, hexlify
from collections import Counter
import csv
import struct
from ntds_esedb import ESENTDB_Abstract, ESENTDB_AbstractDissect
from ntds_crypto import CryptoHash, CryptoPEK
from ntds_common import SAMR_RPC_SID, LINK_METADATA, LDAP_SID
from ntds_entries import NTDSOU, NTDSContainer, NTDSUsers, NTDSGroups, NTDSDomain, NTDSTrust
from ntds_entries.ntds_user import WINDOWS_2012_AND_FUTHER_ATTR
from ntds_entries.ntds_acl import translate_guid
from ntds_entries.sddl import parse_ntSecurityDescriptor, ACEAccessFlags
import sqlite3
from termcolor import colored

import time
from functools import wraps

def execution_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        msg = f"Execution time of {func.__name__}: {elapsed_time:.4f} seconds"
        print(colored(msg,'blue',attrs=['bold']))
        return result
    return wrapper

# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids
def translate_builtin_sid(sid):
    builtin_sids = {
        "S-1-1-0" : "Everyone",
        "S-1-2-0" : "Local",
        "S-1-2-1" : "Console Logon",
        "S-1-3-0" : "Creator Owner ID",
        "S-1-3-1" : "Creator Group ID",
        "S-1-3-2" : "Owner Server",
        "S-1-3-3" : "Group Server",
        "S-1-3-4" : "Owner Rights",
        "S-1-4" : "Non-unique Authority",
        "S-1-5" : "NT Authority",
        "S-1-5-80-0" : "All Services",
        "S-1-5-1" : "Dial Up",
        "S-1-5-113" : "Local account",
        "S-1-5-114" : "Local account and member of Administrators group",
        "S-1-5-2" : "Network",
        "S-1-5-3" : "Batch",
        "S-1-5-4" : "Interactive",
        "S-1-5-6" : "Service",
        "S-1-5-7" : "Anonymous Logon",
        "S-1-5-8" : "Proxy",
        "S-1-5-9" : "Enterprise Domain Controllers",
        "S-1-5-10" : "Self", 
        "S-1-5-11" : "Authenticated Users",
        "S-1-5-12" : "Restricted Code",
        "S-1-5-13" : "Terminal Server User",
        "S-1-5-14" : "Remote Interactive Logon",
        "S-1-5-15" : "This Organization",
        "S-1-5-17" : "IUSR",
        "S-1-5-18" : "System (or LocalSystem)",
        "S-1-5-19" : "NT Authority (LocalService)",
        "S-1-5-20" : "Network Service",
        "S-1-5-32-544": "Administrators",
        "S-1-5-32-545": "Users",
        "S-1-5-32-546": "Guests",
        "S-1-5-32-547": "Power Users",
        "S-1-5-32-548": "Account Operators",
        "S-1-5-32-549": "Server Operators",
        "S-1-5-32-550": "Print Operators",
        "S-1-5-32-551": "Backup Operators",
        "S-1-5-32-552": "Replicators",
        "S-1-5-64-10": "NTLM Authentication",
        "S-1-5-64-14": "SChannel Authentication",
        "S-1-5-64-21": "Digest Authentication",
        "S-1-5-80": "NT Service",
        "S-1-5-80-0": "All Services",
        "S-1-5-83-0": "NT VIRTUAL MACHINE\Virtual Machines"           
    }
    r = builtin_sids.get(sid)
    return sid if r is None else r

FIELDS = { # List of attributes to search
    'cn':'ATTm3',
    'sAMAccountName':'ATTm590045',
    'userPrincipalName':'ATTm590480',
    'primaryGroupID':'ATTj589922',
    'logonCount':'ATTj589993',
    'adminCount':'ATTj589974', 
    'lDAPDisplayName':'ATTm131532',
    'badPwdCount':'ATTj589836',
    'Description':'ATTm13',
    'userPrincipalName':'ATTm590480',
    'comment':'ATTm589980', 
    'info':'ATTm131153',
    'operatingSystem':'ATTm590187',
    'operatingSystemVersion':'ATTm590188',
    'operatingSystemServicePack':'ATTm590189',
    ############
    # To process
    # UID
    'objectGUID':'ATTk589826',
    # Delegation
    'allowedToDelegateTo': 'ATTm591611',
    'allowedToActOnBehalfOfOtherIdentity': 'ATTp592006', # Resource-based Constrained Delegation 
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

    ############
    # Date
    'whenCreated':'ATTl131074',
    'whenChanged':'ATTl131075',
    'accountExpires': 'ATTq589983',
    'pwdLastSet':'ATTq589920',
    'lastLogon':'ATTq589876',

    'maxPwdAge':'ATTq589898',
    'lastLogonTimestamp':'ATTq591520',
    'lastLogon':'ATTq589876',
    'ntSecurityDescriptor':'ATTp131353',
    'badPasswordTime':'ATTq589873',
    ############
    # tmp 
    'tmp_domainID':'NCDNT_col',
    # Linking object OU / Orgs / Dom
    'PDNT_col':'PDNT_col',
}



SAM_GROUP_OBJECT						= 0x10000000
SAM_NON_SECURITY_GROUP_OBJECT			= 0x10000001
SAM_ALIAS_OBJECT						= 0x20000000
SAM_NON_SECURITY_ALIAS_OBJECT			= 0x20000001
SAM_USER_OBJECT							= 0x30000000
SAM_MACHINE_ACCOUNT						= 0x30000001
SAM_TRUST_ACCOUNT						= 0x30000002
SAM_APP_BASIC_GROUP						= 0x40000000
SAM_APP_QUERY_GROUP						= 0x40000001 

ACCOUNT_GROUP_TYPES = ( SAM_GROUP_OBJECT , SAM_ALIAS_OBJECT, SAM_NON_SECURITY_GROUP_OBJECT)
ACCOUNT_USER_TYPES = ( SAM_USER_OBJECT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT )
LINK_TYPES = (1, 2)

# Used to have the correct form of the sd_value
def full_hex(b):
    s = b.hex()
    sx = r"\x" + r"\x".join(s[n : n+2] for n in range(0, len(s), 2))
    # to have a correctly formed bytestring without double backslash
    return sx.encode().decode('unicode-escape').encode("raw_unicode_escape")



class NTDSFile(object):
    
    config = None

    def __init__(self, bootKey, ntdsFile, error_report):
        self.__bootkey = bootKey
        self.__NTDS = ntdsFile
        self.__ese = ESENTDB_Abstract(ntdsFile)
        self.__ese_dissect = ESENTDB_AbstractDissect(ntdsFile)
        self.__ntds_entries = dict()
        self.__PEK = list()
        self.__error_report = error_report
        self.__laps_references = {
            "laps_legacy_admpwd": None,
            "laps_legacy_admpwdexpirationtime": None,
            "laps_admpwd": None,
            "laps_admpwd_encrypted": None,
            "laps_admpwdexpirationtime": None
        }
        self.__laps_legacy_admpwd = None
        self.__laps_legacy_admpwdexpirationtime = None
        self.__laps_admpwd = None
        self.__laps_admpwdexpirationtime = None
        self.__win2k12 = None
        
    
    def __iter__(self):
        self.n = 0
        return self

    def __next__(self):
        if self.n <= self.max:
            result = 2 ** self.n
            self.n += 1
            return result
        else:
            raise StopIteration

    def __is_link_deleted(self, record):

        record_dict = record.as_dict()
        link_deltime = record_dict.get('link_deltime', None)
        link_metadata = record_dict.get('link_metadata', None)
        if link_deltime and link_deltime != 3038287259199220266:
            if link_metadata is not None:             
                count = LINK_METADATA(link_metadata)["count"]
                if count % 2 == 0:                   # if even row
                    # If the counter is even --> link deleted
                    # a priori the counter is incremented with each deletion
                    # 1 --> link creation
                    # 2 --> deletion
                    # 3 --> link restoration
                    # ....
                    logger.debug("LINK DELETED ***")
                    return True
        return False

    def __is_win2k12_or_sup(self,raw_entry):
        for key, value in WINDOWS_2012_AND_FUTHER_ATTR.items():
            if value in raw_entry.as_dict():
                continue
            else:
                self.__win2k12 = False
                return False
        self.__win2k12 = True
        return True


    def parse_linktable(self):
        print(colored("[+] Parsing linktable...", 'green',attrs=['bold']))
        
        linktable = self.__ese_dissect.esentdb_open("link_table")
        for record in self.__ese_dissect.esentdb_read_records():
            
            if record.as_dict()["link_base"] in LINK_TYPES:
                master_indx = record.as_dict()["link_DNT"]
                slave_indx = record.as_dict()["backlink_DNT"]
                if self.__is_link_deleted(record):
                    logger.debug("LINK SKIPPED ***")
                    continue
                self.add_link(slave_indx, master_indx)
        print(colored("[+] Parsing linktable done.", 'green',attrs=['bold']))
                
                
    def get_current_domain_SID(self, report_dir_path, domain, dump_acl):
        """
        Extracts the SID for a given domain name from a CSV file and returns a list of all domain names.

        Parameters:
        - domain_csv_file (str): The path to the CSV file.
        - domain (str): The domain name for which to extract the SID.

        Returns:
        - tuple: 
            - The SID for the given domain name, or None if not found.
            - A list of domain names found in the CSV.
        """

        domain_names = []
        selected_domain = None
        domain_sid = None
        domain_found = False

        try:
            with open(report_dir_path+"/report_domains.csv", mode='r', newline='', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                if len(rows) == 1:
                    domain_names.append(rows[0]["name"])
                    domain_sid = rows[0]["SID"]
                    selected_domain = rows[0]["name"]
                    domain_found = True
                else:
                    for row in rows:
                        domain_names.append(row["name"])
                        if row["name"] == domain:
                            domain_sid = row["SID"]
                            selected_domain = row["name"]
                            domain_found = True
            if not domain_found and dump_acl: # only check if we ask to dump the acl for a specific domain
                filtered_domain_names = [domain for domain in domain_names if "$" not in domain]
                logger.error(f"Your NTDS contains several domains: {filtered_domain_names}")
                logger.error(f"Please choose one of them with the -d option")
                exit(-1)
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return None, selected_domain  # Return the list of domain names even if there's an error
        return domain_sid, selected_domain

    @execution_time            
    def parse_sdtable(self):
        print(colored("[+] Parsing sdtable...", 'green',attrs=['bold']))
        self.__ese_dissect.esentdb_open("sd_table")
        bulk_insert_list = []
        uniq_owner = set()
        for sd_record in self.__ese_dissect.esentdb_read_records():
            try:
                sd_value = full_hex(sd_record.get("sd_value"))
                
                 # Adding SIDs from SACL
                ntSecurityDescriptor = parse_ntSecurityDescriptor(sd_record.get("sd_value"))
                ntSecurityDescriptor["sd_id"] = sd_record.get("sd_id")
                uniq_owner.add(ntSecurityDescriptor["Owner SID"])
                bulk_insert_list.append(ntSecurityDescriptor)
            except NotImplementedError:
                logger.error("ACL parsing error detected (NotImplementedError)")
            except IndexError:
                logger.error("ACL parsing error detected (IndexError)")
        acls_count = len(bulk_insert_list)               
        logger.info(f"Parsing ACL done: {acls_count} ACLs")
        self.__ese_dissect.close()
        print(colored("[+] Parsing sdtable done.", 'green',attrs=['bold']))
        
        return bulk_insert_list,acls_count  # Return the count of ACLs processed

    @execution_time
    def list_ace_raw(self, domain, domain_SID):
        seen_aces = set()
        parsed_sd_table,count = self.parse_sdtable()
        for e in parsed_sd_table:            
            if e['Type']['DACL Present']:
                aceType = e['DACL']['ACEs'][0]['Type']
                if 'Access Allowed' in aceType or 'Access Allowed Object' in aceType:
                    aceList = e['DACL']['ACEs'][0]['Access Required']
                    if aceList['Generic Read'] or aceList['Generic Write'] or aceList['Generic Execute'] or aceList['Generic All'] or aceList['Access SACL'] or aceList['Delete'] or aceList['Read Control'] or aceList['Write DAC'] or aceList['Write Owner'] or aceList['Synchronise'] or aceList['Maximum Allowed'] or aceList['Ads Create Child'] or aceList['Ads Delete Child'] or aceList['Ads List'] or aceList['Ads Self Write'] or aceList['Ads Read Prop'] or aceList['Ads Write Prop'] or aceList['Ads Delete Tree'] or aceList['Ads List Object'] or aceList['Ads Control Access']:
                        sd_id = e['sd_id']
                        owner = e["Owner SID"]
                        aceList = e['DACL']['ACEs']
                        for entry in aceList:
                            trustee = entry["SID"]
                            flags = entry['Access Required']
                            for f in ACEAccessFlags:
                                if flags.get(f, False):
                                    obj_type = entry.get("GUID", "").replace('{', '').replace('}', '')
                                    obj_type = translate_guid(obj_type)
                                    inherited_object_type = entry.get("Inherited GUID", "").replace('{', '').replace('}', '')
                                    inherited_object_type = translate_guid(inherited_object_type)
                                    ace = (domain, sd_id, trustee, f, obj_type, inherited_object_type, owner)
                                    if ace not in seen_aces:
                                        seen_aces.add(ace)
                                        yield ace
                                


    def decode_guid(s):
        part1 =  "%08x-%04x-%04x-" % struct.unpack("<IHH", s[:8])
        part2 = "%04x-%08x%04x" % struct.unpack(">HIH", s[8:])
        return part1+part2

    @execution_time
    def parse_datable(self):
        print(colored("[+] Parsing datatable...", 'green',attrs=['bold']))
        
        # List of dynamic attributes that change from one NTDS to another
        ATTRIBUTES = {
            'LAPS_ADMPWD_REF': 'ms-Mcs-AdmPwd', # LAPS password legacy
            'LAPS_ADMPWDEXP_REF': 'ms-Mcs-AdmPwdExpirationTime', # LAPS password expiration time legacy
            'NEW_LAPS_ADMPWD_REF': 'msLAPS-Password', # LAPS password cleartext
            'NEW_LAPS_ADMPWD_ENCRYPTED_REF': 'msLAPS-EncryptedPassword', # LAPS password encrypted
            'NEW_LAPS_ADMPWDEXP_REF': 'msLAPS-PasswordExpirationTime' # LAPS password expiration time
        }
        datatable = self.__ese_dissect.esentdb_open("datatable")
        for record in self.__ese_dissect.esentdb_read_records():
            # search LAPS
            if "ATTm131532" in record.as_dict() and record.as_dict()["ATTm131532"] is not None: # ATTm131532 = lDAPDisplayName
                if ATTRIBUTES['LAPS_ADMPWD_REF'] in record.as_dict()["ATTm131532"]:
                    logger.debug('LAPS ms-Mcs-AdmPwd found. Dynamique id = %s', record.as_dict()["ATTj591540"])  # ATTj591540 = msDS-IntId            
                    self.__laps_references["laps_legacy_admpwd"] = record.as_dict()["ATTj591540"]
                if ATTRIBUTES['LAPS_ADMPWDEXP_REF'] in record.as_dict()["ATTm131532"]:
                    logger.debug('LAPS ms-Mcs-AdmPwdExpirationTime found. Dynamique id = %s', record.as_dict()["ATTj591540"])
                    self.__laps_references["laps_legacy_admpwdexpirationtime"] = record.as_dict()["ATTj591540"]
                if ATTRIBUTES['NEW_LAPS_ADMPWD_REF'] in record.as_dict()["ATTm131532"] and self.__laps_references["laps_admpwd"] is None:
                    logger.debug('NEW LAPS msLAPS-Password found. Dynamique id = %s', record.as_dict()["ATTj591540"])
                    self.__laps_references["laps_admpwd"] = record.as_dict()["ATTj591540"]
                # we take the highest value if there are multiple (we don't know why there are multiple values sometimes)  
                if ATTRIBUTES['NEW_LAPS_ADMPWD_ENCRYPTED_REF'] in record.as_dict()["ATTm131532"] \
                    and (self.__laps_references["laps_admpwd_encrypted"] is None \
                         or abs(self.__laps_references["laps_admpwd_encrypted"]) < abs(record.as_dict()["ATTj591540"])): 
                    logger.debug('NEW LAPS msLAPS-EncryptedPassword found. Dynamique id = %s', record.as_dict()["ATTj591540"])
                    self.__laps_references["laps_admpwd_encrypted"] = record.as_dict()["ATTj591540"]
                if ATTRIBUTES['NEW_LAPS_ADMPWDEXP_REF'] in record.as_dict()["ATTm131532"]:
                    logger.debug('NEW LAPS msLAPS-PasswordExpirationTime found. Dynamique id = %s', record.as_dict()["ATTj591540"])
                    self.__laps_references["laps_admpwdexpirationtime"] = record.as_dict()["ATTj591540"]
            if self.__win2k12 is None:
                self.__is_win2k12_or_sup(record)
            self.add_entry(record.as_dict())
        print(colored("[+] Parsing datatable done.", 'green',attrs=['bold']))
            
        
    '''
    Get type for entry:
    * OU (abscontainer)
    * Container (abscontainer)
    * Domain 
    * Group
    * User
    '''
    def __get_type(self, raw_entry):

        dnt_col = raw_entry['DNT_col']
        # ATTc0 = objectClass. Values 65541 and 196631 and 655436 have been determined through testing, no doc seems to be available online
        if 'ATTc0' in raw_entry:          
            if isinstance(raw_entry['ATTc0'],int) and raw_entry['ATTc0'] == 65541:
                return NTDSOU(dnt_col)
            elif isinstance(raw_entry['ATTc0'],list) and 65541 in raw_entry['ATTc0']: # == '040500010000000100': value when parsing with impacket
                return NTDSOU(dnt_col)
                
            elif isinstance(raw_entry['ATTc0'],int) and raw_entry['ATTc0'] == 196631:
                return NTDSContainer(dnt_col)
            elif isinstance(raw_entry['ATTc0'],list) and 196631 in raw_entry['ATTc0']:
                return NTDSContainer(dnt_col)
            # particular cases of built-in groups that have a different objectclass ("foreign security principal") such as Everyone or Authenticated Users (S-1-1-0 and S-1-5-11). we need additionnal filters as it retrieves object from foreign domains (e.g. if there is a trust)
            elif isinstance(raw_entry['ATTc0'],int) and raw_entry['ATTc0'] == 655436:
                return NTDSGroups(dnt_col)
            elif isinstance(raw_entry['ATTc0'],list) and 655436 in raw_entry['ATTc0']:
                return NTDSGroups(dnt_col)

        # https://github.com/yosqueoy/ditsnap/blob/aecc3147986439d3c55a3b1848a71428d5b06440/ditsnap_exe/DetailDialog.cpp
        # JoinString : https://github.com/yosqueoy/ditsnap/blob/aecc3147986439d3c55a3b1848a71428d5b06440/ditsnap_exe/util.cpp
        # We filter on the domains that have a SID ('ATTr589970')
        if 'ATTc0' in raw_entry and 'ATTr589970' in raw_entry  and raw_entry["ATTr589970"] is not None:
            if raw_entry['ATTc0'] == '06000a000e0043000a0042000a0000000100':
                logger.debug('DOMAIN found : %d', dnt_col)
                # if a value is provided, we deduce that LAPS is installed
                is_laps_installed = not all(value is None for value in self.__laps_references.values()) 
                return NTDSDomain(dnt_col, is_laps_installed)
        
        # If ATT_TRUST_AUTH_INCOMING or ATT_TRUST_AUTH_OUTGOING exist
        if ('ATTk589953' in raw_entry and raw_entry["ATTk589953"] is not None) or ('ATTk589959' in raw_entry and raw_entry["ATTk589959"] is not None):
            logger.debug('TRUST found : %d', dnt_col)
            return NTDSTrust(dnt_col)
        #if DOMAIN_ATT_TO_INTERNAL["dc"] in raw_entry and raw_entry[DOMAIN_ATT_TO_INTERNAL["dc"]] is not None:
        #    logger.debug('DOMAIN found : %d', dnt_col)
        #    logger.debug('raw_entry[b"ATTc0"] : %s' % raw_entry[b"ATTc0"])
        #    return NTDSDomain(dnt_col)


        # Test if the attribute exists. ATTj590126 = samAccountType
        # from testing:
        # 805306368 = users
        # 805306370 = domain
        # 536870912 = group 
        # 805306369 = machine 
        # 268435456 = group 
        
        if "ATTj590126" in raw_entry and raw_entry["ATTj590126"] is not None:            
            if raw_entry["ATTj590126"] == 805306368 or raw_entry["ATTj590126"] == 805306369:  # in ACCOUNT_USER_TYPES :
                return NTDSUsers(dnt_col, CryptoHash(self.__PEK), self.__laps_references, self.__win2k12)
            elif raw_entry["ATTj590126"] == 536870912 or raw_entry["ATTj590126"] == 268435456: # 536870912 is in ACCOUNT_GROUP_TYPES:
                return NTDSGroups(dnt_col)
            elif raw_entry["ATTj590126"] == 805306370:
                logger.debug('DOMAIN found : %d', dnt_col)
                # If a value is provided, we deduce that LAPS is installed
                is_laps_installed = not all(value is None for value in self.__laps_references.values()) 
                return NTDSDomain(dnt_col, is_laps_installed)
        if 'PDNT_col' in raw_entry:
            # 2 == ROOT_OBJECT 
            # Should be universal ...
            if raw_entry['PDNT_col'] == 2:
                # If a value is provided, we deduce that LAPS is installed
                is_laps_installed = not all(value is None for value in self.__laps_references.values()) 
                return NTDSDomain(dnt_col, is_laps_installed)

        
        if 'RDNtyp_col' in raw_entry:
            if raw_entry['RDNtyp_col'] == 1376281:
                # If a value is provided, we deduce that LAPS is installed
                is_laps_installed = not all(value is None for value in self.__laps_references.values()) 
                return NTDSDomain(dnt_col, is_laps_installed)


        return None

    def add_entry(self, raw_entry):

        # Check for PEK entry
        try:
            if raw_entry['ATTk590689'] is not None:
                
                peklist =  raw_entry['ATTk590689']
                self.__PEK = CryptoPEK.decrypt_PEK(peklist, self.__bootkey)
        except KeyError:
            pass      

        dnt_col = raw_entry['DNT_col']
        entryType = self.__get_type(raw_entry)

        if entryType is not None:
            # Check if entry is malformated ... (thanks esedb)
            try:
                if raw_entry['ATTr589970'] is not None:
                    try:                        
                        SAMR_RPC_SID(raw_entry['ATTr589970'])
                    except:
                        self.__dump_entry_raw(raw_entry)
                        logger.error("Entry corrupted - esedb - %s" % dnt_col)
                        return
            except KeyError:
                pass            

            self.__ntds_entries[dnt_col] = entryType
            
            for key, value in entryType.config.items():
                try:
                    if raw_entry[value] is not None and isinstance(raw_entry[value], str):
                        entryType.entry[key] = raw_entry[value].replace("\n","\\n").replace("\r","\\r")
                    else:
                        entryType.entry[key] = raw_entry[value]
                except KeyError:
                    pass        
            self.__ntds_entries[dnt_col] = entryType

    def __add_element(self, key, array):
        if key not in array:
            array.append(key)

    def __get_group_from_rid(self, rid):
        for key, value in self.__ntds_entries.items():
            if rid == value.get_RIDid():
                return key

    def __get_entry(self, idx):
        try:
            ntds_entry = self.__ntds_entries[idx]
            return ntds_entry
        except KeyError:
            test = "tac"
        
        return None

    def __get_value(self, idx, name):
        ntds_entry = self.__get_entry(idx)

        if ntds_entry is not None:
            try:
                return ntds_entry.entry[name]
            except KeyError:
                logger.error("The attribute for the NTDS entry is not found : %d  / %s " % (idx, name))
                logger.error(" > ntds_entry[%d].entry : %s " % (idx, ntds_entry.entry))
        
        return None

    def update_ntdsentries(self):
        print(colored("[+] Update ntdsentries...", 'green',attrs=['bold']))
        self.__update_full_domainname()
        
        self.__update_alldomains()
        self.__update_allsid()
        self.__update_primarygroups()
        
        # Need the link table
        self.__update_alllinks()

        # Build domain fullname for groups
        self.__update_groupname()

        # Need PEK
        self.__update_cryptedvalue()

        # Convert DNT to SID
        self.__convert_dnt_sid()

        # updating info on OU / Containers
        self.__update_abscontainers()

    def __update_allsid(self):
        for key, value in self.__ntds_entries.items():           
            SID = value.get_SID()
            if SID is not None:
                try:
                    if value.is_domain():               
                        sid = LDAP_SID(SID).formatCanonical()
                    elif value.is_user() or value.is_group():
                        sid = LDAP_SID(SID).formatCanonical()
                        value.rid = int(sid.split('-')[-1])
                    else:
                        continue
                    value.sid = sid
                except:
                    logger.error("CORRUPTED - __update_allsid")
                    value.rid = 0
                    value.sid = "CORRUPTED"
                    continue
                
    def __update_alldomains(self):

        logger.info("Building domains for users/groups ...")
        for key, value in self.__ntds_entries.items():
            get_domain_id = value.get_domain_id()
            if get_domain_id != None:
                domain = self.__get_value(get_domain_id, "dc")
                root_domain = self.__get_entry(get_domain_id)
                if hasattr(root_domain, 'domain_fullname') and root_domain.domain_fullname is not None:
                    value.domain = self.__get_entry(get_domain_id).domain_fullname

    def __update_full_domainname(self):
        logger.info("Building full domain names ...")
        for key_entry, value in self.__ntds_entries.items():
            if value.is_domain() or value.is_ou() or value.is_container():
                logger.debug(value.entry)
                value_entry = value.entry
                domain_fullname = value.entry["RDN"]
                if "PDNT_col" in value_entry:
                    
                    link_info = self.__get_entry(value_entry["PDNT_col"])
                    if link_info:
                        while not link_info.is_rootdomain():
                            domain_fullname = "%s.%s" % (domain_fullname, link_info.entry["RDN"])
                            link_info = self.__get_entry(link_info.entry["PDNT_col"])
                            if not link_info:
                                break
                        if link_info:
                            domain_fullname = "%s.%s" % (domain_fullname, link_info.entry["RDN"])
                        
                value.domain_fullname = domain_fullname


    def __update_primarygroups(self):

        logger.info("processing primarygroup for groups ...")
        for key_entry, value in self.__ntds_entries.items():
            if value.is_group() or value.is_user():
                value_entry = value.entry
                if "primaryGroupID" in value_entry and value_entry["primaryGroupID"] is not None:
                    primaryGroupID = self.__get_group_from_rid(value_entry["primaryGroupID"])
                    primary_entry = self.__get_entry(primaryGroupID)
                    if primary_entry is not None:
                        value.primarygroup = primary_entry.sid
                    

                        if value and value.is_user():
                            self.__add_element(primaryGroupID, value.groups)
                            if hasattr(primary_entry, 'users'): # Fix add to avoid parsing error (rare)
                                self.__add_element(key_entry, primary_entry.users)
                        elif value.is_group():
                            self.__add_element(primaryGroupID, value.subgroups)


    def __update_abscontainers(self):
        logger.info("processing OUs and Containers ...")
        for key, value in self.__ntds_entries.items():
            value_entry = value.entry
            if "PDNT_col" in value_entry and value_entry["PDNT_col"] is not None:

                ref_entry = self.__get_entry(value_entry["PDNT_col"])

                if ref_entry and (ref_entry.is_ou() or ref_entry.is_container()):
                    if value.is_user():
                        ref_entry.users.append(value.sid)
                    elif value.is_group():
                        ref_entry.groups.append(value.sid)
                    elif value.is_ou():
                        ref_entry.groups.append(value.name)
                    elif value.is_container():
                        ref_entry.containers.append(value.name)
                else:
                    logger.debug("Containers missing : %s" % value_entry["PDNT_col"])

    
    def __update_alllinks(self):

        # Process subgroups
        for key, value in self.__ntds_entries.items():
            if value.is_group():
                for subgroup_key in value.subgroups:
                    if subgroup_key != "":
                        self.__process_subgroup(subgroup_key, key)

    def __process_subgroup(self, subgroup_key, top_group_key):
        
        top_group = self.__get_entry(top_group_key)
        group = self.__ntds_entries[subgroup_key]
        self.__add_element(subgroup_key, top_group.subgroups)
        
        # add sub sers:
        if len(group.users) > 0:
            for subuser in group.users:
                if subuser != "":
                    self.__add_element(subuser, top_group.subusers)
                    self.__add_element(top_group_key, self.__get_entry(subuser).groups)

        if len(group.subgroups) > 0:
            for subgroup in group.subgroups:
                self.__add_element(subgroup, top_group.subgroups)

    def __update_cryptedvalue(self):

        logger.info("processing crypted value for users")
        for key, value in self.__ntds_entries.items():
            if value.is_user():
                value.decryptHash()
                

    def __get_array_dnt_sid(self, a_entry):
        """
        Function to retrieve the SID from the UID of an entry
        """
        a_entrys_sid = [] 
        for idx_entry in a_entry:
            entry_sid = self.__get_entry(idx_entry).sid
            a_entrys_sid.append(entry_sid)

        return a_entrys_sid


    def __get_array_dnt_legacy(self, a_entry):
        """
        Fonction qui permet de récupérer le fullname et non les SID associés
        """
        a_entrys_legacy = [] 
        for idx_entry in a_entry:
            entry = self.__get_entry(idx_entry)
            if entry:
                entry_name = entry.get_fullname()
            else:
                # If the entry is empty, it means there was an issue with parsing
                # We just add the ID to indicate that the ID is missing
                entry_name = f'MISSING-{str(idx_entry)}'
            a_entrys_legacy.append(entry_name)

        return a_entrys_legacy

    def __convert_dnt_sid(self):

        logger.info("Converting DNT ref to SID")
        for key, value in self.__ntds_entries.items():

            if value.is_group():
                # We handle the legacy format (for CSV export in case of issues)
                value.users_names = self.__get_array_dnt_legacy(value.users)
                value.subgroups_legacy = self.__get_array_dnt_legacy(value.subgroups)
                value.subusers_names = self.__get_array_dnt_legacy(value.subusers)

                value.users = self.__get_array_dnt_sid(value.users)
                value.subgroups = self.__get_array_dnt_sid(value.subgroups)
                value.subusers = self.__get_array_dnt_sid(value.subusers)

            elif value.is_user():
                for group in value.groups:
                    value.groups_name.append(self.__get_entry(group).sid)
                    value.groups_name_legacy.append(self.__get_entry(group).get_fullname())

    def __update_groupname(self):
        for key, value in self.__ntds_entries.items():
            if value.is_group():
                value.fulldomainname = "%s|%s|%s" % (value.domain, value.entry["cn"], key)

    def add_link(self, slave_idx, master_idx):
        

        ntds_entry_master = self.__get_entry(master_idx)
        ntds_entry_slave = self.__get_entry(slave_idx)

        # Check first if the exists (loaded ?)
        if ntds_entry_master!= None and ntds_entry_slave != None:
            # Test to which type it is Group / Users
            if ntds_entry_slave.is_user():
                ntds_entry_master.users.append(slave_idx)
                self.__add_element(master_idx, self.__get_entry(slave_idx).groups)
            elif ntds_entry_slave.is_group():
                ntds_entry_master.subgroups.append(slave_idx)
            else:
                return

    def update_count_hashnt(self):
        a_hashnt_count = {}
        a_hashnt_count["all"] = []
        
        for key, value in self.__ntds_entries.items():
            if value.is_user() and not value.is_disable():
                if not value.domain in a_hashnt_count:
                    a_hashnt_count[value.domain] = []
                a_hashnt_count[value.domain].append(value.get_hashnt())
                a_hashnt_count["all"].append(value.get_hashnt())

        for domain in a_hashnt_count:
            a_hashnt_count[domain] = dict(Counter(a_hashnt_count[domain]))

        # Count the occurrences of hashNT by domain and globally
        for key, value in self.__ntds_entries.items():
            if value.is_user() and not value.is_disable():
                value.uniq = a_hashnt_count["all"][value.get_hashnt()]
                # DOMAIN ONLY
                value.uniq_dom = a_hashnt_count[value.domain][value.get_hashnt()]

    def dump_csv(self, ntdsReport):

        # init CSV
        for key, value in self.__ntds_entries.items():
            entry = value.get_entry()
            if entry:
                if value.is_user():
                    ntdsReport.users.dump_entry(entry)
                    ntdsReport.john.dump_entry(value.get_john())
                    ntdsReport.john_history.dump_entry(value.get_john_history())
                elif value.is_group():
                    ntdsReport.groups.dump_entry(entry)
                elif value.is_domain():
                    ntdsReport.domains.dump_entry(entry)
                elif value.is_trust():
                    ntdsReport.trusts.dump_entry(entry)
                elif value.is_ou() or value.is_container():
                    ntdsReport.absContainers.dump_entry(entry)
        
        ntdsReport.flush()

    @execution_time
    def dump_sqlite_correlations(self,report_dir_path):
        print(colored("[+] Creating sqlite Correlations table...", 'green',attrs=['bold']))
        
        # Connect to SQLite database (or create it if it doesn't exist)
        conn = sqlite3.connect(report_dir_path+'/sqlite.db')
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS Correlations")
        # Create table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS Correlations (
            domain TEXT,
            SID TEXT,
            name TEXT,
            sd_id INTERGER,
            PRIMARY KEY (domain, SID, name)
        )
        ''')

        # Add indexes to optimize queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON Correlations(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sid ON Correlations(SID)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_name ON Correlations(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sd_id ON Correlations(sd_id)')

        for key, value in self._NTDSFile__ntds_entries.items():     
            if value.is_user() or value.is_group():
                domain = value.domain
                raw_sid = value.get_SID()
                if raw_sid is not None:
                    sid = LDAP_SID(raw_sid).formatCanonical()                
                if value.is_user():
                    name = value.get_login()
                else:    
                    # either returns the translation of a well-known SID in arg, or the arg
                    name = translate_builtin_sid(value.entry["cn"])
                sd_id = value.get_security_descriptor(value.entry["ntSecurityDescriptor"])
                cursor.execute("INSERT INTO Correlations (domain, SID, name, sd_id) VALUES (?, ?, ?, ?)", (domain, sid, name, sd_id))
            elif value.is_ou():
                domain = value.domain
                raw_sid = value.get_SID()
                if raw_sid is not None:
                    sid = LDAP_SID(raw_sid).formatCanonical()
                else:
                    sid = raw_sid
                name = translate_builtin_sid(sid)
                if name is None:
                    entry = value.get_entry()
                    name = entry["domain_fullname"]
                sd_id = value.get_security_descriptor(value.entry["ntSecurityDescriptor"])
                cursor.execute("INSERT INTO Correlations (domain, SID, name, sd_id) VALUES (?, ?, ?, ?)", (domain, sid, name, sd_id))
            elif value.is_domain():
                entry = value.get_entry()
                domain = entry['name']
                name = entry['name']
                sid = entry['SID']
                sd_id = entry['ntSecurityDescriptor']
                cursor.execute("INSERT INTO Correlations (domain, SID, name, sd_id) VALUES (?, ?, ?, ?)", (domain, sid, name, sd_id))
       
        # Commit the changes and close the connection to the database
        conn.commit()
        conn.close()
        print(colored("[+] Sqlite Correlations table created.", 'green',attrs=['bold']))
        

    @execution_time
    def dump_csv_user(self,report_dir_path):
        print(colored("[+] Dumping users to CSV file...", 'green',attrs=['bold']))
        
        headers_user = [
                        'domain', 'login', 'uid', 'SID', 'hashlm', 'hashnt', 'kerberosKeys', 'clearTextPwds', \
                        'servicePrincipalName', 'primarygroup', 'groups', 'groups_c', 'groups_legacy', 'logoncount', \
                        'badpasscount', 'description', 'created', 'change', 'lastlogon', 'lastLogonTimestamp', 'expired', \
                        'lastpasswordset', 'status', 'allowedToDelegateTo', 'allowedToActOnBehalfOfOtherIdentity', 'comment', \
                        'remark', 'os', 'version', 'operatingSystemServicePack', 'msMcsAdmPwd', 'msMcsAdmPwdExpirationTime', \
                        'msLAPSPasswordEncrypted', 'msLAPSPasswordExpirationTime', 'sIDHistory', 'uniq', 'uniq_dom', 'adminCount', \
                        'ntSecurityDescriptor'
                    ]
        csv_file = report_dir_path+"/report_users.csv"
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers_user)
            writer.writeheader()
            for key, value in self._NTDSFile__ntds_entries.items():
                if value.is_user():
                    entry = value.get_entry()
                    writer.writerow(entry)
        print(colored("[+] Users CSV file created.", 'green',attrs=['bold']))
        

    @execution_time
    def dump_csv_group(self,report_dir_path):
        print(colored("[+] Dumping groups to CSV file...", 'green',attrs=['bold']))
        
        headers_group = [
                            'domain', 'name', 'uid', 'SID', 'Users', 'Users_c', 'Users_names', 'SubGroups', \
                            'SubGroups_c', 'SubGroups_legacy', 'SubUsers', 'SubUsers_c', 'SubUsers_names', 'ntSecurityDescriptor'
                        ]
        csv_file = report_dir_path+"/report_groups.csv"
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers_group)
            writer.writeheader()
            for key, value in self._NTDSFile__ntds_entries.items():
                if value.is_group():
                    entry = value.get_entry()                    
                    writer.writerow(entry)
        print(colored("[+] Groups CSV file created.", 'green',attrs=['bold']))
                    

    @execution_time
    def dump_csv_domain(self,report_dir_path):
        print(colored("[+] Dumping domains to CSV file...", 'green',attrs=['bold']))
        
        headers_domain = [
                            'name', 'uid', 'SID', 'lockoutThreashold', 'forceLogoff', 'lockoutDuration', 'lockoutTime', \
                            'lockOutObservationWindow', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdProperties', \
                            'pwdHistoryLength', 'machineAccountQuota', 'lapsInstalled', 'ntSecurityDescriptor'
                        ]
        csv_file = report_dir_path+"/report_domains.csv"
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers_domain)
            writer.writeheader()
            for key, value in self._NTDSFile__ntds_entries.items():
                if value.is_domain():
                    entry = value.get_entry()
                    # keep only interesting domains (it sorts out *.root-servers.net.* etc.)
                    if entry["SID"] is not None:
                        writer.writerow(entry)
                     

    @execution_time
    def dump_csv_trust(self,report_dir_path):
        print(colored("[+] Dumping trusts to CSV file...", 'green',attrs=['bold']))
        
        headers_trust = ['domain', 'name', 'trustPartner', 'trustType', 'trustDirection', 'trustAttributes', 'trustAuthIncoming', \
                         'trustAuthOutgoing', 'created', 'change']
        csv_file = report_dir_path+"/report_trusts.csv"
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers_trust)
            writer.writeheader()
            for key, value in self._NTDSFile__ntds_entries.items():
                if value.is_trust():
                    entry = value.get_entry()
                    writer.writerow(entry)
        print(colored("[+] Trusts CSV file created.", 'green',attrs=['bold']))
                      

    @execution_time
    def dump_csv_ou_container(self,report_dir_path):
        print(colored("[+] Dumping OU and containers to CSV file...", 'green',attrs=['bold']))
        
        headers_ou_container = ['domain', 'domain_fullname', 'entry_type', 'name', 'users_sid', 'users_name', 'groups_sid', 'groups_name', \
                                'ous', 'containers', 'ntSecurityDescriptor']
        # opening the sqlite db to search for correlations betweed SID and user/group names
        conn = sqlite3.connect(report_dir_path+'/sqlite.db')
        cursor = conn.cursor()
        csv_file = report_dir_path+"/report_ou_containers.csv"
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers_ou_container)
            for key, value in self._NTDSFile__ntds_entries.items():
                if value.is_ou() or value.is_container():
                    entry = value.get_entry()
                    domain = entry['domain']
                    # Matching SID with user names    
                    if entry['users'] != '':                 
                        str_users_sid = entry['users']                    
                        users_sid_list = [sid.strip() for sid in str_users_sid.split(',')]
                        list_users_name = []
                        for sid in users_sid_list:
                            cursor.execute("SELECT name FROM Correlations WHERE SID = ? AND domain = ?", (sid,domain)) 
                            res = cursor.fetchone()
                            try:
                                res_user_name = res[0]
                            except TypeError as e:    
                                logger.debug("ntds_file dump_csv_ou_container res_user_name %s" % e)
                                res_user_name = sid                                                                      
                            list_users_name.append(res_user_name)
                        str_users_name = ','.join(map(str, list_users_name))
                    else:
                        str_users_sid = ''
                        str_users_name = ''
                    # Matching SID with group names
                    if entry['groups'] != '':    
                        str_groups_sid = entry['groups']
                        groups_sid_list = [sid.strip() for sid in str_groups_sid.split(',')]                        
                        list_groups_name = []                        
                        for sid in groups_sid_list:
                            cursor.execute("SELECT name FROM Correlations WHERE SID = ? AND domain = ?", (sid,domain)) 
                            res = cursor.fetchone()  
                            try:
                                res_group_name = res[0]
                            except TypeError as e:    
                                logger.debug("ntds_file dump_csv_ou_container res_group_name %s" % e)
                                res_group_name = translate_builtin_sid(sid)       
                            list_groups_name.append(res_group_name) 
                        str_groups_name = ','.join(map(str, list_groups_name))
                    else:
                        str_groups_sid = ''
                        str_groups_name = ''                    
                    domain_fullname = entry['domain_fullname']
                    entry_type = entry['entry_type']
                    name = entry['name']                         
                    ous = entry['ous']
                    containers = entry['containers']
                    ntSecurityDescriptor = entry['ntSecurityDescriptor']
                    line = (domain, domain_fullname, entry_type, name, str_users_sid, str_users_name, str_groups_sid,str_groups_name, ous, containers, ntSecurityDescriptor)
                    writer.writerow(line)
                    
        print(colored("[+] OU and containers CSV file created.", 'green',attrs=['bold']))
                       

                  

    @execution_time
    def dump_csv_suspicious_acl(self,report_dir_path,domain,domain_SID):
        print(colored("[+] Dumping suspicious ACEs to CSV file...", 'green',attrs=['bold']))
        
        headers_acl = ['domain', 'sd_id', 'trustee', 'trustee_sid', 'permission', 'objectGuid', 'inheritedobjectGuid', 'target','owner', 'owner_sid']
        conn = sqlite3.connect(report_dir_path+'/sqlite.db')
        # Create a cursor object using the cursor method
        cursor = conn.cursor()
        csv_file = report_dir_path+"/report_suspicious_acl.csv"
        builtin_rid = ["0","7","11","545"] # Everyone, Anonymous, Authenticated users, Domain Users
        seen_owner = set()
        with open(csv_file,'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers_acl)
            
            for e in self.list_ace_raw(domain,domain_SID):
                sd_id = e[1]
                trustee_sid = e[2]
                permission = e[3]
                objectGuid = e[4]
                inheritedobjectGuid = e[5]
                owner_sid = e[6]
                rid_owner = owner_sid.split("-")[-1]

                # finding name of the trustee with their SID
                cursor.execute("SELECT name FROM Correlations WHERE SID = ? AND domain = ?", (trustee_sid,domain))
                res_trustee_name = cursor.fetchone()
                try:
                    trustee_name = res_trustee_name[0]
                except TypeError as e:    
                    logger.debug("ntds_file dump_csv_acl trustee_name %s" % e)
                    trustee_name = trustee_sid
                rid_trustee = trustee_sid.split("-")[-1]

                # finding name of the owner with their SID
                cursor.execute("SELECT name FROM Correlations WHERE SID = ? AND domain = ?", (owner_sid,domain))
                res_owner_name = cursor.fetchone()
                try:
                    owner_name = res_owner_name[0]
                except TypeError as e:
                    logger.debug("ntds_file dump_csv_acl owner_name %s" % e)
                    owner_name = translate_builtin_sid(owner_sid)
                
                # finding each object name corresponding to the sd_id
                cursor.execute("SELECT name FROM Correlations WHERE sd_id = ? AND domain = ?", (sd_id,domain))
                res_target_name = cursor.fetchall()
                if len(res_target_name) > 0:
                    for n in res_target_name:
                        target_name = n[0]
                        r = (domain,sd_id,trustee_name,trustee_sid,permission,objectGuid,inheritedobjectGuid,target_name,owner_name,owner_sid)
                        # Check if the owner is an interesting object ()
                        if target_name != owner_name and (rid_owner in builtin_rid or len(rid_owner) > 3):
                            permission_own = "Owns"
                            r_own = (domain,sd_id,owner_name,owner_sid,permission_own,"","",target_name,owner_name,owner_sid)
                            if r_own not in seen_owner:
                                seen_owner.add(r_own)
                                writer.writerow(r_own)
                        if target_name != trustee_name and (rid_trustee in builtin_rid or len(rid_trustee) > 3) :
                            if permission == "Write Owner" or permission == "Write DAC":
                                writer.writerow(r)
                            elif permission == "Ads Control Access": # (All) Extended Rights, DCSync, ForceChangePassword
                                # AllExtendedRights
                                if objectGuid == "" and inheritedobjectGuid == "":
                                    permission_aer = "AllExtendedRights"
                                    r_aer = (domain,sd_id,trustee_name,trustee_sid,permission_aer,objectGuid,inheritedobjectGuid,target_name,owner_name,owner_sid)
                                    writer.writerow(r_aer)
                                # TODO other interesting targeted ExtendedRights
                                # ForceChangePassword
                                if objectGuid == "Reset Password" or inheritedobjectGuid == "Reset Password":
                                    writer.writerow(r)
                                # DCSync, even if not both rights because it can be interesting
                                if objectGuid == "Replicating Directory Changes" \
                                 or inheritedobjectGuid == "Replicating Directory Changes" \
                                 or objectGuid == "Replicating Directory Changes All" \
                                 or inheritedobjectGuid == "Replicating Directory Changes All":
                                    writer.writerow(r)
                            elif permission == "Ads Write Prop": # do a match case for interesting (inherited)objectGuid
                                # AddMember
                                if objectGuid == "Add/Remove member" or inheritedobjectGuid == "Add/Remove member":
                                    writer.writerow(r)
                                # WriteAccountRestrictions
                                elif objectGuid == "Account Restrictions" \
                                 or inheritedobjectGuid == "Account Restrictions" \
                                 or objectGuid == "userAccountControl" \
                                 or inheritedobjectGuid == "userAccountControl":
                                    writer.writerow(r)
                                # AddKeyCredentialLink
                                elif objectGuid == "Add Key Credential Link" or inheritedobjectGuid == "Add Key Credential Link":
                                    writer.writerow(r)
                                elif objectGuid == "msds-ManagedPassword" or "inheritedobjectGuid" == "msds-ManagedPassword":
                                    writer.writerow(r)
                            elif permission == "Ads Self Write":
                                # AddMemberSelf
                                if objectGuid == "Add/Remove member" or inheritedobjectGuid == "Add/Remove member":
                                    writer.writerow(r)                        
                else:
                    target_name = "not found"
        print(colored("[+] Suspicious ACEs CSV file created.", 'green',attrs=['bold']))
         

    def dump_csv_global(self, report_dir_path, domain, domain_SID, dump_options):
        print(colored("[+] Dumping data to CSV files...", 'green', attrs=['bold']))
        
        if dump_options['users']:
            self.dump_csv_user(report_dir_path)
        if dump_options['groups']:
            self.dump_csv_group(report_dir_path)
        if dump_options['trusts']:
            self.dump_csv_trust(report_dir_path)
        if dump_options['domains']:
            self.dump_csv_domain(report_dir_path)
        if dump_options['ou']:
            self.dump_csv_ou_container(report_dir_path)
        if dump_options['acl']:
            self.dump_csv_suspicious_acl(report_dir_path, domain, domain_SID)
        
        print(colored("[+] All CSV files created.", 'green', attrs=['bold']))
          

    def __dump_entry_raw(self, raw_entry):
        return None
        # Dumping an error report for the corrupted entry
        # self.__error_report.dump_entry("****** DUMPING ERROR ENTRY ******\n")
        # for key, value in raw_entry.items():
        #     self.__error_report.dump_entry("%-30s: %r\n" % (key, value))
        # self.__error_report.dump_entry("****** ******************* ******\n\n")


    def debug_groups(self):
        for key, value in self.__ntds_entries.items():
            if value.is_group():
                value.debug()

    def debug_users(self):
        for key, value in self.__ntds_entries.items():
            if value.is_user():
                value.debug()

    def debug(self):
        print("******* DEBUG *******")
        for key, value in self.__ntds_entries.items():
            print(value.debug())
