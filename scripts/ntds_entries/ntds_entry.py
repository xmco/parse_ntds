# -*- coding: utf-8 -*-
from logging_config import logger
from binascii import unhexlify
from datetime import datetime

#from impacket.ldap import ldaptypes
from struct import unpack_from, unpack

from ntds_common import LDAP_SID

class NTDSEntry(object):

    config = None

    def __init__(self, dnt_col):
        self.entry = dict()
        self.sid = None
        self.rid = None
        self.uid = dnt_col

    def get_id(self):
        return self.entry["DNT_col"]

    def get_domain_id(self):
        return self.entry["tmp_domainID"]
    
    def show_list(self, v_list):
        if v_list is not None:
            if isinstance(v_list, str):
                return v_list
            else:
                first = True
                s_list = ""
                for value in v_list:
                    if first == True:
                        s_list = "%s" % value
                        first = False
                    else:
                        s_list = "%s , %s" %(s_list, value)
                return s_list
        return None

    '''
    Dummy function
    '''

    def is_group(self):
        return False

    def is_user(self):
        return False

    def is_rootdomain(self):
        return False
    
    def is_domain(self):
        return False

    def is_trust(self):
        return False

    def is_middomain(self):
        return False

    def is_container(self):
        return False

    def is_ou(self):
        return False

    def get_RIDid(self):
        return None

    def get_SID(self):
        return None
    
    def get_entry(self):
        return None
    
    '''
    Methods pour traiter les entrées NTDS
    '''
    @staticmethod
    def decode_sidhistory(entry):
        
        sidHistory = []
        
        if entry:
            '''
            Impacket ne gère pas les multi value et ne renvoie pas les flags associés à une entrée, du coup faut tenter et voir si ca passe ...
            # ToDo: Parse multi-values properly
            https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/impacket/ese.py
            '''
            try:
                #b_entry = bytes.fromhex(entry.decode())
                if isinstance(entry,list):
                    for e in entry:
                        sid = LDAP_SID(e).formatCanonical()
                        sidHistory.append(sid)
                else:
                    sid = LDAP_SID(entry).formatCanonical()
                    sidHistory.append(sid)
            except:
                sid = LDAP_SID(entry)
                sidHistory.append(sid.formatCanonical())

        return sidHistory

    @staticmethod
    def get_security_descriptor(data):
        """
        Return the right sd_id to link with the sd_table
        """
        #logger.info("get_security_descriptor: "+str(data))
        return unpack("<Q",data)[0]
    
    @staticmethod
    def isutf_16le(data):
        try:
            data.decode('utf-16le')
        except UnicodeDecodeError:
            return False
        else:
            return True

    @staticmethod
    def isutf_32le(data):
        try:
            data.decode('utf-32le')
        except UnicodeDecodeError:
            return False
        else:
            return True

    @staticmethod
    def isutf_16be(data):
        try:
            data.decode('utf-16be')
        except UnicodeDecodeError:
            return False
        else:
            return True

    @staticmethod
    def isutf_32be(data):
        try:
            data.decode('utf-32be')
        except UnicodeDecodeError:
            return False
        else:
            return True

    @staticmethod
    def fileTimeToDateTime(t):

        if t == None:
            return ""
        t -= 116444736000000000
        t //= 10000000

        # Bug - setting access time beyond Jan. 2038 
        # https://bugs.python.org/issue13471
        if t == 910692730085:
            return ""
        if t < 0:
            return ""
        else:
            try:
               dt = datetime.fromtimestamp(t)
            except:
                print("****** BUG ****** : %d" % t)
                return t
            return dt.strftime("%Y-%m-%d %H:%M")

    @staticmethod
    def truncate_nanotimestamp(t):
        if t != None:
            dt = datetime.fromtimestamp(t)
            return dt.strftime("%Y-%m-%d %H:%M")
        else:
            return None
    
    '''
    Exemple:
    maxPwdAge = (-1) x 10 days x 24 hours/day x 60 minutes/hour x 60 seconds/minute x 10,000,000 ticks/second = -8,640,000,000,000 ticks
    '''
    @staticmethod
    def format_duration(t):
        if t:
            t_s = -1 * t / 600000000
            return int(t_s)            
        else:
            return None

    def debug(self):
        logger.debug("******* DEBUG *******")
        logger.debug(self.entry)

    def debug_stack(self):
        logger.debug(self.__dict__)
        logger.debug(dir(self))
        logger.debug(type(self))