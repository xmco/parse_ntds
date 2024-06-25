from logging_config import logger

from ntds_entries.ntds_entry import NTDSEntry

ROOT_DOMAIN_ATT_TO_INTERNAL = {
    'RDN': 'ATTm589825'
}

MID_DOMAIN_ATT_TO_INTERNAL = {
    'RDN': 'ATTm589825',
    'PDNT_col':'PDNT_col',
}

DOMAIN_ATT_TO_INTERNAL = {
    'dc':'ATTm1376281',
    'RDN': 'ATTm589825',
    'PDNT_col':'PDNT_col',
    'objectSID':'ATTr589970',
    'lockoutThreashold': 'ATTj589897' ,# ): Long
    'forceLogoff': 'ATTq589863', #Currency
    'lockoutDuration': 'ATTq589884', #Currency
    'lockoutTime': 'ATTq590486', #Currency
    'lockOutObservationWindow': 'ATTq589885', #Currency
    'maxPwdAge': 'ATTq589898', #Currency
    'minPwdAge': 'ATTq589902', #Currency
    'minPwdLength': 'ATTj589903', # Long
    'pwdProperties': 'ATTj589917', #Long
    'pwdHistoryLength': 'ATTj589919', #Long
    'ms-DS-MachineAccountQuota': 'ATTj591235', #Long
    'ntSecurityDescriptor': 'ATTp131353', #Int en hex
}

class NTDSDomain(NTDSEntry):

    config = DOMAIN_ATT_TO_INTERNAL

    def __init__(self, dnt_col, is_laps_installed):
        super().__init__(dnt_col)
        self.entry = dict()
        self.domain_fullname = ""
        self.is_laps_installed = is_laps_installed
    
    def get_domain_id(self):
        return None
    
    def is_domain(self):
        return True

    def get_SID(self):
        try:
            return self.entry["objectSID"]
        except KeyError:
            logger.debug("get_SID domain: no objectSID attribute for %s", self.domain_fullname)

    def get_lockoutThreashold(self):
        try:
            return self.entry["lockoutThreashold"]
        except KeyError:
            logger.debug("get_lockoutThreashold domain: no lockoutThreashold attribute")

    def get_forceLogoff(self):
        try:
            return self.format_duration(self.entry["forceLogoff"])
        except KeyError:
            logger.debug("get_forceLogoff domain: no forceLogoff attribute")

    def get_lockoutDuration(self):
        try:
            return self.format_duration(self.entry["lockoutDuration"])
        except KeyError:
            logger.debug("get_lockoutDuration domain: no lockoutDuration attribute")

    def get_lockoutTime(self):
        try:
            return self.format_duration(self.entry["lockoutTime"])
        except KeyError:
            logger.debug("get_lockoutTime domain: no lockoutTime attribute")     

    def get_lockOutObservationWindow(self):
        try:
            return self.format_duration(self.entry["lockOutObservationWindow"])
        except KeyError:
            logger.debug("get_lockOutObservationWindow domain: no lockOutObservationWindow attribute")  

    def get_maxPwdAge(self):
        try:
            return self.format_duration(self.entry["maxPwdAge"])
        except KeyError:
            logger.debug("get_maxPwdAge domain: no maxPwdAge attribute") 

    def get_minPwdAge(self):
        try:
            return self.format_duration(self.entry["minPwdAge"])
        except KeyError:
            logger.debug("get_minPwdAge domain: no minPwdAge attribute")      

    def get_minPwdLength(self):
        try:
            return self.entry["minPwdLength"]
        except KeyError:
            logger.debug("get_minPwdLength domain: no minPwdLength attribute")   

    def get_pwdProperties(self):
        try:
            return self.entry["pwdProperties"]
        except KeyError:
            logger.debug("get_pwdProperties domain: no pwdProperties attribute")   

    def get_pwdHistoryLength(self):
        try:
            return self.entry["pwdHistoryLength"]
        except KeyError:
            logger.debug("get_pwdHistoryLength domain: no pwdHistoryLength attribute")  

    def get_MachineAccountQuota(self):
        try:
            return self.entry["ms-DS-MachineAccountQuota"]
        except KeyError:
            logger.debug("get_MachineAccountQuota domain: no ms-DS-MachineAccountQuota attribute") 

    def get_ntSecurityDescriptor(self):
        try:
            return self.get_security_descriptor(self.entry["ntSecurityDescriptor"])
        except KeyError:
            logger.debug("get_ntSecurityDescriptor domain: no ntSecurityDescriptor attribute")              

    def get_entry(self):
        
        csv_entry = {
                "name": self.domain_fullname,
                "uid": self.uid,
                "SID": self.sid,
                "lockoutThreashold": self.get_lockoutThreashold(),
                "forceLogoff": self.get_forceLogoff(),
                "lockoutDuration": self.get_lockoutDuration(),
                "lockoutTime": self.get_lockoutTime(),
                "lockOutObservationWindow": self.get_lockOutObservationWindow(),
                "maxPwdAge": self.get_maxPwdAge(),
                "minPwdAge": self.get_minPwdAge(),
                "minPwdLength": self.get_minPwdLength(),
                "pwdProperties": self.get_pwdProperties(),
                "pwdHistoryLength": self.get_pwdHistoryLength(),
                'machineAccountQuota': self.get_MachineAccountQuota(),
                'lapsInstalled':self.is_laps_installed,
                "ntSecurityDescriptor": self.get_ntSecurityDescriptor(),
        }
        #logger.debug(csv_entry)
        return csv_entry


class NTDSRootDomain(NTDSEntry):

    config = ROOT_DOMAIN_ATT_TO_INTERNAL

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()
    
    def get_domain_id(self):
        return None
    
    def is_rootdomain(self):
        return True
    
    def is_domain(self):
        return True


class NTDSMidDomain(NTDSEntry):

    config = MID_DOMAIN_ATT_TO_INTERNAL

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()
    
    def get_domain_id(self):
        return None
    
    def is_middomain(self):
        return True

    def is_domain(self):
        return True
