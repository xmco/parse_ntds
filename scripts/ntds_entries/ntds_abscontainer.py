from logging_config import logger

from ntds_entries.ntds_entry import NTDSEntry



# ATTb590606 = 1635
OU_ATT_TO_INTERNAL = {
    'PDNT_col':'PDNT_col',
    'OrganizationUnitName': 'ATTm11',
    'whenCreated': 'ATTl131074',
    'whenChanged':'ATTl131075',
    'tmp_domainID':'NCDNT_col',
    'RDN': 'ATTm589825',
    'ntSecurityDescriptor': 'ATTp131353',
}

# ATTb590606 = 1371
CONTAINER_ATT_TO_INTERNAL = {
    'PDNT_col':'PDNT_col',
    'CommonName': 'ATTm3',
    'whenCreated': 'ATTl131074',
    'whenChanged':'ATTl131075',
    'tmp_domainID':'NCDNT_col',
    'RDN': 'ATTm589825',
    'ntSecurityDescriptor': 'ATTp131353',
}

class NTDSAbsContainer(NTDSEntry):

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()
        self.users = []
        self.groups = []
        self.ous = []
        self.containers = []
        self.domain = None
        self.domain_fullname = ""

    def get_domain_id(self):
        return self.entry["tmp_domainID"]
    
    @property
    def namee(self):
        return None

    @namee.setter
    def name(self):
        return None
    
    def get_type(self):

        if isinstance(self, NTDSContainer):
            return "Container"
        elif isinstance(self, NTDSOU):
            return "OU"
        else:
            return ""

    def get_SID(self):
        try:
            return self.entry["objectSID"]
        except KeyError:
            logger.debug("ntds_abscontainer get_SID : " + str(KeyError))

    def get_entry(self):

        csv_entry = {
                "domain": self.domain,
                "domain_fullname": self.domain_fullname,
                "entry_type": self.get_type(),
                "name": self.get_name(),
                "users": self.show_list(self.users),
                "groups": self.show_list(self.groups),
                "ous": self.show_list(self.ous),
                "containers": self.show_list(self.containers),
                "ntSecurityDescriptor": self.get_security_descriptor(self.entry["ntSecurityDescriptor"]),
        }
        return csv_entry

class NTDSContainer(NTDSAbsContainer):

    config = CONTAINER_ATT_TO_INTERNAL

    @property
    def namee(self):
        return self.entry["CommonName"]

    def get_name(self):
        return self.entry["CommonName"]

    def is_container(self):
        return True

class NTDSOU(NTDSAbsContainer):

    config = OU_ATT_TO_INTERNAL

    @property
    def namee(self):
        return self.entry["OrganizationUnitName"]
    
    def get_name(self):
        return self.entry["OrganizationUnitName"]
    
    def is_ou(self):
        return True
