from logging_config import logger

from ntds_entries.ntds_entry import NTDSEntry



TRUST_ATT_TO_INTERNAL = {
    'RDN': 'ATTm589825',  #str
    'trustPartner':'ATTm589957', #str
    'trustType': 'ATTj589960', #int
    'trustDirection': 'ATTj589956', #int
    'trustAttributes': 'ATTj590294', #int
    'trustAuthIncoming': 'ATTk589953', #bytes
    'trustAuthOutgoing': 'ATTk589959', #bytes
    'whenCreated': 'ATTl131074', #  create
    'whenChanged':'ATTl131075', # change 
    'flatName': 'ATTm590335', #Actual name of the trust
    'PDNT_col':'PDNT_col',
    'tmp_domainID':'NCDNT_col',
}

TRUST_ATTRIBUTE = {
    1: 'TRUST_ATTRIBUTE_NON_TRANSITIVE',
    2: 'TRUST_ATTRIBUTE_UPLEVEL_ONLY',
    4: 'TRUST_ATTRIBUTE_QUARANTINED_DOMAIN',
    8: 'TRUST_ATTRIBUTE_FOREST_TRANSITIVE',
    10: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION',
    20: 'TRUST_ATTRIBUTE_WITHIN_FOREST',
    40: 'TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL',
    80: 'TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION',
    200: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION_NO_TGT_DELEGATION',
    800: 'TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION',
    400: 'TRUST_ATTRIBUTE_PIM_TRUST'
}

def find_keys_sum(d, target, partial=[], used_keys=[]):
    if target in d: # If the value is a key, return it
        return [target]
    s = sum(partial)
    # if the sum of the keys is equal to the target value, return the list of the keys
    if s == target: 
        return partial
    if s >= target:
        return None # no solution

    # for each key in the dict, check if it has already been used
    # if not, compute the sum of the keys added with this key
    # call the func recursively to check if the sum is equal to the target value
    for key in d:
        if key not in used_keys:
            remaining = d[key]
            n = find_keys_sum(d, target, partial + [key], used_keys + [key])
            if n:
                return n


class NTDSTrust(NTDSEntry):

    config = TRUST_ATT_TO_INTERNAL

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()
        self.domain_fullname = ""
    
    def is_trust(self):
        return True

    def get_entry(self):
        if self.entry["trustAttributes"]:
            attribute = int(hex(self.entry["trustAttributes"]).split('x')[1])
        else:
            attribute = 0
        csv_entry = {
                "domain": self.entry["RDN"],
                "name": self.entry["flatName"],
                "trustPartner": self.entry["trustPartner"],
                "trustType": self.entry["trustType"],
                "trustDirection": self.entry["trustDirection"],
                "trustAttributes": self.show_list(find_keys_sum(TRUST_ATTRIBUTE, attribute)), #les attributs doivent être converti en hexa. Ex: 72 = 0x00000048 = 48
                "trustAuthIncoming": self.entry["trustAuthIncoming"],
                "trustAuthOutgoing": self.entry["trustAuthOutgoing"],
                "created": self.fileTimeToDateTime(self.entry["whenCreated"]* 10000000),
                "change": self.fileTimeToDateTime(self.entry["whenChanged"]* 10000000),
        }
        #logger.debug(csv_entry)
        return csv_entry

    

