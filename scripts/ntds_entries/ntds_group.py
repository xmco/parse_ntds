from logging_config import logger

from ntds_entries.ntds_entry import NTDSEntry

GROUP_ATT_TO_INTERNAL = {

    'uSNCreated':'ATTq131091',
    'uSNChanged':'ATTq131192',
    'cn':'ATTm3',
    'RID':'ATTj589922',
    'sAMAccountType':'ATTj590126',
    'objectSID':'ATTr589970',
    # Value needed to be processed
    # Maybe need to be isolated ?
    #'tmp_primaryGroupID':'ATTj589922',
    'tmp_domainID':'NCDNT_col',
    'ntSecurityDescriptor': 'ATTp131353',
    # Linking object OU / Orgs / Dom
    'PDNT_col':'PDNT_col',
}


class NTDSGroups(NTDSEntry):

    config = GROUP_ATT_TO_INTERNAL

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()
        self.users = []
        self.subgroups = []
        self.subusers = []

        '''
        Legacy field
        Nom au lieu des SID
        '''
        self.users_names = []
        self.subusers_names = []
        self.subgroups_legacy = []
        self.domain = None
        self.fullname = None

    def is_group(self):
        return True

    def get_RIDid(self):
        return self.rid

    def get_SID(self):
        return self.entry["objectSID"]

    def get_fullname(self):
        return f'{self.domain}|{self.entry["cn"]}'

    def debug(self):
        print("******* DEBUG - %s - GROUP *******" % self.entry["cn"])
        print("Entry: %s" % self.entry)
        print("Users : %s" % self.users)
        print("SubGroups : %s" % self.subgroups)
        print("SubUsers : %s" % self.subusers)

    def get_entry(self):
        csv_entry = {
            "domain": self.domain,
            "name": self.entry["cn"],
            "uid": self.uid,
            "SID": self.sid,
            "Users": self.show_list(self.users),
            "Users_c": len(self.users),
            "Users_names": self.show_list(self.users_names),
            "SubGroups": self.show_list(self.subgroups),
            "SubGroups_c": len(self.subgroups),
            "SubGroups_legacy": self.show_list(self.subgroups_legacy),
            "SubUsers": self.show_list(self.subusers),
            "SubUsers_c": len(self.subusers),
            "SubUsers_names": self.show_list(self.subusers_names),
            "ntSecurityDescriptor": self.get_security_descriptor(self.entry["ntSecurityDescriptor"]),
        }
        return csv_entry