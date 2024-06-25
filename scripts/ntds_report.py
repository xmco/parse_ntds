from logging_config import logger
import hashlib

from ntds_esedb import ESENTDB_Abstract

def dump_csv_ntds_report(ntds_path, ntdsReport):

    eseNTDS = ESENTDB_Abstract(ntds_path)

    entry = {
    "DBState":get_DBState_tostring(eseNTDS.ese._ESENT_DB__DBHeader['DBState']),
    "WindowsMajorVersion":eseNTDS.ese._ESENT_DB__DBHeader['WindowsMajorVersion'],
    "WindowsMinorVersion":eseNTDS.ese._ESENT_DB__DBHeader['WindowsMinorVersion'],
    "WindowsBuildNumber":eseNTDS.ese._ESENT_DB__DBHeader['WindowsBuildNumber'],
    "WindowsServicePackNumber":eseNTDS.ese._ESENT_DB__DBHeader['WindowsServicePackNumber'],
    "Version":eseNTDS.ese._ESENT_DB__DBHeader['Version'],
    "ShadowingDisables":eseNTDS.ese._ESENT_DB__DBHeader['ShadowingDisables'],
    "CheckSum":eseNTDS.ese._ESENT_DB__DBHeader['CheckSum'],
    "NLSMajorVersion":eseNTDS.ese._ESENT_DB__DBHeader['NLSMajorVersion'],
    "NLSMinorVersion":eseNTDS.ese._ESENT_DB__DBHeader['NLSMinorVersion'],
    "ntdsSHA1" : ntds_sha1(ntds_path)
    }

    ntdsReport.dump_entry(entry)
    ntdsReport.flush()
    ntdsReport.close()
    eseNTDS.close()

def get_DBState_tostring(DBState):

    '''
    Source : https://github.com/SecureAuthCorp/impacket/blob/429f97a894d35473d478cbacff5919739ae409b4/impacket/ese.py
    '''
    switcher = {
        1: "JET_dbstateJustCreated",
        2: "JET_dbstateDirtyShutdown",
        3: "JET_dbstateCleanShutdown",
        4: "JET_dbstateBeingConverted",
        5: "JET_dbstateForceDetach",
    }

    return switcher.get(DBState, "Unknown state - %d" % DBState)


def ntds_sha1(ntds_path):

    BUF_SIZE = 65536 
    sha1 = hashlib.sha1()
    with open(ntds_path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)

    return sha1.hexdigest()