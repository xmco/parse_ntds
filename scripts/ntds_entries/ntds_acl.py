from logging_config import logger
import json
import struct
import binascii
from functools import reduce
import re

from ntds_entries.ntds_entry import NTDSEntry
from ntds_entries.sddl import ACEAccessFlags


sd_table_fields = ['sd_id', 'sd_hash', 'sd_refcount', 'sd_value']



T0_ASSETS_RID = [
    '500', # Built-in Administrator
    '512', # Domain Admins Group
    '516', # Domain controller
    '517', # Cert Publishers
    '518', # Schema Admins Group
    '519', # Enterprise Admins Group
    '520', # Group Policy Creator Owners
    '521', # Read-only Domain Controllers
    '526', # Key Admins
    '527', # Enterprise Key Admins
    #to test LAPS
    '26596', # Server LAPS
]

# Built-in group with no domain SID (e.g S-1-5-32-544).
T0_BUILTIN_ASSETS_SID = [
    '11',  # Authenticated Users
    '544', # Administrators Group
    '548', # Account Operators Group
    '549', # Server Operators Group
    '550', # Print Operators Group
    '551', # Backup Operators Group
]

ACE_FLAGS = [ 
    'GenericRead', 
    'GenericWrite', 
    'GenericExecute', 
    'GenericAll', 
    'AccessSACL', 
    'Delete', 
    'ReadControl', 
    'WriteDAC', 
    'Write Owner', 
    'Synchronize', 
    'AccessSystemSecurity', 
    'MaximumAllowed', 
    'StandardsRightsRequired', 
    'StandardRightsAll', 
    'SpecificRightsAll', 
    'ADSRightDSCreateChild', 
    'ADSRightDSDeleteChild', 
    'ADSRightACTRLDSList', 
    'ADSRightDSSelf', 
    'ADSRightDSReadProp', 
    'ADSRightDSWriteProp', 
    'ADSRightDSDeleteTree', 
    'ADSRightDSListObject', 
    'ADSRightDSControlAccess'
]



def decode_sid(s, endianness="<"):
    "Depending on the source, last sub-authority will be little or big endian"
    rev,subauthnb = struct.unpack_from("<BB",s)
    rev &= 0x0f
    iah,ial = struct.unpack_from(">IH", s[2:])
    ia = (iah<<16)|ial
    if subauthnb > 0:
        subauth = struct.unpack_from("<%iI" % (subauthnb-1), s[8:-4])
        subauth += struct.unpack_from("%sI"%endianness, s[-4:])
    else:
        subauth = ()
    sid = "S-%i-%s" % (rev, "-".join(["%i"%x for x in ((ia,)+subauth)]))
    return sid

def decode_guid(s):
    part1 =  "%08x-%04x-%04x-" % struct.unpack("<IHH", s[:8])
    part2 = "%04x-%08x%04x" % struct.unpack(">HIH", s[8:])
    return part1+part2

def translate_guid(guid):
    flags = {
        "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain Administer Server",
        "ab721a53-1e2f-11d0-9819-00aa0040529b": "Change Password",
        "00299570-246d-11d0-a768-00aa006e0529": "Reset Password",
        "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send As",
        "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive As",
        "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send To",
        "c7407360-20bf-11d0-a768-00aa006e0529": "Domain Password & Lockout Policies",
        "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General Information",
        "4c164200-20c0-11d0-a768-00aa006e0529": "Account Restrictions",
        "5f202010-79a5-11d0-9020-00c04fc2d4cf": "Logon Information",
        "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Group Membership",
        "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open Address List",
        "77B5B886-944A-11d1-AEBD-0000F80367C1": "Personal Information",
        "E45795B2-9455-11d1-AEBD-0000F80367C1": "Phone and Mail Options",
        "E45795B3-9455-11d1-AEBD-0000F80367C1": "Web Information",
        "5b47d60f-6090-40b2-9f37-2a4de88f3063": "Add Key Credential Link",
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes",
        "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "Replication Synchronization",
        "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "Manage Replication Topology",
        "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change Schema Master",
        "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change Rid Master",
        "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do Garbage Collection",
        "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate Hierarchy",
        "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate Rids",
        "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change PDC",
        "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add GUID",
        "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change Domain Master",
        "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public Information",
        "4b6e08c0-df3c-11d1-9c86-006008764d0e": "Receive Dead Letter",
        "4b6e08c1-df3c-11d1-9c86-006008764d0e": "Peek Dead Letter",
        "4b6e08c2-df3c-11d1-9c86-006008764d0e": "Receive Computer Journal",
        "4b6e08c3-df3c-11d1-9c86-006008764d0e": "Peek Computer Journal",
        "06bd3200-df3e-11d1-9c86-006008764d0e": "Receive Message",
        "06bd3201-df3e-11d1-9c86-006008764d0e": "Peek Message",
        "06bd3202-df3e-11d1-9c86-006008764d0e": "Send Message",
        "06bd3203-df3e-11d1-9c86-006008764d0e": "Receive Journal",
        "b4e60130-df3f-11d1-9c86-006008764d0e": "Open Connector Queue",
        "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply Group Policy",
        "037088f8-0ae1-11d2-b422-00a0c968f939": "Remote Access Information",
        "9923a32a-3607-11d2-b9be-0000f87a36b2": "Add/Remove Replica In Domain",
        "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change Infrastructure Master",
        "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update Schema Cache",
        "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate Security Inheritance",
        "69ae6200-7f46-11d2-b9ad-00c04f79f805": "Check Stale Phantoms",
        "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate Enrollment",
        "bf9679c0-0de6-11d0-a285-00aa003049e2": "Add/Remove member",
        "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated write to DNS host name",
        "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated write to service principal name",
        "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate Resultant Set of Policy (Planning)",
        "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh Group Cache for Logons",
        "91d67418-0135-4acc-8d79-c08e857cfbec": "Enumerate Entire SAM Domain",
        "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate Resultant Set of Policy (Logging)",
        "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other Domain Parameters (for use by SAM)",
        "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS Host Name Attributes",
        "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create Inbound Forest Trust",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes All",
        "BA33815A-4F93-4c76-87F3-57574BFF8109": "Migrate SID History",
        "45EC5156-DB7E-47bb-B53F-DBEB2D03C40F": "Reanimate Tombstones",
        "68B1D179-0D15-4d4f-AB71-46152E79A7BC": "Allowed to Authenticate",
        "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "Execute Forest Update Script",
        "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "Monitor Active Directory Replication",
        "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update Password Not Required Bit",
        "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire Password",
        "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable Per User Reversibly Encrypted Password",
        "1F298A89-DE98-47b8-B5CD-572AD53D267E": "Exchange Information",
        "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "Query Self Quota",
        "B1B3A417-EC55-4191-B327-B72E33E38AF2": "Exchange Personal Information",
        "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private Information",
        "a7a9ea66-e08c-4e23-8fe7-68c40e49c6c0": "Accept Forest Headers",
        "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read Only Replication Secret Synchronization",
        "c307dccd-6676-4d19-95c8-d1567fab9820": "Accept Organization Headers",
        "ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
        "04031f4f-7c36-43ea-9b49-4bd0f5f1e6af": "Accept Routing Headers",
        "5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal Server License Server",
        "ce4c81a8-afe6-11d2-aa04-00c04f8eedd8": "Add PF to admin group",
        "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload SSL/TLS Certificate",
        "8e48d5a8-b09e-11d2-aa06-00c04f8eedd8": "Exchange administrator",
        "89e95b76-444d-4c62-991a-0facbeda640c": "Replicating Directory Changes In Filtered Set",
        "8e6571e0-b09e-11d2-aa06-00c04f8eedd8": "Exchange full administrator",
        "8ff1383c-b09e-11d2-aa06-00c04f8eedd8": "Exchange public folder read-only administrator",
        "90280e52-b09e-11d2-aa06-00c04f8eedd8": "Exchange public folder service",
        "d19299b4-86c2-4c9a-8fa7-acb70c63023a": "Bypass Anti-Spam",
        "6760cfc5-70f4-4ae8-bc39-9522d86ac69b": "Bypass Message Size Limit",
        "cf0b3dc8-afe6-11d2-aa04-00c04f8eedd8": "Create public folder",
        "cf4b9d46-afe6-11d2-aa04-00c04f8eedd8": "Create top level public folder",
        "BD919C7C-2D79-4950-BC9C-E16FD99285E8": "Download Offline Address Book",
        "8DB0795C-DF3A-4aca-A97D-100162998DFA": "Exchange Web Services Impersonation",
        "bc39105d-9baa-477c-a34a-997cc25e3d60": "Allow Impersonation to Personal Exchange Information",
        "06386F89-BEFB-4e48-BAA1-559FD9221F78": "Exchange Web Services Token Serialization",
        "cf899a6a-afe6-11d2-aa04-00c04f8eedd8": "Mail-enable public folder",
        "D74A8769-22B9-11d3-AA62-00C04F8EEDD8": "Modify public folder ACL",
        "D74A876F-22B9-11d3-AA62-00C04F8EEDD8": "Modify public folder admin ACL",
        "cffe6da4-afe6-11d2-aa04-00c04f8eedd8": "Modify public folder deleted item retention",
        "cfc7978e-afe6-11d2-aa04-00c04f8eedd8": "Modify public folder expiry",
        "d03a086e-afe6-11d2-aa04-00c04f8eedd8": "Modify public folder quotas",
        "d0780592-afe6-11d2-aa04-00c04f8eedd8": "Modify public folder replica list",
        "D74A8774-22B9-11d3-AA62-00C04F8EEDD8": "Open mail send queue",
        "BE013017-13A1-41ad-A058-F156504CB617": "Read metabase properties",
        "165AB2CC-D1B3-4717-9B90-C657E7E57F4D": "Access Recipient Update Service",
        "d0b86510-afe6-11d2-aa04-00c04f8eedd8": "Remove PF from admin group",
        "b3f9f977-552c-4ee6-9781-59280a81417b": "Send Forest Headers",
        "2f7d0e23-f951-4ed0-8e71-39b6a22fa298": "Send Organization Headers",
        "eb8c07ad-b5ad-49c3-831e-bc439cca4c2a": "Send Routing Headers",
        "5c82f031-4e4c-4326-88e1-8c4f0cad9de5": "Submit Messages to any Recipient",
        "b857b50b-94a2-4b53-93f6-41cebd2fced0": "Accept any Sender",
        "1c75aca8-b56b-48b3-a021-858a29fa877b": "Accept Authoritative Domain Sender",
        "c22841f4-96cb-498a-ac02-f9a87c74eb14": "Accept Exch50",
        "e373fb21-d851-4d15-af23-982f09f2400b": "Send Exch50",
        "11716db4-9647-4bce-8922-1f99e526cb41": "Submit Messages to Server",
        "a18293f1-0685-4540-aa63-e32df421b3a2": "Submit Messages for MLS",
        "D74A8762-22B9-11d3-AA62-00C04F8EEDD8": "Administer information store",
        "9fbec2a1-f761-11d9-963d-00065bbd3175": "Store constrained delegation",
        "D74A8766-22B9-11d3-AA62-00C04F8EEDD8": "Create named properties in the information store",
        "9fbec2a3-f761-11d9-963d-00065bbd3175": "Store read only access",
        "9fbec2a4-f761-11d9-963d-00065bbd3175": "Store read and write access",
        "9fbec2a2-f761-11d9-963d-00065bbd3175": "Store transport access",
        "D74A875E-22B9-11d3-AA62-00C04F8EEDD8": "View information store status",
        "4332AAD9-95AB-4e8e-A264-4965C3E1F964": "Bypass Exchange Access Auditing in the Information Store",
        "e362ed86-b728-0842-b27d-2dea7a9df218": "msds-ManagedPassword",
        "bf967a68-0de6-11d0-a285-00aa003049e2": "userAccountControl"
    }
    return flags.get(guid, guid)

def acl_to_json(acl):
    rev,_sbz,size,count,_sbz2 = struct.unpack_from("<BBHHH", acl)
    ACL = {}
    ACL["Revision"] = rev
    ACL["Size"] = size
    ACL["Count"] = count
    ACL["ACEList"] = ACEList = []
    acestr = acl[8:]
    while count > 0:
        typeraw,flags,size = struct.unpack_from("<BBH", acestr)
        type_ = ACEType(typeraw)
        ACE = {}
        ACE["Type"] = type_.to_json()
        ACE["Flags"] = ACEFlags(flags).to_json()
        ACE["Size"] = size
        amask, = struct.unpack_from("<I", acestr[4:])
        ACE["AccessMask"] = AccessMask(amask).to_json()
        sstr = acestr[8:size]
        if typeraw in [5, 6, 7, 8]:
            objflagsraw, = struct.unpack_from("<I", sstr)
            sstr = sstr[4:]
            objflags = ACEObjectFlags(objflagsraw)
            ACE["ObjectFlags"] = objflags.to_json()
            if objflags.ObjectTypePresent:
                ACE["ObjectType"] = translate_guid(decode_guid(sstr[:16]))
                sstr = sstr[16:]
            if objflags.InheritedObjectTypePresent:
                ACE["InheritedObjectType"] = translate_guid(decode_guid(sstr[:16]))
                sstr = sstr[16:]

        if typeraw in [0, 1, 2, 3, 5, 6, 7, 8]:
            ACE["SID"] = decode_sid(sstr)

        if type == 0: # ACCESS_ALLOWED
            pass
        elif type == 1: # ACCESS_DENIED
            pass
        elif type == 2: # SYSTEM_AUDIT
            pass
        elif type == 3: # SYSTEM_ALARM
            pass
        elif type == 4: # ACCESS_ALLOWED_COMPOUND
            pass
        elif type == 5: # ACCESS_ALLOWED_OBJECT
            pass
        elif type == 6: # ACCESS_DENIED_OBJECT
            pass
        elif type == 7: # SYSTEM_AUDIT_OBJECT
            pass
        elif type == 8: # SYSTEM_ALARM_OBJECT
            pass

        ACEList.append(ACE)
        acestr = acestr[size:]
        count -= 1
    return ACL
    

def sd_to_json(sd):
    jsd = {}
    try:
        rev,_sbz,rctrl,owner,group,saclofs,daclofs = struct.unpack_from("<BBHIIII", sd)
        ctrl = ControlFlags(rctrl)
        jsd["Revision"] = rev
        jsd["Control"] = ctrl.to_json()
        if ctrl.SelfRelative:
            jsd["Owner"] = decode_sid(sd[owner:])
            jsd["Group"] = decode_sid(sd[group:]) 
            if ctrl.SACLPresent:
                jsd["SACL"] = acl_to_json(sd[saclofs:])
            if ctrl.DACLPresent:
                jsd["DACL"] = acl_to_json(sd[daclofs:])
    except struct.error as e:
        logger.error("Erreur de parsing d'ACL")
    return jsd



class Flags(object):
    class __metaclass__(type):
        def __getattr__(self, attr):
            if attr in self._flags_:
                return self._flags_[attr]
            raise AttributeError(attr)
        def __getitem__(self, attr):
            return self._flags_[attr]
        def __iter__(self):
            return self._flags_.iteritems()

    _flags_ = {}
    def __init__(self, flags):
        self.flags = flags

    def test_flag(self, f):
        return bool(self.flags & f == f)

    def __getattr__(self, attr):
        if attr in self._flags_:
            return self.test_flag(self._flags_[attr])
        raise AttributeError(attr)

    def to_json(self):
        j = {}
        for k,v in self._flags_.items():
            j[k] = self.test_flag(v)
        return {"value":self.flags,"flags":j}


class Enums(object):
    _enum_ = {}
    def __init__(self, val):
        renum = {}
        for k,v in self._enum_.items():
            renum[v] = k
        self.renum = renum
        self.val = val
        self.text = self.renum.get(val, "unk:%r" % val)
    def to_json(self):
        return self.text

class SE:
    SE_OWNER_DEFAULTED               = 0x0001
    SE_GROUP_DEFAULTED               = 0x0002
    SE_DACL_PRESENT                  = 0x0004
    SE_DACL_DEFAULTED                = 0x0008
    SE_SACL_PRESENT                  = 0x0010
    SE_SACL_DEFAULTED                = 0x0020
    SE_DACL_AUTO_INHERIT_REQ         = 0x0100
    SE_SACL_AUTO_INHERIT_REQ         = 0x0200
    SE_DACL_AUTO_INHERITED           = 0x0400
    SE_SACL_AUTO_INHERITED           = 0x0800
    SE_DACL_PROTECTED                = 0x1000
    SE_SACL_PROTECTED                = 0x2000
    SE_SELF_RELATIVE                 = 0x8000

class SecurityDescriptor(object):
    def __init__(self, sd):
        self.raw_sd = sd
        _rev,_sbz,ctrl,owner,group,sacl,dacl = struct.unpack_from("<BBHIIII", sd)
        self.ctrl = ctrl
        self.owner = owner
        self.group = group

        if self.ctrl & SE.SE_SELF_RELATIVE:

            if self.ctrl & SE.SE_SACL_PRESENT:
                self.sacl = sd[sacl:dacl]
            if self.ctrl & SE.SE_DACL_PRESENT:
                self.dacl = sd[dacl:]

class ACL(object):
    def __init__(self, acl):
        _rev,_sbz,_sz,_count,_sbz2 = struct.unpack_from("<BBHHH", acl)


class ACE(object):
    def __init__(self, ace):
        _type,_flags,_size = struct.unpack_from("<BBH", ace)


class ACEType(Enums):
    _enum_ = {
        "AccessAllowed" : 0,
        "AccessDenied" : 1,
        "SystemAudit" : 2,
        "SystemAlarm" : 3,
        "AccessAllowedCompound" : 4,
        "AccessAllowedObject" : 5,
        "AccessDeniedObject" : 6,
        "SystemAuditObject" : 7,
        "SystemAlarmObject" : 8,
        }


class SidTypeName(Enums):
    _enum_ = {
        "User" : 1,
        "Domain" : 2,
        "Alias" : 3,
        "WellKnownGroup" : 4,
        "DeletedAccount" : 5,
        "Invalid" : 6,
        "Unknown" : 7,
        "Computer" : 8,
        }

class ControlFlags(Flags):
    _flags_ = {
        "OwnerDefaulted" : 0x0001,
        "GroupDefaulted" : 0x0002,
        "DACLPresent" : 0x0004,
        "DACLDefaulted" : 0x0008,
        "SACLPresent" : 0x0010,
        "SACLDefaulted" : 0x0020,
        "DACLAutoInheritReq" : 0x0100,
        "SACLAutoInheritReq" : 0x0200,
        "DACLAutoInherited" : 0x0400,
        "SACLAutoInherited" : 0x0800,
        "DACLProtected" : 0x1000,
        "SACLProtected" : 0x2000,
        "SelfRelative" : 0x8000,
        }


class ACEFlags(Flags):
    _flags_ = {
        "ObjectInheritAce" : 0x1,
        "ContainerInheritAce" : 0x2,
        "NoPropagateInheritAce" : 0x4,
        "InheritOnlyAce" : 0x8,
        "InheritedAce" : 0x10,
        "SuccessfulAccessAceFlag" : 0x40,
        "FailedAccessAceFlag" : 0x80,
        }


class ACEObjectFlags(Flags):
    _flags_ = {
        "ObjectTypePresent" : 0x1,
        "InheritedObjectTypePresent" : 0x2,
        }

# Check winnt.h to find these values or here : https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum
class AccessMask(Flags):
    _flags_ = {
        "GenericRead":              0x80000000,
        "GenericWrite":             0x40000000,
        "GenericExecute":           0x20000000,
        "GenericAll":               0x10000000,
        "AcessSystemAcl":           0x01000000,
        "Delete":                   0x00010000,
        "ReadControl":              0x00020000,
        "WriteDAC":                 0x00040000,
        "WriteOwner":               0x00080000,
        "Synchronize":              0x00100000,
        "AccessSystemSecurity":     0x01000000,
        "MaximumAllowed":           0x02000000,
        "StandardsRightsRequired":  0x000f0000,
        "StandardRightsAll":         0x001f0000,
        "SpecificRightsAll":        0x0000ffff,
        "ADSRightDSCreateChild":    0x00000001,
        "ADSRightDSDeleteChild":    0x00000002,
        "ADSRightACTRLDSList":      0x00000004,
        "ADSRightDSSelf":           0x00000008,
        "ADSRightDSReadProp":       0x00000010,
        "ADSRightDSWriteProp":      0x00000020,
        "ADSRightDSDeleteTree":     0x00000040,
        "ADSRightDSListObject":     0x00000080,
        "ADSRightDSControlAccess":  0x00000100,
    }

    

class NTDSAcl(NTDSEntry):

    def __init__(self, dnt_col):
        super().__init__(dnt_col)
        self.entry = dict()

    def get_entry(self):
        
        csv_entry = {
            "domain": self.domain,
            "sd_id": self.entry["sd_id"],
            "trustee": self.entry["trustee"],
            "permission":  self.entry["permission"],
            "objectType": self.entry["objectType"],
            "inheritedObjectType": self.entry["inheritedObjectType"],
            "owner": self.entry["owner"],
        }
        return csv_entry
    
