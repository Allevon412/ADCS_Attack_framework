from impacket.uuid import string_to_bin

EKUS = {
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.4.1.311.20.2.2":"Smart Card Logon",
    "2.5.29.37.0":"Any Purpose",
    "1.3.6.1.5.2.3.4":"PKINIT Client Authentication",
    "":"(No EKUs Present)",
    "1.3.6.1.4.1.311.20.2.1" : "Certificate Request Agent"

}

Enrollment_flags = {
    "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS": 0x00000001,
    "CT_FLAG_PEND_ALL_REQUESTS": 0x00000002,
    "CT_FLAG_PUBLISH_TO_KRA_CONTAINER": 0x00000004,
    "CT_FLAG_PUBLISH_TO_DS": 0x00000008,
    "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE": 0x00000010,
    "CT_FLAG_AUTO_ENROLLMENT": 0x00000020,
    "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT": 0x00000040,
    "CT_FLAG_USER_INTERACTION_REQUIRED": 0x00000100,
    "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE": 0x00000400,
    "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF": 0x00000800,
    "CT_FLAG_ADD_OCSP_NOCHECK" : 0x00001000,
    "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL": 0x00002000,
    "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS": 0x00004000,
    "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS": 0x00008000,
    "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT": 0x00010000,
    "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST" : 0x00020000,
    "CT_FLAG_SKIP_AUTO_RENEWAL" : 0x00040000
}

certificate_name_flags = {
    "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT": 0x00000001,
    "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME" : 0x00010000,
}

EXTRIGHTS_GUID_MAPPING = {
    "GetChanges": string_to_bin("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"),
    "GetChangesAll": string_to_bin("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"),
    "WriteMember": string_to_bin("bf9679c0-0de6-11d0-a285-00aa003049e2"),
    "UserForceChangePassword": string_to_bin("00299570-246d-11d0-a768-00aa006e0529"),
    "AllowedToAct": string_to_bin("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"),
}

ACE_ACCESS_BITS = {
    "ADS_RIGHT_DS_CREATE_CHILD" : 1,
    "ADS_RIGHT_DS_DELETE_CHILD" : 2,
    "ADS_RIGHT_ACTRL_DS_LIST" : 4,
    "ADS_RIGHT_DS_SELF" : 8,
    "ADS_RIGHT_DS_READ_PROP" : 16,
    "ADS_RIGHT_DS_WRITE_PROP" : 32,
    "ADS_RIGHT_DS_DELETE_TREE" : 64,
    "ADS_RIGHT_DS_LIST_OBJECT" : 128,
    "ADS_RIGHT_DS_CONTROL_ACCESS" : 256,
    "ADS_RIGHT_DELETE" : 65536,
    "ADS_RIGHT_READ_CONTROL" : 131072,
    "ADS_RIGHT_WRITE_DAC" : 262144,
    "ADS_RIGHT_WRITE_OWNER" : 524288,
    "ADS_RIGHT_SYNCHRONIZE" : 1048576,
    "ADS_RIGHT_ACCESS_SYSTEM_SECURITY" : 16777216,
    "ADS_RIGHT_GENERIC_ALL" : 268435456,
    "ADS_RIGHT_GENERIC_EXECUTE" : 536870912,
    "ADS_RIGHT_GENERIC_WRITE" : 1073741824,
    "ADS_RIGHT_GENERIC_READ" : 2147483648
}

common_sids = {
    "DOMAIN_ADMINS": 512,
    "DOMAIN_USERS" : 513,
    "DOMAIN_GUESTS": 514,
    "DOMAIN_COMPUTERS" : 515,
    "AUTHENTICATED_USERS" : "S-1-5-11",
    "ENTERPRISE_ADMINS" : 519,
    "DOMAIN_DOMAIN_CONTROLLERS" : 516,
    "ADMINISTRATOR" : 500,
    "ENTERPRISE_DOMAIN_CONTROLLERS" : "S-1-5-9"
}

default_cert_templates = ["Administrator","Authenticated Session","Basic EFS","CA Exchange","CEP Encryption","Code Signing",
                          "Cross Certification Authority","Directory Email Replication","Domain Controller","Domain Controller Authentication",
                          "EFS Recovery Agent","EFS Recovery Agent","Enrollment Agency","Enrollment Agent (Computer)","Exchange Enrollment Agent (Offline Request)",
                          "Exchange Signature Only","Exchange User","IPSec","IPSec (Offline request)","Kerberos Authentication","Key Recovery Agent",
                          "OCSP Response Signing","RAS and IAS Server","Root Certification Authority","Router (Offline request)","Smartcard Logon",
                          "Smartcard User","Subordinate Certification Authority","Trust List Signing","User Signature Only","Web Server","Workstation Authentication"]