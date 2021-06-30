import logging

from impacket.ldap.ldap import *
from impacket.ldap import ldapasn1, ldaptypes

from get_acls import get_ldap_connection, parse_acl, perform_query, parse_ca_acl

from classes import client_certificate, certificate_authority
from mappings import EKUS, Enrollment_flags, certificate_name_flags, default_cert_templates

import sys


def get_current_user_sid(conn, base, user):
    result = perform_query(conn, base, "(&(objectClass=user)(sAMAccountName=" + user + "))", ["*"],
                           0x05)
    for e in result:
        if e['type'] != 'searchResEntry':
            continue
        for k, v in e.items():
            if k == 'raw_attributes':
                if v['objectSid']:
                    sid = v['objectSid'][0]
                    sid_ = ldaptypes.LDAP_SID()
                    sid_.fromString(sid)
                    return(sid_.formatCanonical())


def main(target, user, password, protocol, domain):

    client_certs = []
    CAS = []
    domain_items = domain.split('.')
    base = "DC="+domain_items[0].upper()+",DC="+domain_items[1].upper()
    conn = get_ldap_connection(target, user, password, protocol, domain)
    sid = get_current_user_sid(conn,base, user)

    vulnerable_cert_templates = []

    try:
        #get info about the CA
        ldap_con = LDAPConnection('ldap://%s' % target, baseDN="CN=Configuration,"+ base)
        ldap_con.login(user,password,domain)
        searchFilter = "(objectCategory=pKIEnrollmentService)"
        attributes=["dNSHostName", "certificateTemplates","aclEntry"]
        response = ldap_con.search(searchFilter=searchFilter)#, attributes=attributes)
        logging.info("Printing all CA's for the domain:")
        for item in response:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            for attribute in item['attributes']:
                if str(attribute['type']) == "dNSHostName":
                    ca = certificate_authority()
                    ca.set_name(attribute['vals'][0])
                    ca.set_current_user_sid(sid)
                    CAS.append(ca)
                    logging.info("CA: " + str(attribute['vals'][0]))


        logging.info("Enumerating:")
        searchFilter = "(objectClass=pKICertificateTemplate)"
        results = ldap_con.search(searchFilter=searchFilter)

        for item in results:
            #might need to change the client_cert creation position (might be creating a bunch of empty objcets b/c of the later check for the default cert names.
            client_cert = client_certificate()
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            for attribute in item['attributes']:
                if str(attribute['type']) == 'displayName':
                    if str(attribute['vals'][0]) in default_cert_templates:
                        continue
                    client_cert.set_name(str(attribute['vals'][0]))
                elif str(attribute['type']) == 'msPKI-RA-Signature':
                    if int(attribute['vals'][0]) == 0:
                        client_cert.set_sig_required(False)
                elif str(attribute['type']) == 'msPKI-Enrollment-Flag':
                    for enroll_flag, enroll_value in Enrollment_flags.items():
                        answer = int(attribute['vals'][0]) & enroll_value
                        if answer != 0:
                            client_cert.set_flags(enroll_flag)
                elif str(attribute['type']) == 'pKIExtendedKeyUsage':
                    for eku in attribute['vals']:
                        if str(eku) in EKUS:
                            client_cert.set_EKUS(EKUS[str(eku)])
                elif str(attribute['type']) == 'msPKI-Certificate-Name-Flag':
                    for cert_flag, cert_value in certificate_name_flags.items():
                        answer = int(attribute['vals'][0]) & cert_value
                        if answer != 0:
                            client_cert.set_name_flags(cert_flag)
            client_cert.set_current_user_sid(sid)
            client_certs.append(client_cert)

        base = "CN=Configuration,DC=BREADMAN,DC=LOCAL"
        ca_filter = "(objectCategory=pKIEnrollmentService)"
        ca_attributes = ["nTSecurityDescriptor", "dnshostname"]
        certs_filter = "(objectClass=pKICertificateTemplate)"
        certs_attributes = ["nTSecurityDescriptor", "displayName"]

        result = perform_query(conn, base, ca_filter, ca_attributes, 0x05)
        parse_ca_acl(result, CAS)

        result2 = perform_query(conn, base, certs_filter, certs_attributes, 0x05)
        parse_acl(result2, client_certs)

        #setting the vulnerability status's
        for cert in client_certs:
            cert.set_can_write_subjectname()
            cert.set_writability("DOMAIN_USERS")
            cert.set_enrollment("DOMAIN_USERS")

        logging.info("Printing vulnerable certificate Templates:")
        for cert in client_certs:
            cert.get_escalations()
            if cert.escalations:
                logging.info("Vulnerable Cert: {0}".format(cert.name))
                logging.info("Escalation Paths: {0}".format(cert.escalations))
                vulnerable_cert_templates.append(cert)

    except Exception as e:
        exception_type, exception_object, exception_traceback = sys.exc_info()
        filename = exception_traceback.tb_frame.f_code.co_filename
        line_number = exception_traceback.tb_lineno
        logging.error("Execpetion %s" % str(e))
        logging.error("Exception Type: ", exception_type)
        logging.error("File Name: ", filename)
        logging.error("Line number:", line_number)

    return vulnerable_cert_templates