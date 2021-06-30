from ldap3 import Connection, Server, ALL, NTLM
from ldap3.protocol.microsoft import security_descriptor_control

from mappings import ACE_ACCESS_BITS, common_sids

from impacket.ldap import ldaptypes


def get_sid(sid):
    #special case for sids like s-1-5-9
    if not isinstance(sid[-3:], int):
        for k,v in common_sids.items():
            if v == sid:
                return k
    for k, v in common_sids.items():
        if int(sid[-3:]) == v or sid == v:
            return (k)
    return sid

def get_ldap_connection(target,user,password,protocol, domain):
    server = Server('%s://%s' % (protocol, target), get_info=ALL)
    connection = Connection(server=server, user=domain+"\\"+user, password=password, authentication=NTLM)
    connection.bind()
    return connection

def perform_query(connection, base, filter, attributes, controls):
    response = connection.extend.standard.paged_search(search_base=base, search_filter=filter, attributes=attributes,
                            paged_size=1000, controls=security_descriptor_control(sdflags=controls), generator=True)
    return response

def parse_acl(response, client_certs):
    for e in response:
        try:
            if e['type'] != 'searchResEntry':
                continue
            for k,v in e.items():
                if k == 'raw_attributes':
                    for cert in client_certs:
                        name = cert.get_name()
                        if name == v['displayName'][0].decode('ascii'):
                            for item in v['ntSecurityDescriptor']:
                                sd = item
                                secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
                                secDesc.fromString(sd)
                                count = 0
                                for ace in secDesc['Dacl']['Data']:
                                    group = get_sid(secDesc['Dacl']['Data'][count]['Ace']['Sid'].formatCanonical())
                                    if group == "AUTHENTICATED_USERS" or group == "DOMAIN_USERS" or group == cert.get_current_user_sid():
                                        for k2, v2 in ACE_ACCESS_BITS.items():
                                            mask = secDesc['Dacl']['Data'][count]['Ace']['Mask']['Mask']
                                            if mask & v2 > 1:
                                                cert.set_group_access_rights(group,k2)
                                        count += 1
                                    else:
                                        count += 1
                        else:
                            continue
        except Exception as e:
            print("[!] Execpetion %s" % str(e))
            continue


def parse_ca_acl(response, cas):
    for e in response:
        try:
            if e['type'] != 'searchResEntry':
                continue
            for k,v in e.items():
                if k == 'raw_attributes':
                    for ca in cas:
                        if str(ca.get_name()) == str(v['dnshostname'][0].decode('ascii')):
                            for item in v['ntSecurityDescriptor']:
                                sd = item
                                secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
                                secDesc.fromString(sd)
                                count = 0
                                for ace in secDesc['Dacl']['Data']:
                                    group = get_sid(secDesc['Dacl']['Data'][count]['Ace']['Sid'].formatCanonical())
                                    if group == "AUTHENTICATED_USERS" or group == "DOMAIN_USERS" or group == ca.get_current_user_sid():
                                        for k2, v2 in ACE_ACCESS_BITS.items():
                                            mask = secDesc['Dacl']['Data'][count]['Ace']['Mask']['Mask']
                                            if mask & v2 > 1:
                                                ca.set_group_access_rights(group,k2)
                                        count += 1
                                    else:
                                        count += 1
                        else:
                            continue
        except Exception as e:
            print("[!] Execpetion %s" % str(e))
            continue
    #http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm super helpful resource for AD security descriptors
    #https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab resource for SIDS
    #http://www.kouti.com/tables/userattributes.htm user attrbiute tables for ldap
