class certificate_authority():
    def __init__(self):
        self.flags = []
        self.EKUS = []
        self.name = ""
        self.sig_required = True
        self.is_vulnerable = False
        self.name_flags = []
        self.escalations = []
        self.current_user_sid = ""

        self.ad_groups = {
            "AUTHENTICATED_USERS" : [],
            "DOMAIN_USERS" : [],
            "CURRENT_USER" : []
        }
        self.can_enroll = False
        self.canUserEnroll = False
        self.userCanWriteOverCert = False
        self.can_write_over_cert = False
        self.can_supply_subject = False

    def set_flags(self, flag):
        self.flags.append(flag)

    def set_EKUS(self, eku):
        self.EKUS.append(eku)

    def set_name(self, name):
        self.name = name

    def set_sig_required(self, sig_required):
        self.sig_required = sig_required

    def set_name_flags(self, flag):
        self.name_flags.append(flag)

    def set_group_access_rights(self, group, right):
        if group != "AUTHENTICATED_USERS" and group != "DOMAIN_USERS":
            self.ad_groups['CURRENT_USER'].append(right)
        self.ad_groups[group].append(right)

    def set_enrollment(self, group):
        if group != "AUTHENTICATED_USERS" or group != "DOMAIN_USERS":
            if "ADS_RIGHT_DS_CONTROL_ACCESS" in self.ad_groups["CURRENT_USER"]:
                self.canUserEnroll = True
        if "ADS_RIGHT_DS_CONTROL_ACCESS" in self.ad_groups[group]:
            self.can_enroll = True

    def set_writability(self, group):
        if group != "AUTHENTICATED_USERS" or group != "DOMAIN_USERS":
            if "ADS_RIGHT_WRITE_DAC" in self.ad_groups["CURRENT_USER"] and "ADS_RIGHT_DS_WRITE_PROP" in \
                    self.ad_groups["CURRENT_USER"] \
                    and "ADS_RIGHT_WRITE_OWNER" in self.ad_groups["CURRENT_USER"]:
                self.userCanWriteOverCert = True
        if "ADS_RIGHT_WRITE_DAC" in self.ad_groups[group] and "ADS_RIGHT_DS_WRITE_PROP" in self.ad_groups[group] \
                and "ADS_RIGHT_WRITE_OWNER" in self.ad_groups[group]:
            self.can_write_over_cert = True

    def set_can_write_subjectname(self):
        if "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in self.name_flags:
            self.can_supply_subject = True

    def set_current_user_sid(self, sid):
        self.current_user_sid = sid

    def get_name(self):
        return self.name

    def get_current_user_sid(self):
        return self.current_user_sid

class client_certificate():
    def __init__(self):
        self.flags = []
        self.EKUS = []
        self.name = ""
        self.sig_required = True
        self.is_vulnerable = False
        self.name_flags = []
        self.escalations = []
        self.current_user_sid = ""

        self.ad_groups = {
            "AUTHENTICATED_USERS" : [],
            "DOMAIN_USERS" : [],
            "CURRENT_USER" : []
        }
        self.can_enroll = False
        self.canUserEnroll = False
        self.userCanWriteOverCert = False
        self.can_write_over_cert = False
        self.can_supply_subject = False

    def set_flags(self, flag):
        self.flags.append(flag)

    def set_EKUS(self, eku):
        self.EKUS.append(eku)

    def set_name(self, name):
        self.name = name

    def set_sig_required(self, sig_required):
        self.sig_required = sig_required

    def set_name_flags(self, flag):
        self.name_flags.append(flag)

    def set_group_access_rights(self, group, right):
        if group != "AUTHENTICATED_USERS" and group != "DOMAIN_USERS":
            self.ad_groups['CURRENT_USER'].append(right)
        self.ad_groups[group].append(right)

    def set_enrollment(self, group):
        if group != "AUTHENTICATED_USERS" or group != "DOMAIN_USERS":
            if "ADS_RIGHT_DS_CONTROL_ACCESS" in self.ad_groups["CURRENT_USER"]:
                self.canUserEnroll = True
        if "ADS_RIGHT_DS_CONTROL_ACCESS" in self.ad_groups[group]:
            self.can_enroll = True

    def set_writability(self, group):
        if group != "AUTHENTICATED_USERS" or group != "DOMAIN_USERS":
            if "ADS_RIGHT_WRITE_DAC" in self.ad_groups["CURRENT_USER"] and "ADS_RIGHT_DS_WRITE_PROP" in self.ad_groups["CURRENT_USER"] \
                    and "ADS_RIGHT_WRITE_OWNER" in self.ad_groups["CURRENT_USER"]:
                self.userCanWriteOverCert = True
        if "ADS_RIGHT_WRITE_DAC" in self.ad_groups[group] and "ADS_RIGHT_DS_WRITE_PROP" in self.ad_groups[group]\
            and "ADS_RIGHT_WRITE_OWNER" in self.ad_groups[group]:
            self.can_write_over_cert = True
    def set_can_write_subjectname(self):
        if "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in self.name_flags:
            self.can_supply_subject = True

    def set_current_user_sid(self, sid):
        self.current_user_sid = sid

    def get_current_user_sid(self):
        return self.current_user_sid

    def get_escalations(self):

        #ESC1 logic user can supply subject name of certificate.
        if self.sig_required == False and "CT_FLAG_PEND_ALL_REQUESTS" not in self.flags and \
                (self.can_enroll or self.canUserEnroll):
            if "Client Authentication" in self.EKUS or "Smart Card Logon" in self.EKUS:
                if self.can_supply_subject:
                    if self.can_enroll and self.canUserEnroll:
                        self.escalations.append("ESC1, DOMAIN USERS & CURRENT USER")
                    elif self.can_enroll and not self.canUserEnroll:
                        self.escalations.append("ESC1 DOMAIN USERS")
                    elif not self.can_enroll and self.canUserEnroll:
                        self.escalations.append("ESC1 CURRENT USER")

        ##ESC2 logic. user can enlist a cert for any purpose.
        if self.sig_required == False and "CT_FLAG_PEND_ALL_REQUESTS" not in self.flags and\
                (self.can_enroll or self.canUserEnroll):
            if "Any Purpose" in self.EKUS or not self.EKUS:
                if not self.EKUS:
                    escalation_string = "ESC2 no EKU listed "
                else:
                    escalation_string = "ESC2 ANY Purpose "
                if self.can_enroll and not self.canUserEnroll:
                    self.escalations.append(escalation_string + "DOMAIN USERS")
                elif not self.can_enroll and self.canUserEnroll:
                    self.escalations.append(escalation_string + "CURRENT USER")
                elif self.can_enroll and self.canUserEnroll:
                    self.escalations.append(escalation_string + "DOMAIN USERS & CURRENT USER")

        #esc3 logic user can request cert on behave of others. Certificate Request Agent
        if self.sig_required == False and "CT_FLAG_PEND_ALL_REQUESTS" not in self.flags and \
                (self.can_enroll or self.canUserEnroll):
            if "Certificate Request Agent" in self.EKUS:
                if self.can_enroll and self.canUserEnroll:
                    self.escalations.append("ESC3 DOMAIN USERS & CURRENT USER")
                elif self.can_enroll and not self.canUserEnroll:
                    self.escalations.append("ESC3 DOMAIN USERS")
                elif not self.can_enroll and self.canUserEnroll:
                    self.escalations.append("ESC3 CURRENT USER")

        #ESC 4 LOGIC user can overwrite certificate template properites to give our selves enroll or whatever.
        if self.can_write_over_cert == True or self.userCanWriteOverCert == True:
            if self.can_write_over_cert and not self.userCanWriteOverCert:
                self.escalations.append("ESC4 DOMAIN USERS")
            elif self.can_write_over_cert and self.userCanWriteOverCert:
                self.escalations.append("ESC4 DOMAIN USERS & CURRENT USER")
            elif not self.can_write_over_cert and self.userCanWriteOverCert:
                self.escalations.append("ESC4 CURRENT USER")

        # for escalation 5 the CA server needs to be writable by the attacker. Seems more like an exploit needs to exist
        # or an ad object we have access to needs to be able to control the CA computer object. Will skip this one for now.
        #if - need to do access controls for CA + figure out the EDITF_AttributesSUBJECTALNAME2 thing. for esc6 + esc7
        #if self. -- put EKU for certificate request Agent EKU in here.
        # TODO: need to implement ESC3-8, need to figure out a way to get the Supply in request for Subject name property for a cert.
        # TODO: put an explanation on how ESC2 is actually used to implement a weird attack path that's not immediately useful for DA path.
        #if self.sig_required == False and "CT_FLAG_PEND_ALL_REQUESTS" not in self.flags:
        #   if

    def get_vulnerability(self):
        return self.is_vulnerable

    def print_info(self):
        print("[*] cert_temp_name: {0}".format(self.name))
        print("[*] cert_ekus: ")
        for eku in self.EKUS:
            print("[>] {0}".format(eku))
        print("[*] requires signature: {0}".format(str(self.sig_required)))
        for sub_flag in self.name_flags:
            print("[*] Subject Alt Name Flags {0}".format(sub_flag))
        print("[*] AD Groups & Permissions:")
        for k,v in self.ad_groups.items():
            print("[>] Group %s" % k)
            for perm in v:
                print("[!] %s" % perm)

    def get_name(self):
        return self.name