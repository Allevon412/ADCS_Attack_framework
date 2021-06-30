# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Config utilities
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Configuration class which holds the config specified on the
# command line, this can be passed to the tools' servers and clients

from impacket.examples.utils import parse_credentials


class NTLMRelayxConfig:
    def __init__(self):

        self.daemon = True

        # Set the value of the interface ip address
        self.interfaceIp = None

        self.listeningPort = None

        self.domainIp = None
        self.runSocks = False
        self.machineAccount = None
        self.machineHashes = None
        self.target = None
        self.mode = None
        self.attacks = None
        self.encoding = None
        self.remove_mic = False
        self.encoding = None

        self.outputFile = None
        self.SMBServerChallenge = None
        self.ipv6 = False

        self.smb2support = None

        self.protocolClients = None

        # HTTP options
        self.remove_target = False


        # AD CS attack options
        self.isADCSAttack = False
        self.template = None
        self.ADCSUser = None
        self.ADCSPass = None
        self.ADCSDomain = None
        self.ADCSListener = None
        self.ADCSTarget = None
        self.ADCSNTLMHash= None
        #to run dementor in another thread after all servers have started.
        self.isDementorAttack = False
        self.escalate = False
        self.target_user = "Administrator"
        self.target_cert_name = None

    def setSMB2Support(self, value):
        self.smb2support = value

    def setProtocolClients(self, clients):
        self.protocolClients = clients

    def setListeningPort(self, port):
        self.listeningPort = port

    def setTargets(self, target):
        self.target = target

    def setMode(self, mode):
        self.mode = mode

    def setADCSOptions(self, template):
        self.template = template

    def setIsADCSAttack(self, isADCSAttack):
        self.isADCSAttack = isADCSAttack

    def setIsDementorAttack(self, isDementorAttack):
        self.isDementorAttack = isDementorAttack

    def setEscalation(self, escalate):
        self.escalate = escalate

    def setTargetUser(self, target_user):
        self.target_user = target_user

    def setADCSUser(self, user):
        self.ADCSUser = user

    def setADCSPass(self, password):
        self.ADCSPass = password

    def setADCSDomain(self, domain):
        self.ADCSDomain = domain

    def setADCSListener(self, listener):
        self.ADCSListener = listener

    def setADCSTargetDC(self, targetDC):
        self.ADCSTarget = targetDC

    def setADCSNTLMHash(self, NTLMHash):
        self.ADCSNTLMHash = NTLMHash

    def setInterfaceIP(self, IP):
        self.interfaceIp = IP

    def setAttacks(self, attacks):
        self.attacks = attacks

    def setDomainAccount(self, machineAccount, machineHashes, domainIp):
        # Don't set this if we're not exploiting it
        if not self.remove_target:
            return
        if machineAccount is None or machineHashes is None or domainIp is None:
            raise Exception("You must specify machine-account/hashes/domain all together!")
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

    def setIPv6(self, use_ipv6):
        self.ipv6 = use_ipv6

    def setExploitOptions(self, remove_mic, remove_target):
        self.remove_mic = remove_mic
        self.remove_target = remove_target

    def setEncoding(self, encoding):
        self.encoding = encoding

    def setTargetCertName(self, target_cert):
        self.target_cert_name = target_cert



