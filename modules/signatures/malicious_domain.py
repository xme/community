#
# Cuckoo customer signature
# Purpose: Detect the resolution of a malicious domain name
#
# Author: Xavier Mertens <xavier@rootshell.be>
#
# To setup the malicious domain files, see:
# http://blog.rootshell.be/2012/07/27/cuckoo-increasing-the-power-of-malware-behavior-reporting-with-signatures/
# 


import fileinput
from lib.cuckoo.common.abstracts import Signature

# Load the list of malicious domains
domains = []
for domain in fileinput.input(['/data/cuckoo/conf/malicious-domains.txt']):
    domains.append(domain.rstrip())

class ResolveMaliciousDomain(Signature):
    name = "resolve_malicious_domain"
    description = "Try to resolve a malicious domain name"
    severity = 3
    category = ["generic"]
    authors = ["Xavier Mertens <xavier@rootshell.be>"]
 
    def run(self, results):
        for fqdn in results["network"]["dns"]:
            for d in domains:
                if fqdn["hostname"].find(d) >= 0:
                    return True

        return False
