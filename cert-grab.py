import ssl
# for whatever reason cryptography doesn't exist for python3??? Or I'm bad at looking
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys


# open the file listed in the command line
if len(sys.argv) > 1:
	file = open(sys.argv[1], 'r')
else:
	print "No input file specified: cert-grab.py <input ip file>"

# make a list to store (ip,port) pairs in
iplist = []
for line in file:
	line = line.rstrip("\n")
	print line
	iplist.append(line.split(" "))

# fetch and decode certificates
for ip in iplist:
	try:
		cert = ssl.get_server_certificate((ip[0], int(ip[1])))
		cert_txt = x509.load_pem_x509_certificate(cert.encode('ascii','ignore'), default_backend())
		print type(cert_txt)
		ip.append(cert_txt)
	except:
		ip.append("no cert or error")

print iplist
