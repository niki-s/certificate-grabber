import ssl
# for whatever reason cryptography doesn't exist for python3??? Or I'm bad at looking
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sys

def main():
	# open the file listed in the command line
	if len(sys.argv) > 1:
		f = open(sys.argv[1], 'r')
	else:
		print "No input file specified: cert-grab.py <input ip file>"
		return

	# make a list to store (ip,port) pairs in
	iplist = []
	for line in f:
		line = line.rstrip("\n")
		print line
		iplist.append(line.split(" "))

	f.close()
	# fetch and decode certificates
	for ip in iplist:
		try:
			cert = ssl.get_server_certificate((ip[0], int(ip[1])))
			cert_txt = x509.load_pem_x509_certificate(cert.encode('ascii','ignore'), default_backend())
			print type(cert_txt)
			ip.append(cert_txt)
		except:
			ip.append("no cert or error")

	# save certificate info in a csv
	for ip in iplist:
		print
		print "cert found for", ip[0], "is:", ip[2]
		if ip[2] != "no cert or error":
			version = ip[2].version
			fingerprint = ip[2].fingerprint
			serial = ip[2].serial_number
			publicKey = ip[2].public_key()
			notValidBefore = ip[2].not_valid_before
			notValidAfter = ip[2].not_valid_after
			issuer = ip[2].issuer
			subject = ip[2].subject
			hashAlg = ip[2].signature_hash_algorithm
			#sigBytes = ip[2].signature
			#bytes = ip[2].tbs_certificate_bytes
			
			#there has to be a better way to do this...but the certificate isn't iterable...
			c = str(version)+','+str(fingerprint)+','+str(serial)+','+str(publicKey)+','+\
				str(notValidBefore)+','+str(notValidAfter)+','+str(issuer)+','+str(subject)+','+\
				str(hashAlg)
		else:
			c = "no cert or error"

		f = open(ip[0]+"_cert.txt", 'w')
		f.write(c)
		f.close()

if __name__ == "__main__":
	main()
	
