import ssl
# for whatever reason cryptography doesn't exist for python3??? Or I'm bad at looking
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
		iplist.append(line.split(":"))

	f.close()
	# fetch and decode certificates
	for ip in iplist:
		try:
			cert = ssl.get_server_certificate((ip[0], int(ip[1])))
			cert_txt = x509.load_pem_x509_certificate(cert.encode('ascii','ignore'), default_backend())
			#print type(cert_txt)
			ip.append(cert_txt)
		except:
			ip.append("no cert or error")

	# save certificate info in a csv
	erroredIps = []
	f = open("results_certs_grab.csv", 'w')

	# insert labels for all the columns as the first entry
	c = "ip:port, version, serial number, public key length, not valid before, not valid after, issuer country name,\
issuer organization name, issuer common name, subject country name, subject state or province, \
subject locality name, subject organization name, subject common name, hash algorithm \n"
	f.write(c)

	for ip in iplist:
		# create a string c of all the important elements in the cert (or at least most of them)
		# currently unneeded additions are commented out
		if ip[2] != "no cert or error":
			c = str(ip[0])
			c = c  + ',' + str(ip[1])
			c = c  + ',' + str(ip[2].version)
			c = c  + ',' + str(ip[2].serial_number)
			c = c  + ',' + str(ip[2].public_key().key_size)
			c = c  + ',' + str(ip[2].not_valid_before)
			c = c  + ',' + str(ip[2].not_valid_after)
			for attribute in ip[2].issuer: 
				#countryName, organizationName, commonName
				c = c  + ',' + str(attribute.value)
			for attribute in ip[2].subject:
				#countryName, stateOrProvinceName, localityName, organizationName, commonName
				c = c  + ',' + str(attribute.value)

			c = c  + ',' + str(ip[2].signature_hash_algorithm.name)
			c = c + '\n'
			#fingerprint = ip[2].fingerprint(hashes.SHA256())
			#sigBytes = ip[2].signature
			#bytes = ip[2].tbs_certificate_bytes

			f.write(c)

		else:
			# if there is an error, skip adding it to the csv but save in a list to print at the end of the program
			erroredIps.append((ip[0], ip[1]))

	
	f.close()

	if len(erroredIps) > 0:
		print "unable to aquire certs for some IPs:"
		for item in erroredIps:
			print item

if __name__ == "__main__":
	main()
	
