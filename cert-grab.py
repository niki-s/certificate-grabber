import ssl
# for whatever reason cryptography doesn't exist for python3??? Or I'm bad at looking
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import sys

# find the list of possible nameOIDs here: https://cryptography.io/en/latest/x509/reference/#cryptography.x509.oid.NameOID
# for expansion
NameOIDList = [NameOID.COMMON_NAME, NameOID.COUNTRY_NAME, NameOID.STATE_OR_PROVINCE_NAME,
	NameOID.LOCALITY_NAME, NameOID.STREET_ADDRESS, NameOID.ORGANIZATION_NAME,
	NameOID.SERIAL_NUMBER]

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
			ip.append(cert_txt)
		except:
			ip.append("no cert or error")

	# save certificate info in a csv
	erroredIps = []
	f = open("results_certs_grab.csv", 'w')

	# insert labels for all the columns as the first entry
	c = "ip, port, version, serial number, public key length, not valid before, not valid after,\
	 issuer common name, issuer country name, issuer state or province, issuer locality,\
	 issuer street address, issuer organization name, issuer serial number,\
	 subject common name, subject country name, subject state or province, subject locality,\
	 subject street address, subject organization name, subject serial number,\
	 hash algorithm \n"
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

			# here comes a nice ty except of strangeness
			# it took way too long to come up with this, why is the response given as a list??
			for oid in NameOIDList:
				try:
					c = c  + ',' + str(ip[2].issuer.get_attributes_for_oid(oid)[0].value).replace(',', '')
				except:
					c = c  + ', '

			for oid in NameOIDList:
				try:
					c = c  + ',' + str(ip[2].subject.get_attributes_for_oid(oid)[0].value).replace(',', '')
				except:
					c = c  + ', '
			# print ip[2].issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
			# print ip[2].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			# try:
			# 	print ip[2].issuer.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
			# except:
			# 	print " "
			# print "-"

			
			# for attribute in ip[2].issuer: 
			# 	#countryName, organizationName, commonName
			# 	print str(attribute.oid)
			# 	c = c  + ',' + str(attribute.value)
			# for attribute in ip[2].subject:
			# 	#countryName, stateOrProvinceName, localityName, organizationName, commonName
			# 	c = c  + ',' + str(attribute.value)

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
	
