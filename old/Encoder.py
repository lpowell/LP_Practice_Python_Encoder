# Encode or encrypt files in base64, rot13, or pgp
# lol could've .encode("base64")
import base64
import sys, getopt
import codecs
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import pgpy
from datetime import timedelta


# list of args

# it reads both the - and the option [1:]
# argv  0 is the name of the python file, first arg after the python com
arguments=sys.argv[1:]

# options
options ="hedbrpi::o::n:v:k:u::c::m::"
# help, encode, decode, base64, rot13, pgp, inputfile, outputfile, keyfile

encode=False
decode=False
base = False
rot = False
pgp = False
GenKey=False
# could probably just cut out errs

try:
	#parse arguments
	ArgV, Values = getopt.getopt(arguments, options)

	# check args
	for CurrentARG, CurrentVAL in ArgV:

		if CurrentARG in ('-h'):
			print("Encoder.py \
				\n Encodes and decodes files into base64, rot13, and pgp. \
				\n Author: Liam Powell \
				\n -e Encode \
				\n -d Decode \
				\n -b base64 \
				\n -r rot13 \
				\n -p pgp \
				\n -i [input file] \
				\n -o [output file] \
				\n -k [key file] (public)\
				\n -n [key file] New key file\
				\n -u UserID for new PGP key\
				\n -c Comment line for new PGP key\
				\n -m Mail for new PGP key\
				\n -h help")
			sys.exit()

		elif CurrentARG in ("-i"):
			encode_file = open(CurrentVAL)
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-o"):
			output_file = open(CurrentVAL, "w")
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-e"):
			encode=True
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-d"):
			decode = True
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-b"):
			base = True
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-r"):
			rot = True	
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-p"):
			pgp = True
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-n"):
			GenKey = True
			key_file=open(CurrentVAL, "w")
			print(CurrentARG, CurrentVAL)
		elif CurrentARG in ("-v"):
			GenKey - True
			pubkey_file=open(CurrentVAL, "w")
			print(CurrentARG, CurrentVAL)
		elif CurrentARG in ("-k"):
			key_file=open(CurrentVAL)
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-u"):
			userid = CurrentVAL
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-c"):
			pgpcomment = CurrentVAL
			print(CurrentARG, CurrentVAL)

		elif CurrentARG in ("-m"):
			mail = CurrentVAL
			print(CurrentARG, CurrentVAL)
	if (base):
		# B64 encoding 
		if (encode):
			#check if encoding

			while(encode_file):
			# while the file is not EoF

				for line in encode_file:
				# For each line in file

					encode_line = base64.b64encode(line.encode('utf-8'))
					# convert the lines into a bytes object

					output_file.write(encode_line.decode(encoding='UTF-8',errors='strict'))
					# decode the converted and encoded line into a str object

				sys.exit()
				# exit when done

		# B64 Decoding
		elif (decode):
		# Check if decoding

			while(encode_file):
			# While file is not Eof

				for line in encode_file:
				# for each line in the file

					decode_line = base64.b64decode(line.encode('utf-8'))
					# convert the lines to bytes to decode

					output_file.write(decode_line.decode(encoding='UTF-8',errors='strict'))
					# convert decoded bytes obj back to string type and write to file

				sys.exit()
				# exit when done
	if (rot):
		if (encode):
			while (encode_file):
				for line in encode_file:
					encode_line = codecs.encode(line,"rot-13")
					output_file.write(encode_line)
				sys.exit()
		elif(decode):
			while (encode_file):
				for line in encode_file:
					decode_line = codecs.decode(line,"rot-13")
					output_file.write(decode_line)
				sys.exit()
	if(pgp):
		if(GenKey):
			key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
			uid = pgpy.PGPUID.new(userid, comment=pgpcomment, email=mail)
			key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
			subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
			key.add_subkey(subkey, usage={KeyFlags.Authentication})
			keystr = str(key)
			pubkeystr = str(key.pubkey)

			pubkey_file.write(pubkeystr)
			key_file.write(keystr)
			sys.exit()
			# keygen works, decrypt does not
		if(encode):
			strkfile=""
			for line in key_file:
				strkfile += line
			key, _ = pgpy.PGPKey.from_blob(strkfile)
			file_message = pgpy.PGPMessage.new(encode_file.name, file=True)
			# file_message |= sec.sign(file_message)
			# pub.verify(file_message)
			encrypted_file_message = key.encrypt(file_message)
			msgstr = str(encrypted_file_message)
			output_file.write(msgstr)
			sys.exit()
			#encrypt appears to work
			# NOT ENCRYPTING MESSAGE, ENCRYPTING IOWRAPPER 
			# Fixed, encode_file.name
		if(decode):
			# Decrypt not working, decrypting to further pgp encryption. File is translated
			# correctly, but is still encrypted.
			strkfile=""
			for line in key_file:
				strkfile += line
			key, _ = pgpy.PGPKey.from_blob(strkfile)
			message = pgpy.PGPMessage.from_file(encode_file.name)
			# this is going through correctly
			
			decrypted_message = key.decrypt(message)
			# this is not
			
			print(decrypted_message)
			msgstr = str(decrypted_message)
			output_file.write(msgstr)
			sys.exit()
except getopt.GetoptError:
	print("Encoder.py \
		\n Encodes and decodes files into base64, rot13, and pgp. \
		\n Author: Liam Powell \
		\n -e Encode \
		\n -d Decode \
		\n -b base64 \
		\n -r rot13 \
		\n -p pgp \
		\n -i [input file] \
		\n -o [output file] \
		\n -k [key file] (pgp only)\
		\n -h help")
	sys.exit(2)

# PGP

# output
