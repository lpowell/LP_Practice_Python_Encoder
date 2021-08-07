# Commented version
# Liam Powell

# Import libs
import base64, sys, getopt, codecs, pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

# Function to recieve the command line operators
def getfunc():

	# define the arguments
	arguments=sys.argv[1:]

	# accepted options
	options="hedbrpi::o::nk:u::c::m::"
	
	# Test the options
	try:

		# ArgV grabs the option as Current Argument, and stores the value of the argument as Current Value
		ArgV, Values=getopt.getopt(arguments, options)
		for CurrentARG, CurrentVAL in ArgV:

			# Parses the current argument
			if CurrentARG in ('-h'):
				print("Encoder.py \
					\n Encodes and decodes files into base64, rot13, and pgp. \
					\n Author: Liam Powell \
					\n Method of use: \
					\n python3 Practice_Encoder.py -[e,d] -[u,c,m] -[i,o,k] -[b,r,p,n] \
					\n -e Encode \
					\n -d Decode \
					\n -b base64 \
					\n -r rot13 \
					\n -p pgp \
					\n -i [input file] \
					\n -o [output file] \
					\n -k [key file] \
					\n -n New pgp keys \
					\n -u UserID for new PGP key\
					\n -c Comment line for new PGP key\
					\n -m Mail for new PGP key\
					\n -h help")
				sys.exit()
			
			elif CurrentARG in ("-i"):
				
				# Open the input file
				input_file = open(CurrentVAL)
			
			elif CurrentARG in ("-o"):
			
				# Open the output file
				output_file = open(CurrentVAL, 'w')
			
			elif CurrentARG in ("-e"):
				encode = True
			
			elif CurrentARG in ("-d"):
				encode = False
			
			elif CurrentARG in ("-k"):
			
				# Open the pgp key file
				key_file = open(CurrentVAL)
			
			elif CurrentARG in ("-u"):
				userid = CurrentVAL
			
			elif CurrentARG in ("-c"):
				comment = CurrentVAL
			
			elif CurrentARG in ("-m"):
				mail = CurrentVAL
			
			elif CurrentARG in ("-b"):
			
				# Pass the arguments to the base64 function
				Base_64(encode, input_file, output_file)
			
			elif CurrentARG in ("-r"):
			
				# Pass the arguments to the Rot_13 function
				Rot_13(encode, input_file, output_file)
			
			elif CurrentARG in ("-p"):
			
				# Pass the arguments to the pgp encryption function
				pgp_en(encode, input_file, output_file, key_file)
			
			elif CurrentARG in ("-n"):
			
				# Pass the arguments to the pgp generation function
				pgp_gen(userid, comment, mail)
	
	# on error print command for help
	except getopt.GetoptError:
		print("Encoder.py \
			\n Type \"python3 Practice_Encoder.py -h\" for help")
	sys.exit()

# Base64 function. 
# Requires an encode T/F, input file, and output file
def Base_64(encode, input_file, output_file):

	# Encryption function
	if(encode):

		# While the input file is not EoF
		while (input_file):

			# transfer lines to encode_line
			for line in input_file:

				# Convert the string type lines to bytes for the base64 encode function to work
				encode_line = codecs.encode(line.encode('utf-8'),'base64')

				# decode the bytes object backto string to write to the output file
				output_file.write(encode_line.decode(encoding='UTF-8'))
			sys.exit()

	# Decryption function
	else:

		# While input file is not EoF
		while(input_file):

			# transfer lines to decode_line
			for line in input_file:

				# Convert string to bytes to decode 
				decode_line = codecs.decode(line.encode('utf-8'),'base64')

				# Convert back to string to output
				output_file.write(decode_line.decode(encoding='UTF-8'))
			sys.exit()

# Rot 13 function
def Rot_13(encode, input_file, output_file):

	# Encryption function
	if(encode):

		# Parse file
		while (input_file):
			for line in input_file:

				# encode line as rot 13
				encode_line = codecs.encode(line,'rot-13')

				# write encoded line to file
				output_file.write(encode_line)
			sys.exit()

	# Decrypt function
	else:

		# Parse file
		while(input_file):
			for line in input_file:
				
				# Decode rot 13 text
				decode_line = codecs.decode(line,'rot-13')

				# Write decoded line to file
				output_file.write(decode_line)
			sys.exit()

# Function to generate pgp keys
# Requires a user id, comment, and mail field.
# Creates a private key and public key
def pgp_gen(userid, pgpcomment, mail, priv_key_file='priv_key_file.acs', pub_key_file='pub_key_file.gpg'):

	# Create the key
	key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

	# Create the user id information
	uid = pgpy.PGPUID.new(userid, comment=pgpcomment, email=mail)

	# Add the user id info to the key and generate the encryption for the key
	key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
	
	# Create the public key
	subkey = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

	# add the public key to the private key
	key.add_subkey(subkey, usage={KeyFlags.Authentication})

	# turn the private key into a string 
	keystr = str(key)

	# turn the public key into a string
	pubkeystr = str(key.pubkey)

	# Write the keys to file
	tmp_file = open(pub_key_file, 'w')
	tmp_file.write(pubkeystr)
	tmp_file.close()
	tmp_file = open(priv_key_file, 'w')
	tmp_file.write(keystr)
	tmp_file.close()
	sys.exit()

# Function to encrypt or decrypt pgp files
# Requires an encyrpt T/F, input file, output file, key file
def pgp_en(encrypt, input_file, output_file, key_file):

	# encrypt function
	if(encrypt):

		# open the pgp public key
		key, _ = pgpy.PGPKey.from_file(key_file.name)

		# open the message to encrypt
		file_message = pgpy.PGPMessage.new(input_file.name, file=True)

		# Encrypt the message
		encrypted_file_message = key.encrypt(file_message)

		# write the encrypted message to the output file
		output_file.write(str(encrypted_file_message))
		sys.exit()


	# Decrypt function
	else:

		# open the private key
		key, _ = pgpy.PGPKey.from_file(key_file.name)

		# open the encrypted message
		encrypted_message = pgpy.PGPMessage.from_file(input_file.name)

		# decrypt the message
		decrypted_message = key.decrypt(encrypted_message)

		# convert the decoded message into a string
		str_decrypted_message = decrypted_message.message

		# write the decoded message to the output file
		output_file.write(str_decrypted_message)
		sys.exit()

# parse command line options
getfunc()
