# Cleaned version
# Liam Powell
import base64, sys, getopt, codecs, pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

def getfunc():
	arguments=sys.argv[1:]
	options="hedbrpi::o::nk:u::c::m::"
	try:
		ArgV, Values=getopt.getopt(arguments, options)
		for CurrentARG, CurrentVAL in ArgV:
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
				input_file = open(CurrentVAL)
			elif CurrentARG in ("-o"):
				output_file = open(CurrentVAL, 'w')
			elif CurrentARG in ("-e"):
				encode = True
			elif CurrentARG in ("-d"):
				encode = False
			elif CurrentARG in ("-k"):
				key_file = open(CurrentVAL)
			elif CurrentARG in ("-u"):
				userid = CurrentVAL
			elif CurrentARG in ("-c"):
				comment = CurrentVAL
			elif CurrentARG in ("-m"):
				mail = CurrentVAL
			elif CurrentARG in ("-b"):
				Base_64(encode, input_file, output_file)
			elif CurrentARG in ("-r"):
				Rot_13(encode, input_file, output_file)
			elif CurrentARG in ("-p"):
				pgp_en(encode, input_file, output_file, key_file)
			elif CurrentARG in ("-n"):
				pgp_gen(userid, comment, mail)
	except getopt.GetoptError:
		print("Encoder.py \
			\n Type \"python3 Practice_Encoder.py -h\" for help")
	sys.exit()
def Base_64(encode, input_file, output_file):
	if(encode):
		while (input_file):
			for line in input_file:
				encode_line = codecs.encode(line.encode('utf-8'),'base64')
				output_file.write(encode_line.decode(encoding='UTF-8'))
			sys.exit()
	else:
		while(input_file):
			for line in input_file:
				decode_line = codecs.decode(line.encode('utf-8'),'base64')
				output_file.write(decode_line.decode(encoding='UTF-8'))
			sys.exit()
def Rot_13(encode, input_file, output_file):
	if(encode):
		while (input_file):
			for line in input_file:
				encode_line = codecs.encode(line,'rot-13')
				output_file.write(encode_line)
			sys.exit()
	else:
		while(input_file):
			for line in input_file:
				decode_line = codecs.decode(line,'rot-13')
				output_file.write(decode_line)
			sys.exit()
def pgp_gen(userid, pgpcomment, mail, priv_key_file='priv_key_file.acs', pub_key_file='pub_key_file.gpg'):
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
	tmp_file = open(pub_key_file, 'w')
	tmp_file.write(pubkeystr)
	tmp_file.close()
	tmp_file = open(priv_key_file, 'w')
	tmp_file.write(keystr)
	tmp_file.close()
	sys.exit()
def pgp_en(encrypt, input_file, output_file, key_file):
	if(encrypt):
		key, _ = pgpy.PGPKey.from_file(key_file.name)
		file_message = pgpy.PGPMessage.new(input_file.name, file=True)
		encrypted_file_message = key.encrypt(file_message)
		output_file.write(str(encrypted_file_message))
		sys.exit()
	else:
		key, _ = pgpy.PGPKey.from_file(key_file.name)
		encrypted_message = pgpy.PGPMessage.from_file(input_file.name)
		decrypted_message = key.decrypt(encrypted_message)
		str_decrypted_message = decrypted_message.message
		output_file.write(str_decrypted_message)
		sys.exit()
getfunc()