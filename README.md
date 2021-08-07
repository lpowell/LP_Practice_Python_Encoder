# LP_Practice_Python_Encoder

Practice python code, trying out some new things. Encodes text files to base64, rot13, and generates and encrypts with pgp. 


Method of use: 

python3 Practice_Encoder.py -[e,d] -[u,c,m] -[i,o,k] -[b,r,p,n] 

-e Encode 

-d Decode 

-b base64 

-r rot13 

-p pgp 

-i [input file] 

-o [output file] 

-k [key file] 

    opens both private and public keys.
  
-n New pgp keys 

    New pgp keys are output to the directory the program is in and do not allow for password protection or expiration. 
  
-u UserID for new PGP key

-c Comment line for new PGP key

-m Mail for new PGP key

-h help
