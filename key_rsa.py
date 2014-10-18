from Crypto.PublicKey import RSA
from Crypto import Random

rand_new = Random.new().read
RSAkey = RSA.generate(1024, rand_new) 

privatekey = RSAkey
publickey = RSAkey.publickey()
print(privatekey.exportKey()) #export under the 'PEM' format (I think)
print(publickey.exportKey())
