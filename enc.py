from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64


aes_key = b'Sixteen byte key'
iv = Random.new().read(AES.block_size)
cipher = AES.new(aes_key, AES.MODE_CBC,iv)
msg = '1234567890123456'
enc_msg = base64.b64encode(iv + cipher.encrypt(msg))

print enc_msg



public_key_file = open('public.pem', 'r')
private_key_file = open('private.pem', 'r')

public_key = RSA.importKey(public_key_file.read())
private_key = RSA.importKey(private_key_file.read(), passphrase='password')

#Test Text
plain_text = aes_key
print('Plain Text:', plain_text)

#Key Encryption Using RSA
random_func = Random.new().read
encrypted = public_key.encrypt(plain_text.encode('utf-8'), random_func)
print('Encrypted Text:', encrypted)

# Key Decryption Using RSA
decrypted = private_key.decrypt(encrypted)
print('Decrypted Text:', decrypted.decode('utf-8'))

#Sassert verified, 'Signature verification failed'
digest = SHA256.new()
digest.update(plain_text)

signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(digest)


verifier = PKCS1_v1_5.new(private_key.publickey())
verified = verifier.verify(digest, sig)

assert verified, 'Signature verification failed'
print 'Successfully verified message'


enc_msg = base64.b64decode(enc_msg.encode('utf-8'))
print enc_msg
d_iv = enc_msg[:16]
print d_iv
decryptor = AES.new(decrypted.decode('utf-8'),AES.MODE_CBC, d_iv)
print decryptor.decrypt(enc_msg[16:])

public_key_file.close()
private_key_file.close()
