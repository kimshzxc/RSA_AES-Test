from Crypto.PublicKey import RSA

rsa = RSA.generate(2048)
private_pem = rsa.exportKey(format='PEM', passphrase='password')

with open('private.pem', 'wb') as f:
    f.write(private_pem)

public_pem = rsa.publickey().exportKey(format='PEM')

with open('public.pem', 'wb') as f:
   f.write(public_pem)
