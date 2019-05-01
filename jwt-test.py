import base64
import hmac
import hashlib 
import binascii

header	='{"alg":"HS256","typ":"JWT"}'
payload = '{"user":"jamesshieh1111","password":"1234567"}'
key 	= "fji234j;raewr823423"
#convert utf-8 string to byte format
def toBytes(string):
	return bytes(string,'utf-8')

def encodeBase64(text):
	#remove "=" sign, 
	#P.S. "=" sign is used only as a complement in the final process of encoding a message. 
	return base64.urlsafe_b64encode(text).replace(b'=',b'')

#signature = HMAC-SHA256(key, unsignedToken)
def create_sha256_signature(key, unsignedToken):
	signature = hmac.new(toBytes(key), unsignedToken, hashlib.sha256).digest()
	return encodeBase64(signature)

unsignedToken 	=encodeBase64(toBytes(header)) + toBytes('.') + encodeBase64(toBytes(payload))
#unsignedToken	=toBytes(unsignedToken.decode("utf-8").replace("=",''))
signature 		=create_sha256_signature(key,unsignedToken)


jwt_toekn=unsignedToken.decode("utf-8") +'.'+signature.decode("utf-8")
print(jwt_toekn)

