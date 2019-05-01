import base64
import hmac
import hashlib 
import binascii

header	='{"alg":"HS256","typ":"JWT"}'
payload = '{"loggedInAs":"admin","iat":1422779638}'
key 	= "secretkey"

#convert utf-8 string to byte format
def toBytes(string):
	return bytes(string,'utf-8')

def encodeBase64(text):
	return base64.urlsafe_b64encode(text)

#signature = HMAC-SHA256(key, unsignedToken)
def create_sha256_signature(key, unsignedToken):
	signature = hmac.new(toBytes(key), unsignedToken, hashlib.sha256).digest()
	return encodeBase64(signature)

unsignedToken 	=encodeBase64(toBytes(header)) + toBytes('.') + encodeBase64(toBytes(payload))
signature 		=create_sha256_signature(key,unsignedToken)

#remove "=" sign, 
#P.S. "=" sign is used only as a complement in the final process of encoding a message. 
jwt_toekn=unsignedToken.decode("utf-8") +'.'+signature.decode("utf-8").replace("=",'')
print(jwt_toekn)

