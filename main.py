__author__ = 'stormacq'

from boto3.session import Session
from boto3.s3.transfer import S3Transfer
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import random, os, struct, base64

MASTER_KEY_ARN = 'arn:aws:kms:us-east-1:486652066693:key/44d25f19-fda9-48ed-88d8-4c8afd0e837b'
S3_BUCKET = 'public-sst'
DIRECTORY = '/Users/stormacq/Desktop'
FILENAME  = 'wifi.jpg'

def kmsKeyDemo():
    print("\nHello KMS Key Demo\n")

    #
    # Create a KMS Client object
    #
    session = Session(profile_name="default", region_name="us-east-1")
    kms = session.client('kms')

    #
    # Generate a Data Key (encoded with my Master Key in KMS)
    #
    key = kms.generate_data_key(KeyId=MASTER_KEY_ARN,KeySpec='AES_256')
    keyPlain  = key['Plaintext']
    keyCipher = key['CiphertextBlob']
    # print(key)

    #
    # Encode a plain text with the data key
    #
    obj = AES.new(keyPlain, AES.MODE_CBC, b'This is an IV123')
    msgPlain  = b'Hello world of cryptography w/managed keys'
    msgCipher = obj.encrypt(pad(msgPlain, 16))

    print ('Plain text key = %s' % base64.b64encode(keyPlain))
    print ('Plain text msg = %s' % msgPlain)
    print ('Cipher message = %s' % base64.b64encode(msgCipher))

    #
    # Now, we're supposed to trash the clear text key
    # and save the cipher version of the key
    #

    #
    # Later, we ask KMS to create a plain text version of the cipher key
    #
    key = kms.decrypt(CiphertextBlob=keyCipher)
    keyPlain = key['Plaintext']

    #
    # and we decrypt our cipher text
    #
    obj = AES.new(keyPlain, AES.MODE_CBC, b'This is an IV123')
    plainText = unpad(obj.decrypt(msgCipher), 16)

    print ('Plain text msg = %s' % plainText)

def kmsEncryptionDemo():

    print ("\nHello KMS Password encryption Demo\n")

    #
    # Create a KMS Client object
    #
    session = Session(profile_name="default", region_name="us-east-1")
    kms = session.client('kms')

    password = "this is my super secret password"
    print("Plaintext password  = %s" % password)

    #
    # Cipher a plain text object using your master key
    #
    ret = kms.encrypt(KeyId=MASTER_KEY_ARN,Plaintext=password)
    print ("Cipher password    = %s" % base64.b64encode(ret['CiphertextBlob']))

    #
    # Decrypt a ciphered text
    #
    ret = kms.decrypt(CiphertextBlob=ret['CiphertextBlob'])
    print (f"Plaintext password = {ret['Plaintext']}")


#file encryption code taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def S3KMSDemo():

    #
    # Create a KMS Client object
    #
    session = Session(profile_name="default", region_name="us-east-1")
    kms = session.client('kms')

    #
    # Generate a Data Key (encoded with my Master Key in KMS)
    #
    key = kms.generate_data_key(KeyId=MASTER_KEY_ARN,KeySpec='AES_256')
    keyPlain  = key['Plaintext']
    keyCipher = key['CiphertextBlob']

    #
    # Encode a file with the data key
    #
    print ("Initializing encryption engine")
    iv = Random.new().read(AES.block_size)
    chunksize = 64*1024
    encryptor = AES.new(keyPlain, AES.MODE_CBC, iv)

    print ("KMS Plain text key = %s " % base64.b64encode(keyPlain))
    print ("KMS Encrypted key  = %s " % base64.b64encode(keyCipher))

    in_filename = os.path.join(DIRECTORY, FILENAME)
    out_filename = in_filename + '.enc'
    filesize = os.path.getsize(in_filename)

    print ("Encrypting file")
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            chunk = infile.read(chunksize)
            while len(chunk) != 0:
                if len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))
                chunk = infile.read(chunksize)

    #
    # Store encrypted file on S3
    # Encrypted Key will be stored as meta data
    #
    print ("Storing encrypted file on S3")
    metadata = {
        "key" : base64.b64encode(keyCipher).decode('ascii')
    }

    s3 = session.client('s3')
    s3.upload_file(out_filename, S3_BUCKET, out_filename, ExtraArgs={'Metadata' : metadata})
    os.remove(out_filename)

    ##
    ## Later ...
    ##

    #
    # Download Encrypted File and it's metadata
    #
    print ("Download file and meta data from S3")
    transfer = S3Transfer(s3)
    transfer.download_file(S3_BUCKET, out_filename, out_filename)

    #retrieve meta data
    import boto3
    s3 = boto3.resource('s3')
    object = s3.Object(S3_BUCKET, out_filename)
    #print object.metadata

    keyCipher = base64.b64decode(object.metadata['key'])

    #decrypt encrypted key
    print ("Decrypt ciphered key")
    key = kms.decrypt(CiphertextBlob=keyCipher)
    keyPlain = key['Plaintext']
    print ("KMS Plain text key = %s " % base64.b64encode(keyPlain))
    print ("KMS Encrypted key  = %s " % base64.b64encode(keyCipher))

    #
    # Decrypt the file
    #
    print("Decrypt the file")

    in_filename = out_filename
    out_filename = in_filename + '.jpg'
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(keyPlain, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            chunk = infile.read(chunksize)
            while len(chunk) != 0:
                outfile.write(decryptor.decrypt(chunk))
                chunk = infile.read(chunksize)

            outfile.truncate(origsize)

    # Cleanup S3
    object.delete()

    print ("Done.\n\nYour file %s should be identical to original file %s" % (out_filename, os.path.join(DIRECTORY, FILENAME)))

# from https://github.com/aws/aws-encryption-sdk-python
# see http://busy-engineers-guide.reinvent-workshop.com/ 
def encryptionSDKDemo():
    import aws_encryption_sdk

    #
    # AWS Encryption SDK works with arbitrary length text 
    #
    plaintext = 'This is a very long text document'

    #
    # The MKP object contains reference to master keys
    #
    mkp = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[MASTER_KEY_ARN])
    encryption_context = {"data_type": "example", "classification": "public"}

    #
    # Let's encrypt the plaintext data
    #
    ciphertext, encryptor_header = aws_encryption_sdk.encrypt(
        source=plaintext, key_provider=mkp, encryption_context=encryption_context
    )

    #
    # Let's decrypt the ciphertext data
    #
    decrypted_plaintext, decryptor_header = aws_encryption_sdk.decrypt(
        source=ciphertext, key_provider=mkp
    )

    print(decrypted_plaintext.decode("utf-8"))

def kmsSign():

    MESSAGE_TO_SIGN = b'This is the message to sign'
    SIGNATURE_KEY_ARN = 'arn:aws:kms:us-east-1:486652066693:key/c74eed44-ecb6-424b-9b1e-1a305ab64a4e'

    #
    # Create a KMS Client object
    #
    session = Session(profile_name="default", region_name="us-east-1")
    kms = session.client('kms')

    #
    # Sign a piece of text 
    #
    print('Signing a simple text ')
    response = kms.sign(
        KeyId=SIGNATURE_KEY_ARN,
        Message=MESSAGE_TO_SIGN,
        MessageType='RAW',
        SigningAlgorithm='RSASSA_PSS_SHA_256'
    )

    signature = response['Signature']

    #
    # Show signature 
    #
    print(f"Signature : {base64.b64encode(signature).decode('ascii')}")

    #
    # verify signature 
    #
    response = kms.verify(
        KeyId=SIGNATURE_KEY_ARN,
        Message=MESSAGE_TO_SIGN,
        MessageType='RAW',
        Signature=signature,
        SigningAlgorithm='RSASSA_PSS_SHA_256'
    )

    if response['SignatureValid'] == True:
        print('Signature is valid')
    else:
        print('Signature is NOT valid')

def kmsAsyncEncrypt():

    # small amount of data only 
    # see https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.encrypt
    MESSAGE_TO_CRYPT = b'This is the message to encrypt'
    ASYNC_KEY_ARN    = 'arn:aws:kms:us-east-1:486652066693:key/5a681bd7-d1f9-44f7-839f-576601255490'

    #
    # Create a KMS Client object
    #
    session = Session(profile_name="default", region_name="us-east-1")
    kms = session.client('kms')

    #
    # Cipher a plain text object using your master key
    #
    ret = kms.encrypt(
        KeyId=ASYNC_KEY_ARN,
        Plaintext=MESSAGE_TO_CRYPT,
        EncryptionAlgorithm='RSAES_OAEP_SHA_256'
    )
    print (f"Ciphered text     = {base64.b64encode(ret['CiphertextBlob'])}")

    #
    # Decrypt a ciphered text
    #
    ret = kms.decrypt(
        KeyId=ASYNC_KEY_ARN,
        CiphertextBlob=ret['CiphertextBlob'],
        EncryptionAlgorithm='RSAES_OAEP_SHA_256'
    )
    print (f"Plaintext message = {ret['Plaintext']}")


if __name__ == '__main__':
    # kmsKeyDemo()
    # kmsEncryptionDemo()
    # S3KMSDemo()
    # encryptionSDKDemo()
    # kmsSign()
    kmsAsyncEncrypt()
