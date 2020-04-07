# KMS Developer Demo

## Description

This is a developer oriented demonstration on how to use [AWS Key Management Service (KMS)]( https://aws.amazon.com/kms/) to encrypt plain text or files in the Python programming language, although this example and API used is also relevant for developers using other programming languages.

AWS Key Management Service (KMS) is a managed service that makes it easy for you to create and control the encryption keys used to encrypt your data, and uses Hardware Security Modules (HSMs) to protect the security of your keys.

## Comments

This demo is divided in four main parts.

### Part 1 : Infrastructure Setup

This part is required to setup the infrastructure required by the demo:
- create a role allowing you to use KMS  

- create a KMS Master key if it does not exist yet.  

  Each key that you create in AWS Key Management Service costs $1/month as long as it is enabled, therefore, for this demo, we choose to create a KMS Master key in your account and to not delete it at the end of the demo, instead we will de-activate it and reuse it later for the next run of the demo.  

- create an S3 bucket (to be used in part 3 below)
- Establish the connection to the KMS service in the given region

### Part 2 : Clear Text encoding / decoding

The next two code blocks are dealing with clear text encryption and decryption.

#### Cipher

The code request a data key from KMS.  KMS returns the key as cleartext and as a ciphered object.  Code is using the cleartext key to encode the text message.  

In real life scenario, code should dispose the cleartext version of the key and store the ciphered key only.

#### Decipher

The code makes a KMS call, passing the cipher version of the key and receive the clear text key back.

It then uses this clear text key to decipher the ciphered message.

### Part 3 : File encoding / decoding

The next two code blocks perform a cipher / decipher operation on a JPG file and upload the file to an S3 bucket.

Notice the following:

- The AES Initialization Vector (IV) is stored in the ciphered file header (<Q+original file length+IV)

- The ciphered version of the data key is base64 encoded and stored in the S3 MetaData, as "Key"

Deciphering is following similar steps as the clear text version described above.  

### Part 4 : Clean up

The clean part of the code takes care of deleting files and the S3 bucket.  It then disable the KMS master key.

## Costs

KMS cost metrics are:
- a fixed cost per month for enabled master keys
- a price per 10000 API calls.

The free tier includes 20000 API calls per month.

Details and up-to-date information is available in [KMS Pricing page](https://aws.amazon.com/kms/pricing/)

S3 cost to host the 11k JPG file is negligible.

## Credits

File encryption code taken from http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/ published under a [Public Domain License](http://unlicense.org)

## License

Copyright 2015, Amazon Web Services.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
