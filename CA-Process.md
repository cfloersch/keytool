# Creating a CA and Intermediary CA Certificates

This example will walk you through the steps of creating a CA Server keyset, creating an
intermediary certificate, and certifying and signing the intermediary certificate with a
CA cert.

Finally, we will show you a number of ways of exporting the keys for use in your servers
and to import into trusted stores.


Creating Root CA Key Pair
-------------------------

In the following example we are creating an RSA keypair for our Root CA. We are overriding
the prompted distinguished name input with a command line specified shortened variant. The
resulting Root CA Certificate will have an exipration of 20 years.

```
keytool –genkeypair –alias cacert –keystore castore.pfx
        –keyalg RSA –keysize 2048 –validity 7300
        –ext bc:c=ca:true –ext ku:c=keyCertSign,cRLSign
        -dname "CN=Xpertss Root CA, OU=Certificate Authority, O=Xpert Solution Services, L=Atlanta, ST=GA, C=US"
```

The –ext option allows you to supply extensions. In this case we add a Basic Constraint (bc)
option which is marked as critical and defines this as a CA certificate. We also define a 
Key usage (ku) extension which is also marked as critical and which defines certificate 
signing and CRL signing usages.

It is recommended to use a strong password to protect this key pair as it represents the
root of your trust hierarchy. The resulting keypair will be stored in the file `castore.pfx`
protected by your prompted password.



Exporting Root CA Public Certificate
------------------------------------

Once you've created your Root CA certificate you will want to export the public certificate
so that it may be imported into various trust stores. The public certificate is shared with
clients that need to trust the CA.

```
keytool –exportcert –alias cacert –keystore castore.pfx 
        –file cacert.crt
```

The above exports the certificate in a binary format known as DER. Alternatively, you can
export it to a text friendly format known as PEM.

```
keytool –exportcert –alias cacert –keystore castore.pfx 
        -rfc –file cacert.pem
```

You should import one of these exported Root CA certificates into your various trust stores.
This is accomplished differently depending on the platform. Most Operating Systems provide
a means to do this to include iOS, Android, Linux, Windows, and Mac. Some browsers and or
servers also have a means to do this.



Creating a Singular TrustStore
------------------------------

In some cases you may want your java based server/client to verify TLS certificates where
only your CA cert is valid. Rather than adding your Root CA Cert to an existing trust
store you will want to create a trust store with only your cert.

```
keytool -importcert -trustcacerts -alias "Xpertss Root CA" 
        -file cacert.crt -keystore truststore.pfx 
```




Create an Intermediary CA Certificate
-------------------------------------

It is generally a bad idea to sign end user certificates with your Root CA certificate. Instead,
you should create an Intermediary CA keypair that is actually used to do the signing.

```
keytool –genkeypair –alias signing –keystore castore.pfx
        –keyalg RSA –keysize 2048
        –ext bc:c=ca:true –ext ku:c=keyCertSign,cRLSign
        -dname "CN=Xpertss Intermediary CA, OU=Certificate Authority, O=Xpert Solution Services, L=Atlanta, ST=GA, C=US"
```

You will want to use a different Common Name (CN). In some cases you may have multiple intermediary
CA keypair so chose a name wisely. No need to specify a `validity` as that is done by the Root CA
when they sign the intermediary certificate.

Like the Root CA this private key should be protected by a strong password.


Create Signing Request for Intermediary
---------------------------------------

An intermediary certificate is not self-signed. It must be signed by your root CA cert. The first
step is to create a certificate signing request (CSR).

```
keytool -certreq -alias signing  -keystore castore.pfx
           –ext bc:c=ca:true –ext ku:c=keyCertSign,cRLSign
           -file signing.csr
```


Validating a Certificate Signing Request
----------------------------------------

As the CA you should validate the certificate you are being asked to sign. Generally, this would
require the requestor to prove they are who they say they are using various methods like presenting
a business license, showing ID, or proving they control a dns domain.

You can view the contents of the signing request using:

```
keytool –printcertreq -v –file signing.csr
```

The above command will output the certificate signing request to the console and allow you to examine
the contents. It will include the subject name which you should verify, both MD5 and SHA1 hashes of 
the contained public key, and the set of extensions they are requesting.

The following table shows the attributes you'd generally include for the various types of certificates.

| Certificate Type | Signing Options                                                                                                                                                                      |
|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TLS Server       | Basic Constraints: CA=false <br> Key Usage: Digital Signature, Key Encipherment <br> Extended Key Usage: Server Auth <br> Subject Alternative Names: A list of IP or DNS entries     |
| TLS Client       | Basic Constraints: CA=false <br> Key Usage: Digital Signature <br> Extended Key Usage: Client Auth                                                                                   |
| S/MIME           | Basic Constraints: CA=false <br>  Key Usage: Digital Signature, Key Encipherment <br> Extended Key Usage: Email Protection <br> Subject Alternative Names: A list of EMAIL addresses |
| Code Signing     | Basic Constraints: CA=false <br> Key Usage: Digital Signature <br> Extended Key Usage: Code Signing                                                                                  |
| CA               | Basic Constraints: CA=true <br> Key Usage: Digital Signature <br> Extended Key Usage: Key Cert Sign, CRL Sign                                                                        |


Signing a Certificate Signing Request
-------------------------------------

If the certificates identify verifies and the requested attributes line up the following will sign 
it inline. Note as the signer we are responsible for specifying the `validity` period. For an 
intermediary CA certificate we would keep this period smaller than the Root CA but longer than the
period of the certificates it will be signing. Most end user/system certificates are constrained to
one year or less so an intermediary could be as small as three years.

```
keytool –gencert -infile signing.csr -outfile signing.p7b 
          -alias cacert -keystore castore.pfx -storetype pkcs12 
          -validity 3650 -ext honored=all
```


| Arguments                                | Output Attributes                                                                                              |
|------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| -ext honored=all                         | Accept all attributes from the request as they are.                                                            |
| -ext honored=all,-bc                     | Accept all attributes from the request except the basic constraint (bc)                                        |
| -ext honored=san                         | Honor only the subject alternative name (SAN) from the request.                                                |
| -ext honored=san,ku                      | Honor both subject alternative name (SAN) and Key Usage (ku) from request                                      |
| -ext honored=all <br> -ext bc:c=ca:false | Honor all requested extensions but override/add the basic constraint (bc) with the specified basic constraint. |

You may include the `-rfc` option to encode the output in PEM format. The default is DER encoded. 
The outfile includes both the signed certificate and the signing certificate. This is critical for 
intermediaries which themselves are not trusted so a trust chain must be established.

The outfile may now be returned to the requestor.


Importing a Signed Certificate into Keystore
--------------------------------------------

Once you receive the signed certificate you will often want to import it back into your keystore
to sit alongside your private key.

```
keytool –importcert –alias signing –keystore castore.pfx 
   -trustcacerts –file signing.p7b
```


Extract Intermediary Keypair
----------------------------

Generally, you want to lock down the castore.pfx file with the Root CA Cert somewhere safe, 
unreachable by the internet. But before you do that you want to extract your intermediary 
keypair so you may use it to do your signing.

```
keytool -importkeystore 
        -srckeystore castore.pfx -srcalias signing
        -destkeystore signing.pfx -destalias signing
```

When you run the command, keytool will prompt you for three different passwords in this order:
* Destination key password: Create a new password for your new single-entry file.
* Destination key password: Validate the password entered in prompt one.
* Source key password: The password protecting that specific private key inside the source collection.



