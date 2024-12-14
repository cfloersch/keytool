# Creating and Certifying a TLS Server Certificate

This example will walk you through the steps of creating a TLS Server keyset, creating a
certificate signing request, certifying and signing the certificate with a CA cert, and
finally importing that signed certificate into the keystore along side the private key.

Finally, we will show you a number of ways of exporting the keys for use in your server.

Creating TLS Server Key Pair
----------------------------

In the following example we are creating an RSA keypair for a server named `servera.domain.com`.
We are overriding the prompted distinguished name input with a command line specified shortened
variant.

```
keytool -genkeypair -alias servera -keystore servers.pfx
        -keyalg RSA -keysize 2048   
        -ext san=dns:servera.domain.com,dns:*.domain.com 
        -dname "CN=servera.domain.com, OU=Application Servers, O=Manheim, c=US"
```

We exclude the `-validity` argument above as that is only necessary on self-signed certificates.

Creating a Certificate Signing Request
--------------------------------------

When we create a certification request we must specify the key usage and extended key usage
extensions. The indication that this is NOT a certificate authority key is generally advisable
to make things smoother when obtaining approval.

```
keytool -certreq -alias servera  -keystore servers.pfx
           -ext ku:c=digitalSignature,keyEncipherment
           -ext bc:c=ca:false -ext eku=serverAuth
           -file servera.csr
```
                               

Viewing the Certificate Request
-------------------------------

Generally a certificate authority will view the certificate request and validate it's properties
before approving it and creating the signed certificate.

```
keytool -printcertreq -v -file servera.csr
```

TODO Add a table of generally acceptable key-usage and ext-key-usage for the various types of
keys.


Creating Signed Certificate Chain
---------------------------------

Once we have decided we will create the requested certificate we must determine the validity period
and supply it to the `gencert` method of keytool. Generally, this validity period will be 365 days
or less. The weaker the key the shorter the validity period should be.

```
keytool -gencert -infile servera.csr -outfile servera.spc
            -alias cacert -keystore castore.pfx
            -validity 365 -ext honored=all
```

Additionally, we must specify which certificate extensions in the request we intend to honor when
producing the resulting certificate. In the above example we honor all-of-the requested extensions.

TODO Add a table showing the means by which we can exclude/include extensions


Importing Signed Certificate
----------------------------

Generally the signed certificate file produced by the CA will include the full certificate chain
spanning the root certificate, any intermediaries, and the subject certificate signed in the
request. We will import the entire chain into the keystore with the private key.

```
keytool -importcert -alias servera -keystore servers.pfx -trustcacerts -file servera.spc
```

You now have an encrypted keystore protected by a password that includes the private key and an 
associated and certified certificate along with the certification chain in PKCS12 format. This
may be sufficient for some systems. However, many systems will require these elements be provided
in different formats.

Exporting the Private Key in PEM Format
---------------------------------------

Some systems may require the private key to be unencrypted and in PEM format. To export the
private key in a format suitable for those systems we will use:

```
keytool -exportprikey -alias servera -keystore servers.pfx -rfc -file servera-prikey.pem 
```

The `-rfc` argument is used to indicate the key should be exported in PEM format.
                                                   

Exporting the Certificate in PEM Format
---------------------------------------

To export the certificate to a PEM encoded file without the certificate chain:

```
keytool -exportcert -alias servera -keystore servers.pfx -rfc -file servera-cert.pem 
```

Again the `-rfc` argument indicates a PEM encoding to the export.


Exporting the Certificate Chain in PKCS7 Format
-----------------------------------------------

Some servers may want the certificate and it's certification chain. There are many different
variations of that. This will show the PKCS7 variant:

```
keytool -exportchain -alias servera -keystore servers.pfx -v -rfc -file servera-chain.pem 
```

Again the `-rfc` argument indicates a PEM encoding to the export. In most cases, systems that
want PKCS7 formatted certification chain do not care if it is PEM encoded or not.

The `-v` argument is important. If you exclude that you will get the certificate chain to
root without the actual server certificate. Including it ensures you get the server cert and
the entire chain.


Exporting the Certificate Chain in PEM Format
---------------------------------------------

Some servers may want the certificate and it's certification chain. There are many different
variations of that. This will show the PEM variant:

```
keytool -exportpem -alias servera -keystore servers.pfx -v -file servera-chain.pem 
```

The `-v` argument is important. If you exclude that you will get the certificate chain to
root without the actual server certificate. Including it ensures you get the server cert and
the entire chain.

In some cases you may need to edit the resulting file to include the private key at the
head.

