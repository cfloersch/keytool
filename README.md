# keytool
Java keytool replacement


Keytool is a replacement for the java keytool which provides a few additional
capabilities the standard keytool does not.

The two main additions include the ability to export a private key to an
unencrypted DER or PEM format and the ability to export an entire certificate
chain to a PEM format.

The install directory may be added to your path but it should be included in
the path before the default java install to avoid using that version of the
tool.

Please see the included README.docx for instructions on how to perform basic
key/certificate management functions and for an explanation of the various
cryptographic formats.

It is important to note that the default signature algorithm used by this tool is
SHA1withRSA. That algorithm is no longer considered secure and browsers will
increasingly warn users about sites utilizing it on their certificates. To avoid
those warnings make sure all signatures are created using SHA256withRSA as a minimum.