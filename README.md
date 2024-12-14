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

US Grade Jurisdiction Policy files must be installed for the Java VM. These
are also called the unlimited strength cryptography policy files. Please see
the readme included with that distribution for installation instructions.

Please see the included README.docx for instructions on how to perform basic
key/certificate management functions and for an explanation of the various
cryptographic formats.

Examples
  [TLS Server Process](TLS-Server-Process.md)
