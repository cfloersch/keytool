package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Enumeration;

import xpertss.crypto.util.DerValue;
import xpertss.crypto.util.DerOutputStream;

/**
 * Represents the CRL Certificate Issuer Extension (OID = 2.5.29.29).
 * <p/>
 * The CRL certificate issuer extension identifies the certificate issuer
 * associated with an entry in an indirect CRL, i.e. a CRL that has the
 * indirectCRL indicator set in its issuing distribution point extension. If
 * this extension is not present on the first entry in an indirect CRL, the
 * certificate issuer defaults to the CRL issuer. On subsequent entries
 * in an indirect CRL, if this extension is not present, the certificate
 * issuer for the entry is the same as that for the preceding entry.
 * <p/>
 * If used by conforming CRL issuers, this extension is always
 * critical.  If an implementation ignored this extension it could not
 * correctly attribute CRL entries to certificates.  PKIX (RFC 3280)
 * RECOMMENDS that implementations recognize this extension.
 * <p/>
 * The ASN.1 definition for this is:
 * <pre>
 * id-ce-certificateIssuer   OBJECT IDENTIFIER ::= { id-ce 29 }
 *
 * certificateIssuer ::=     GeneralNames
 * </pre>
 *
 * @author Anne Anderson
 * @author Sean Mullan
 * @see Extension
 * @see CertAttrSet
 * @since 1.5
 */
public class CertificateIssuerExtension extends Extension implements CertAttrSet<String> {

   /**
    * Attribute names.
    */
   public static final String NAME = "CertificateIssuer";
   public static final String ISSUER = "issuer";

   private GeneralNames names;

   /**
    * Encode this extension
    */
   private void encodeThis() throws IOException
   {
      if (names == null || names.isEmpty()) {
         this.extensionValue = null;
         return;
      }
      DerOutputStream os = new DerOutputStream();
      names.encode(os);
      this.extensionValue = os.toByteArray();
   }

   /**
    * Create a CertificateIssuerExtension containing the specified issuer name.
    * Criticality is automatically set to true.
    *
    * @param issuer the certificate issuer
    * @throws IOException on error
    */
   public CertificateIssuerExtension(GeneralNames issuer) throws IOException
   {
      this.extensionId = PKIXExtensions.CertificateIssuer_Id;
      this.critical = true;
      this.names = issuer;
      encodeThis();
   }

   /**
    * Create a CertificateIssuerExtension from the specified DER encoded
    * value of the same.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value
    * @throws ClassCastException if value is not an array of bytes
    * @throws IOException        on error
    */
   public CertificateIssuerExtension(Boolean critical, Object value)
      throws IOException
   {
      this.extensionId = PKIXExtensions.CertificateIssuer_Id;
      this.critical = critical.booleanValue();

      this.extensionValue = (byte[]) value;
      DerValue val = new DerValue(this.extensionValue);
      this.names = new GeneralNames(val);
   }

   /**
    * Set the attribute value.
    *
    * @throws IOException on error
    */
   public void set(String name, Object obj) throws IOException
   {
      if (name.equalsIgnoreCase(ISSUER)) {
         if (!(obj instanceof GeneralNames)) {
            throw new IOException("Attribute value must be of type " +
               "GeneralNames");
         }
         this.names = (GeneralNames) obj;
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateIssuer");
      }
      encodeThis();
   }

   /**
    * Gets the attribute value.
    *
    * @throws IOException on error
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(ISSUER)) {
         return names;
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateIssuer");
      }
   }

   /**
    * Deletes the attribute value.
    *
    * @throws IOException on error
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(ISSUER)) {
         names = null;
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateIssuer");
      }
      encodeThis();
   }

   /**
    * Returns a printable representation of the certificate issuer.
    */
   public String toString()
   {
      return super.toString() + "Certificate Issuer [\n" +
         String.valueOf(names) + "]\n";
   }

   /**
    * Write the extension to the OutputStream.
    *
    * @param out the OutputStream to write the extension to
    * @throws IOException on encoding errors
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      if (extensionValue == null) {
         extensionId = PKIXExtensions.CertificateIssuer_Id;
         critical = true;
         encodeThis();
      }
      super.encode(tmp);
      out.write(tmp.toByteArray());
   }

   /**
    * Return an enumeration of names of attributes existing within this
    * attribute.
    */
   public Enumeration<String> getElements()
   {
      AttributeNameEnumeration elements = new AttributeNameEnumeration();
      elements.add(ISSUER);
      return Collections.enumeration(elements);
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return NAME;
   }
}
