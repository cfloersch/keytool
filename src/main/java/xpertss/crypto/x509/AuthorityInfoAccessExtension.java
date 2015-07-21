package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;

import java.util.*;

import xpertss.crypto.util.DerOutputStream;
import xpertss.crypto.util.DerValue;
import xpertss.crypto.util.ObjectIdentifier;

/**
 * The Authority Information Access Extension (OID = 1.3.6.1.5.5.7.1.1).
 * <p/>
 * The AIA extension identifies how to access CA information and services
 * for the certificate in which it appears. It enables CAs to issue their
 * certificates pre-configured with the URLs appropriate for contacting
 * services relevant to those certificates. For example, a CA may issue a
 * certificate that identifies the specific OCSP Responder to use when
 * performing on-line validation of that certificate.
 * <p/>
 * This extension is defined in <a href="http://www.ietf.org/rfc/rfc3280.txt">
 * Internet X.509 PKI Certificate and Certificate Revocation List
 * (CRL) Profile</a>. The profile permits
 * the extension to be included in end-entity or CA certificates,
 * and it must be marked as non-critical. Its ASN.1 definition is as follows:
 * <pre>
 *   id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *
 *   AuthorityInfoAccessSyntax  ::=
 *         SEQUENCE SIZE (1..MAX) OF AccessDescription
 *
 *   AccessDescription  ::=  SEQUENCE {
 *         accessMethod          OBJECT IDENTIFIER,
 *         accessLocation        GeneralName  }
 * </pre>
 * <p/>
 *
 * @see Extension
 * @see CertAttrSet
 */

public class AuthorityInfoAccessExtension extends Extension implements CertAttrSet<String> {

   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.extensions.AuthorityInfoAccess";

   /**
    * Attribute name.
    */
   public static final String NAME = "AuthorityInfoAccess";
   public static final String DESCRIPTIONS = "descriptions";

   /**
    * The List of AccessDescription objects.
    */
   private List<AccessDescription> accessDescriptions;

   /**
    * Create an AuthorityInfoAccessExtension from a List of
    * AccessDescription; the criticality is set to false.
    *
    * @param accessDescriptions the List of AccessDescription
    * @throws IOException on error
    */
   public AuthorityInfoAccessExtension(
      List<AccessDescription> accessDescriptions) throws IOException
   {
      this.extensionId = PKIXExtensions.AuthInfoAccess_Id;
      this.critical = false;
      this.accessDescriptions = accessDescriptions;
      encodeThis();
   }

   /**
    * Create the extension from the passed DER encoded value of the same.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    Array of DER encoded bytes of the actual value.
    * @throws IOException on error.
    */
   public AuthorityInfoAccessExtension(Boolean critical, Object value)
      throws IOException
   {
      this.extensionId = PKIXExtensions.AuthInfoAccess_Id;
      this.critical = critical.booleanValue();

      if (!(value instanceof byte[])) {
         throw new IOException("Illegal argument type");
      }

      extensionValue = (byte[]) value;
      DerValue val = new DerValue(extensionValue);
      if (val.tag != DerValue.tag_Sequence) {
         throw new IOException("Invalid encoding for " +
            "AuthorityInfoAccessExtension.");
      }
      accessDescriptions = new ArrayList<AccessDescription>();
      while (val.data.available() != 0) {
         DerValue seq = val.data.getDerValue();
         AccessDescription accessDescription = new AccessDescription(seq);
         accessDescriptions.add(accessDescription);
      }
   }

   /**
    * Return the list of AccessDescription objects.
    */
   public List<AccessDescription> getAccessDescriptions()
   {
      return accessDescriptions;
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return NAME;
   }

   /**
    * Write the extension to the DerOutputStream.
    *
    * @param out the DerOutputStream to write the extension to.
    * @throws IOException on encoding errors.
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      if (this.extensionValue == null) {
         this.extensionId = PKIXExtensions.AuthInfoAccess_Id;
         this.critical = false;
         encodeThis();
      }
      super.encode(tmp);
      out.write(tmp.toByteArray());
   }

   /**
    * Set the attribute value.
    */
   public void set(String name, Object obj) throws IOException
   {
      if (name.equalsIgnoreCase(DESCRIPTIONS)) {
         if (!(obj instanceof List)) {
            throw new IOException("Attribute value should be of type List.");
         }
         accessDescriptions = (List<AccessDescription>) obj;
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:AuthorityInfoAccessExtension.");
      }
      encodeThis();
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DESCRIPTIONS)) {
         return accessDescriptions;
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:AuthorityInfoAccessExtension.");
      }
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DESCRIPTIONS)) {
         accessDescriptions = new ArrayList<AccessDescription>();
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:AuthorityInfoAccessExtension.");
      }
      encodeThis();
   }

   /**
    * Return an enumeration of names of attributes existing within this
    * attribute.
    */
   public Enumeration<String> getElements()
   {
      AttributeNameEnumeration elements = new AttributeNameEnumeration();
      elements.add(DESCRIPTIONS);
      return Collections.enumeration(elements);
   }

   // Encode this extension value
   private void encodeThis() throws IOException
   {
      if (accessDescriptions.isEmpty()) {
         this.extensionValue = null;
      } else {
         DerOutputStream ads = new DerOutputStream();
         for (AccessDescription accessDescription : accessDescriptions) {
            accessDescription.encode(ads);
         }
         DerOutputStream seq = new DerOutputStream();
         seq.write(DerValue.tag_Sequence, ads);
         this.extensionValue = seq.toByteArray();
      }
   }

   /**
    * Return the extension as user readable string.
    */
   public String toString()
   {
      StringBuffer buf = new StringBuffer(super.toString());
      buf.append("AuthorityInfoAccess").append(" [\n");
      for(int i = 0 ; i < accessDescriptions.size(); i++) {
         AccessDescription desc = accessDescriptions.get(i);
         ObjectIdentifier accessMethod = desc.getAccessMethod();
         if (accessMethod.equals(AccessDescription.Ad_CAISSUERS_Id)) {
            buf.append("  ").append("Certificate Authority Issuer");
         } else if (accessMethod.equals(AccessDescription.Ad_CAREPOSITORY_Id)) {
            buf.append("  ").append("Certificate Authority Repository");
         } else if (accessMethod.equals(AccessDescription.Ad_TIMESTAMPING_Id)) {
            buf.append("  ").append("Time Stamping");
         } else if (accessMethod.equals(AccessDescription.Ad_OCSP_Id)) {
            buf.append("  ").append("On-line Certificate Status Protocol");
         } else {
            buf.append("  ").append(accessMethod);
         }
         buf.append("\n  ").append("  ").append(desc.getAccessLocation());
         buf.append("\n");
      }
      buf.append("]\n");
      return buf.toString();
   }

}
