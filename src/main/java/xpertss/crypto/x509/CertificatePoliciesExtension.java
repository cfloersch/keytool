package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.PolicyQualifierInfo;
import java.util.*;

import xpertss.crypto.util.DerValue;
import xpertss.crypto.util.DerOutputStream;
import xpertss.crypto.util.HexUtils;

/**
 * This class defines the certificate policies extension which specifies the
 * policies under which the certificate has been issued
 * and the purposes for which the certificate may be used.
 * <p/>
 * Applications with specific policy requirements are expected to have a
 * list of those policies which they will accept and to compare the
 * policy OIDs in the certificate to that list.  If this extension is
 * critical, the path validation software MUST be able to interpret this
 * extension (including the optional qualifier), or MUST reject the
 * certificate.
 * <p/>
 * Optional qualifiers are not supported in this implementation, as they are
 * not recommended by RFC2459.
 * <p/>
 * The ASN.1 syntax for this is (IMPLICIT tagging is defined in the
 * module definition):
 * <pre>
 * id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
 *
 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 * PolicyInformation ::= SEQUENCE {
 *      policyIdentifier   CertPolicyId,
 *      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
 *                              PolicyQualifierInfo OPTIONAL }
 *
 * CertPolicyId ::= OBJECT IDENTIFIER
 *
 * PolicyQualifierInfo ::= SEQUENCE {
 * policyQualifierId  PolicyQualifierId,
 * qualifier          ANY DEFINED BY policyQualifierId }
 *
 * -- policyQualifierIds for Internet policy qualifiers
 *
 * id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
 * id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
 * id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
 *
 * PolicyQualifierId ::=
 * OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 *
 * Qualifier ::= CHOICE {
 * cPSuri           CPSuri,
 * userNotice       UserNotice }
 *
 * CPSuri ::= IA5String
 *
 * UserNotice ::= SEQUENCE {
 * noticeRef        NoticeReference OPTIONAL,
 * explicitText     DisplayText OPTIONAL}
 *
 * NoticeReference ::= SEQUENCE {
 * organization     DisplayText,
 * noticeNumbers    SEQUENCE OF INTEGER }
 *
 * DisplayText ::= CHOICE {
 * ia5String        IA5String      (SIZE (1..200)),
 * visibleString    VisibleString  (SIZE (1..200)),
 * bmpString        BMPString      (SIZE (1..200)),
 * utf8String       UTF8String     (SIZE (1..200)) }
 * </pre>
 *
 * @author Anne Anderson
 * @see Extension
 * @see CertAttrSet
 * @since 1.4
 */
public class CertificatePoliciesExtension extends Extension implements CertAttrSet<String> {
   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.extensions.CertificatePolicies";
   /**
    * Attribute names.
    */
   public static final String NAME = "CertificatePolicies";
   public static final String POLICIES = "policies";

   /**
    * List of PolicyInformation for this object.
    */
   private List<PolicyInformation> certPolicies;

   // Encode this extension value.
   private void encodeThis()
      throws IOException
   {
      if (certPolicies == null || certPolicies.isEmpty()) {
         this.extensionValue = null;
      } else {
         DerOutputStream os = new DerOutputStream();
         DerOutputStream tmp = new DerOutputStream();

         for (PolicyInformation info : certPolicies) {
            info.encode(tmp);
         }

         os.write(DerValue.tag_Sequence, tmp);
         this.extensionValue = os.toByteArray();
      }
   }

   /**
    * Create a CertificatePoliciesExtension object from
    * a List of PolicyInformation; the criticality is set to false.
    *
    * @param certPolicies the List of PolicyInformation.
    */
   public CertificatePoliciesExtension(List<PolicyInformation> certPolicies)
      throws IOException
   {
      this(Boolean.FALSE, certPolicies);
   }

   /**
    * Create a CertificatePoliciesExtension object from
    * a List of PolicyInformation with specified criticality.
    *
    * @param critical     true if the extension is to be treated as critical.
    * @param certPolicies the List of PolicyInformation.
    */
   public CertificatePoliciesExtension(Boolean critical, List<PolicyInformation> certPolicies)
      throws IOException
   {
      this.certPolicies = certPolicies;
      this.extensionId = PKIXExtensions.CertificatePolicies_Id;
      this.critical = critical.booleanValue();
      encodeThis();
   }

   /**
    * Create the extension from its DER encoded value and criticality.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws ClassCastException if value is not an array of bytes
    * @throws IOException        on error.
    */
   public CertificatePoliciesExtension(Boolean critical, Object value)
      throws IOException
   {
      this.extensionId = PKIXExtensions.CertificatePolicies_Id;
      this.critical = critical.booleanValue();
      this.extensionValue = (byte[]) value;
      DerValue val = new DerValue(this.extensionValue);
      if (val.tag != DerValue.tag_Sequence) {
         throw new IOException("Invalid encoding for " +
            "CertificatePoliciesExtension.");
      }
      certPolicies = new ArrayList<PolicyInformation>();
      while (val.data.available() != 0) {
         DerValue seq = val.data.getDerValue();
         PolicyInformation policy = new PolicyInformation(seq);
         certPolicies.add(policy);
      }
   }

   /**
    * Return the extension as user readable string.
    */
   public String toString()
   {
      if (certPolicies == null) {
         return "";
      }
      StringBuilder sb = new StringBuilder(super.toString());
      sb.append("CertificatePolicies [\n");
      for (PolicyInformation info : certPolicies) {
         sb.append(info);
      }
      sb.append("]\n");
      return sb.toString();
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
      if (extensionValue == null) {
         extensionId = PKIXExtensions.CertificatePolicies_Id;
         critical = false;
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
      if (name.equalsIgnoreCase(POLICIES)) {
         if (!(obj instanceof List)) {
            throw new IOException("Attribute value should be of type List.");
         }
         certPolicies = (List<PolicyInformation>) obj;
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:CertificatePoliciesExtension.");
      }
      encodeThis();
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(POLICIES)) {
         //XXXX May want to consider cloning this
         return certPolicies;
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:CertificatePoliciesExtension.");
      }
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(POLICIES)) {
         certPolicies = null;
      } else {
         throw new IOException("Attribute name [" + name +
            "] not recognized by " +
            "CertAttrSet:CertificatePoliciesExtension.");
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
      elements.add(POLICIES);

      return Collections.enumeration(elements);
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return (NAME);
   }
}
