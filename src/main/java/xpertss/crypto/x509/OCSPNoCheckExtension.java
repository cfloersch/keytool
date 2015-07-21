package xpertss.crypto.x509;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;


/**
 * Represent the OCSP NoCheck Extension from RFC2560.
 * <p/>
 * A CA may specify that an OCSP client can trust a responder for the
 * lifetime of the responder's certificate. The CA does so by including
 * the extension id-pkix-ocsp-nocheck. This SHOULD be a non-critical
 * extension. The value of the extension should be NULL. CAs issuing
 * such a certificate should realized that a compromise of the
 * responder's key, is as serious as the compromise of a CA key used to
 * sign CRLs, at least for the validity period of this certificate. CA's
 * may choose to issue this type of certificate with a very short
 * lifetime and renew it frequently.
 * <pre>
 * id-pkix-ocsp-nocheck OBJECT IDENTIFIER ::= { id-pkix-ocsp 5 }
 * </pre>
 *
 * @author Xuelei Fan
 * @see Extension
 * @see CertAttrSet
 */
public class OCSPNoCheckExtension extends Extension implements CertAttrSet<String> {

   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.extensions.OCSPNoCheck";
   /**
    * Attribute names.
    */
   public static final String NAME = "OCSPNoCheck";

   /**
    * Create a OCSPNoCheckExtension
    */
   public OCSPNoCheckExtension() throws IOException
   {
      this.extensionId = PKIXExtensions.OCSPNoCheck_Id;
      this.critical = false;
      this.extensionValue = new byte[0];
   }

   /**
    * Create the extension from the passed DER encoded value.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws IOException on error.
    */
   public OCSPNoCheckExtension(Boolean critical, Object value)
      throws IOException
   {

      this.extensionId = PKIXExtensions.OCSPNoCheck_Id;
      this.critical = critical.booleanValue();

      // the value should be null, just ignore it here.
      this.extensionValue = new byte[0];
   }

   /**
    * Set the attribute value.
    */
   public void set(String name, Object obj) throws IOException
   {
      throw new IOException("No attribute is allowed by " +
         "CertAttrSet:OCSPNoCheckExtension.");
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      throw new IOException("No attribute is allowed by " +
         "CertAttrSet:OCSPNoCheckExtension.");
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      throw new IOException("No attribute is allowed by " +
         "CertAttrSet:OCSPNoCheckExtension.");
   }

   /**
    * Return an enumeration of names of attributes existing within this
    * attribute.
    */
   public Enumeration<String> getElements()
   {
      return Collections.enumeration(new AttributeNameEnumeration());
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return NAME;
   }
}
