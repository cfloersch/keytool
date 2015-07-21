package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

import xpertss.crypto.util.*;

/**
 * This class defines the Private Key Usage Extension.
 * <p/>
 * <p>The Private Key Usage Period extension allows the certificate issuer
 * to specify a different validity period for the private key than the
 * certificate. This extension is intended for use with digital
 * signature keys.  This extension consists of two optional components
 * notBefore and notAfter.  The private key associated with the
 * certificate should not be used to sign objects before or after the
 * times specified by the two components, respectively.
 * <p/>
 * <pre>
 * PrivateKeyUsagePeriod ::= SEQUENCE {
 *     notBefore  [0]  GeneralizedTime OPTIONAL,
 *     notAfter   [1]  GeneralizedTime OPTIONAL }
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see Extension
 * @see CertAttrSet
 */
public class PrivateKeyUsageExtension extends Extension implements CertAttrSet<String> {
   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.extensions.PrivateKeyUsage";
   /**
    * Sub attributes name for this CertAttrSet.
    */
   public static final String NAME = "PrivateKeyUsage";
   public static final String NOT_BEFORE = "not_before";
   public static final String NOT_AFTER = "not_after";

   // Private data members
   private static final byte TAG_BEFORE = 0;
   private static final byte TAG_AFTER = 1;

   private Date notBefore = null;
   private Date notAfter = null;

   // Encode this extension value.
   private void encodeThis() throws IOException
   {
      if (notBefore == null && notAfter == null) {
         this.extensionValue = null;
         return;
      }
      DerOutputStream seq = new DerOutputStream();

      DerOutputStream tagged = new DerOutputStream();
      if (notBefore != null) {
         DerOutputStream tmp = new DerOutputStream();
         tmp.putGeneralizedTime(notBefore);
         tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
            false, TAG_BEFORE), tmp);
      }
      if (notAfter != null) {
         DerOutputStream tmp = new DerOutputStream();
         tmp.putGeneralizedTime(notAfter);
         tagged.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
            false, TAG_AFTER), tmp);
      }
      seq.write(DerValue.tag_Sequence, tagged);
      this.extensionValue = seq.toByteArray();
   }

   /**
    * The default constructor for PrivateKeyUsageExtension.
    *
    * @param notBefore the date/time before which the private key
    *                  should not be used.
    * @param notAfter  the date/time after which the private key
    *                  should not be used.
    */
   public PrivateKeyUsageExtension(Date notBefore, Date notAfter)
      throws IOException
   {
      this.notBefore = notBefore;
      this.notAfter = notAfter;

      this.extensionId = PKIXExtensions.PrivateKeyUsage_Id;
      this.critical = false;
      encodeThis();
   }

   /**
    * Create the extension from the passed DER encoded value.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws ClassCastException   if value is not an array of bytes
    * @throws CertificateException on certificate parsing errors.
    * @throws IOException          on error.
    */
   public PrivateKeyUsageExtension(Boolean critical, Object value)
      throws CertificateException, IOException
   {
      this.extensionId = PKIXExtensions.PrivateKeyUsage_Id;
      this.critical = critical.booleanValue();

      this.extensionValue = (byte[]) value;
      DerInputStream str = new DerInputStream(this.extensionValue);
      DerValue[] seq = str.getSequence(2);

      // NB. this is always encoded with the IMPLICIT tag
      // The checks only make sense if we assume implicit tagging,
      // with explicit tagging the form is always constructed.
      for (int i = 0; i < seq.length; i++) {
         DerValue opt = seq[i];

         if (opt.isContextSpecific(TAG_BEFORE) &&
            !opt.isConstructed()) {
            if (notBefore != null) {
               throw new CertificateParsingException(
                  "Duplicate notBefore in PrivateKeyUsage.");
            }
            opt.resetTag(DerValue.tag_GeneralizedTime);
            str = new DerInputStream(opt.toByteArray());
            notBefore = str.getGeneralizedTime();

         } else if (opt.isContextSpecific(TAG_AFTER) &&
            !opt.isConstructed()) {
            if (notAfter != null) {
               throw new CertificateParsingException(
                  "Duplicate notAfter in PrivateKeyUsage.");
            }
            opt.resetTag(DerValue.tag_GeneralizedTime);
            str = new DerInputStream(opt.toByteArray());
            notAfter = str.getGeneralizedTime();
         } else
            throw new IOException("Invalid encoding of " +
               "PrivateKeyUsageExtension");
      }
   }

   /**
    * Return the printable string.
    */
   public String toString()
   {
      return (super.toString() +
         "PrivateKeyUsage: [\n" +
         ((notBefore == null) ? "" : "From: " + notBefore.toString() + ", ")
         + ((notAfter == null) ? "" : "To: " + notAfter.toString())
         + "]\n");
   }

   /**
    * Verify that that the current time is within the validity period.
    *
    * @throws CertificateExpiredException     if the certificate has expired.
    * @throws CertificateNotYetValidException if the certificate is not
    *                                         yet valid.
    */
   public void valid()
      throws CertificateNotYetValidException, CertificateExpiredException
   {
      Date now = new Date();
      valid(now);
   }

   /**
    * Verify that that the passed time is within the validity period.
    *
    * @throws CertificateExpiredException     if the certificate has expired
    *                                         with respect to the <code>Date</code> supplied.
    * @throws CertificateNotYetValidException if the certificate is not
    *                                         yet valid with respect to the <code>Date</code> supplied.
    */
   public void valid(Date now)
      throws CertificateNotYetValidException, CertificateExpiredException
   {
        /*
         * we use the internal Dates rather than the passed in Date
         * because someone could override the Date methods after()
         * and before() to do something entirely different.
         */
      if (notBefore.after(now)) {
         throw new CertificateNotYetValidException("NotBefore: " +
            notBefore.toString());
      }
      if (notAfter.before(now)) {
         throw new CertificateExpiredException("NotAfter: " +
            notAfter.toString());
      }
   }

   /**
    * Write the extension to the OutputStream.
    *
    * @param out the OutputStream to write the extension to.
    * @throws IOException on encoding errors.
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      if (extensionValue == null) {
         extensionId = PKIXExtensions.PrivateKeyUsage_Id;
         critical = false;
         encodeThis();
      }
      super.encode(tmp);
      out.write(tmp.toByteArray());
   }

   /**
    * Set the attribute value.
    *
    * @throws CertificateException on attribute handling errors.
    */
   public void set(String name, Object obj)
      throws CertificateException, IOException
   {
      if (!(obj instanceof Date)) {
         throw new CertificateException("Attribute must be of type Date.");
      }
      if (name.equalsIgnoreCase(NOT_BEFORE)) {
         notBefore = (Date) obj;
      } else if (name.equalsIgnoreCase(NOT_AFTER)) {
         notAfter = (Date) obj;
      } else {
         throw new CertificateException("Attribute name not recognized by"
            + " CertAttrSet:PrivateKeyUsage.");
      }
      encodeThis();
   }

   /**
    * Get the attribute value.
    *
    * @throws CertificateException on attribute handling errors.
    */
   public Object get(String name) throws CertificateException
   {
      if (name.equalsIgnoreCase(NOT_BEFORE)) {
         return (new Date(notBefore.getTime()));
      } else if (name.equalsIgnoreCase(NOT_AFTER)) {
         return (new Date(notAfter.getTime()));
      } else {
         throw new CertificateException("Attribute name not recognized by"
            + " CertAttrSet:PrivateKeyUsage.");
      }
   }

   /**
    * Delete the attribute value.
    *
    * @throws CertificateException on attribute handling errors.
    */
   public void delete(String name) throws CertificateException, IOException
   {
      if (name.equalsIgnoreCase(NOT_BEFORE)) {
         notBefore = null;
      } else if (name.equalsIgnoreCase(NOT_AFTER)) {
         notAfter = null;
      } else {
         throw new CertificateException("Attribute name not recognized by"
            + " CertAttrSet:PrivateKeyUsage.");
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
      elements.add(NOT_BEFORE);
      elements.add(NOT_AFTER);
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
