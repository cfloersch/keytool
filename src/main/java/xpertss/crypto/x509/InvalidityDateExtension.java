package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

import xpertss.crypto.util.*;

/**
 * From RFC 3280:
 * <p/>
 * The invalidity date is a non-critical CRL entry extension that
 * provides the date on which it is known or suspected that the private
 * key was compromised or that the certificate otherwise became invalid.
 * This date may be earlier than the revocation date in the CRL entry,
 * which is the date at which the CA processed the revocation.  When a
 * revocation is first posted by a CRL issuer in a CRL, the invalidity
 * date may precede the date of issue of earlier CRLs, but the
 * revocation date SHOULD NOT precede the date of issue of earlier CRLs.
 * Whenever this information is available, CRL issuers are strongly
 * encouraged to share it with CRL users.
 * <p/>
 * The GeneralizedTime values included in this field MUST be expressed
 * in Greenwich Mean Time (Zulu), and MUST be specified and interpreted
 * as defined in section 4.1.2.5.2.
 * <pre>
 * id-ce-invalidityDate OBJECT IDENTIFIER ::= { id-ce 24 }
 *
 * invalidityDate ::=  GeneralizedTime
 * </pre>
 *
 * @author Sean Mullan
 */
public class InvalidityDateExtension extends Extension implements CertAttrSet<String> {

   /**
    * Attribute name and Reason codes
    */
   public static final String NAME = "InvalidityDate";
   public static final String DATE = "date";

   private Date date;

   private void encodeThis() throws IOException
   {
      if (date == null) {
         this.extensionValue = null;
         return;
      }
      DerOutputStream dos = new DerOutputStream();
      dos.putGeneralizedTime(date);
      this.extensionValue = dos.toByteArray();
   }

   /**
    * Create a InvalidityDateExtension with the passed in date.
    * Criticality automatically set to false.
    *
    * @param date the invalidity date
    */
   public InvalidityDateExtension(Date date) throws IOException
   {
      this(false, date);
   }

   /**
    * Create a InvalidityDateExtension with the passed in date.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param date     the invalidity date
    */
   public InvalidityDateExtension(boolean critical, Date date)
      throws IOException
   {
      this.extensionId = PKIXExtensions.InvalidityDate_Id;
      this.critical = critical;
      this.date = date;
      encodeThis();
   }

   /**
    * Create the extension from the passed DER encoded value of the same.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws ClassCastException if value is not an array of bytes
    * @throws IOException        on error.
    */
   public InvalidityDateExtension(Boolean critical, Object value)
      throws IOException
   {
      this.extensionId = PKIXExtensions.InvalidityDate_Id;
      this.critical = critical.booleanValue();
      this.extensionValue = (byte[]) value;
      DerValue val = new DerValue(this.extensionValue);
      this.date = val.getGeneralizedTime();
   }

   /**
    * Set the attribute value.
    */
   public void set(String name, Object obj) throws IOException
   {
      if (!(obj instanceof Date)) {
         throw new IOException("Attribute must be of type Date.");
      }
      if (name.equalsIgnoreCase(DATE)) {
         date = (Date) obj;
      } else {
         throw new IOException
            ("Name not supported by InvalidityDateExtension");
      }
      encodeThis();
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DATE)) {
         if (date == null) {
            return null;
         } else {
            return (new Date(date.getTime()));    // clone
         }
      } else {
         throw new IOException
            ("Name not supported by InvalidityDateExtension");
      }
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DATE)) {
         date = null;
      } else {
         throw new IOException
            ("Name not supported by InvalidityDateExtension");
      }
      encodeThis();
   }

   /**
    * Returns a printable representation of the Invalidity Date.
    */
   public String toString()
   {
      return super.toString() + "    Invalidity Date: " + String.valueOf(date);
   }

   /**
    * Write the extension to the DerOutputStream.
    *
    * @param out the DerOutputStream to write the extension to
    * @throws IOException on encoding errors
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();

      if (this.extensionValue == null) {
         this.extensionId = PKIXExtensions.InvalidityDate_Id;
         this.critical = false;
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
      elements.add(DATE);
      return Collections.enumeration(elements);
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return NAME;
   }

   public static InvalidityDateExtension toImpl(java.security.cert.Extension ext)
      throws IOException
   {
      if (ext instanceof InvalidityDateExtension) {
         return (InvalidityDateExtension) ext;
      } else {
         return new InvalidityDateExtension
            (Boolean.valueOf(ext.isCritical()), ext.getValue());
      }
   }
}
