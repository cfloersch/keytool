package xpertss.crypto.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Enumeration;

import xpertss.crypto.util.*;

/**
 * This class defines the SerialNumber attribute for the Certificate.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see CertAttrSet
 */
public class CertificateSerialNumber implements CertAttrSet<String> {
   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.serialNumber";

   /**
    * Sub attributes name for this CertAttrSet.
    */
   public static final String NAME = "serialNumber";
   public static final String NUMBER = "number";

   private SerialNumber serial;

   /**
    * Default constructor for the certificate attribute.
    *
    * @param num the serial number for the certificate.
    */
   public CertificateSerialNumber(BigInteger num)
   {
      this.serial = new SerialNumber(num);
   }

   /**
    * Default constructor for the certificate attribute.
    *
    * @param num the serial number for the certificate.
    */
   public CertificateSerialNumber(int num)
   {
      this.serial = new SerialNumber(num);
   }

   /**
    * Create the object, decoding the values from the passed DER stream.
    *
    * @param in the DerInputStream to read the serial number from.
    * @throws IOException on decoding errors.
    */
   public CertificateSerialNumber(DerInputStream in) throws IOException
   {
      serial = new SerialNumber(in);
   }

   /**
    * Create the object, decoding the values from the passed stream.
    *
    * @param in the InputStream to read the serial number from.
    * @throws IOException on decoding errors.
    */
   public CertificateSerialNumber(InputStream in) throws IOException
   {
      serial = new SerialNumber(in);
   }

   /**
    * Create the object, decoding the values from the passed DerValue.
    *
    * @param val the DER encoded value.
    * @throws IOException on decoding errors.
    */
   public CertificateSerialNumber(DerValue val) throws IOException
   {
      serial = new SerialNumber(val);
   }

   /**
    * Return the serial number as user readable string.
    */
   public String toString()
   {
      if (serial == null) return "";
      return (serial.toString());
   }

   /**
    * Encode the serial number in DER form to the stream.
    *
    * @param out the DerOutputStream to marshal the contents to.
    * @throws IOException on errors.
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      serial.encode(tmp);

      out.write(tmp.toByteArray());
   }

   /**
    * Set the attribute value.
    */
   public void set(String name, Object obj) throws IOException
   {
      if (!(obj instanceof SerialNumber)) {
         throw new IOException("Attribute must be of type SerialNumber.");
      }
      if (name.equalsIgnoreCase(NUMBER)) {
         serial = (SerialNumber) obj;
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateSerialNumber.");
      }
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(NUMBER)) {
         return (serial);
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateSerialNumber.");
      }
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(NUMBER)) {
         serial = null;
      } else {
         throw new IOException("Attribute name not recognized by " +
            "CertAttrSet:CertificateSerialNumber.");
      }
   }

   /**
    * Return an enumeration of names of attributes existing within this
    * attribute.
    */
   public Enumeration<String> getElements()
   {
      AttributeNameEnumeration elements = new AttributeNameEnumeration();
      elements.add(NUMBER);
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
