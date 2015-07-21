package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Enumeration;

import xpertss.crypto.util.*;

/**
 * Represent the Key Usage Extension.
 * <p/>
 * <p>This extension, if present, defines the purpose (e.g., encipherment,
 * signature, certificate signing) of the key contained in the certificate.
 * The usage restriction might be employed when a multipurpose key is to be
 * restricted (e.g., when an RSA key should be used only for signing or only
 * for key encipherment).
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see Extension
 * @see CertAttrSet
 */
public class KeyUsageExtension extends Extension implements CertAttrSet<String> {

   /**
    * Identifier for this attribute, to be used with the
    * get, set, delete methods of Certificate, x509 type.
    */
   public static final String IDENT = "x509.info.extensions.KeyUsage";
   /**
    * Attribute names.
    */
   public static final String NAME = "KeyUsage";
   public static final String DIGITAL_SIGNATURE = "digital_signature";
   public static final String NON_REPUDIATION = "non_repudiation";
   public static final String KEY_ENCIPHERMENT = "key_encipherment";
   public static final String DATA_ENCIPHERMENT = "data_encipherment";
   public static final String KEY_AGREEMENT = "key_agreement";
   public static final String KEY_CERTSIGN = "key_certsign";
   public static final String CRL_SIGN = "crl_sign";
   public static final String ENCIPHER_ONLY = "encipher_only";
   public static final String DECIPHER_ONLY = "decipher_only";

   // Private data members
   private boolean[] bitString;

   // Encode this extension value
   private void encodeThis() throws IOException
   {
      DerOutputStream os = new DerOutputStream();
      os.putTruncatedUnalignedBitString(new BitArray(this.bitString));
      this.extensionValue = os.toByteArray();
   }

   /**
    * Check if bit is set.
    *
    * @param position the position in the bit string to check.
    */
   private boolean isSet(int position)
   {
      return bitString[position];
   }

   /**
    * Set the bit at the specified position.
    */
   private void set(int position, boolean val)
   {
      // enlarge bitString if necessary
      if (position >= bitString.length) {
         boolean[] tmp = new boolean[position + 1];
         System.arraycopy(bitString, 0, tmp, 0, bitString.length);
         bitString = tmp;
      }
      bitString[position] = val;
   }

   /**
    * Create a KeyUsageExtension with the passed bit settings. The criticality
    * is set to true.
    *
    * @param bitString the bits to be set for the extension.
    */
   public KeyUsageExtension(byte[] bitString) throws IOException
   {
      this.bitString =
         new BitArray(bitString.length * 8, bitString).toBooleanArray();
      this.extensionId = PKIXExtensions.KeyUsage_Id;
      this.critical = true;
      encodeThis();
   }

   /**
    * Create a KeyUsageExtension with the passed bit settings. The criticality
    * is set to true.
    *
    * @param bitString the bits to be set for the extension.
    */
   public KeyUsageExtension(boolean[] bitString) throws IOException
   {
      this.bitString = bitString;
      this.extensionId = PKIXExtensions.KeyUsage_Id;
      this.critical = true;
      encodeThis();
   }

   /**
    * Create a KeyUsageExtension with the passed bit settings. The criticality
    * is set to true.
    *
    * @param bitString the bits to be set for the extension.
    */
   public KeyUsageExtension(BitArray bitString) throws IOException
   {
      this.bitString = bitString.toBooleanArray();
      this.extensionId = PKIXExtensions.KeyUsage_Id;
      this.critical = true;
      encodeThis();
   }

   /**
    * Create the extension from the passed DER encoded value of the same.
    * The DER encoded value may be wrapped in an OCTET STRING.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value (possibly
    *                 wrapped in an OCTET STRING).
    * @throws ClassCastException if value is not an array of bytes
    * @throws IOException        on error.
    */
   public KeyUsageExtension(Boolean critical, Object value)
      throws IOException
   {
      this.extensionId = PKIXExtensions.KeyUsage_Id;
      this.critical = critical.booleanValue();
        /*
         * The following check should be activated again after
         * the PKIX profiling work becomes standard and the check
         * is not a barrier to interoperability !
         * if (!this.critical) {
         *   throw new IOException("KeyUsageExtension not marked critical,"
         *                         + " invalid profile.");
         * }
         */
      byte[] extValue = (byte[]) value;
      if (extValue[0] == DerValue.tag_OctetString) {
         this.extensionValue = new DerValue(extValue).getOctetString();
      } else {
         this.extensionValue = extValue;
      }
      DerValue val = new DerValue(this.extensionValue);
      this.bitString = val.getUnalignedBitString().toBooleanArray();
   }

   /**
    * Create a default key usage.
    */
   public KeyUsageExtension()
   {
      extensionId = PKIXExtensions.KeyUsage_Id;
      critical = true;
      bitString = new boolean[0];
   }

   /**
    * Set the attribute value.
    */
   public void set(String name, Object obj) throws IOException
   {
      if (!(obj instanceof Boolean)) {
         throw new IOException("Attribute must be of type Boolean.");
      }
      boolean val = ((Boolean) obj).booleanValue();
      if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
         set(0, val);
      } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
         set(1, val);
      } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
         set(2, val);
      } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
         set(3, val);
      } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
         set(4, val);
      } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
         set(5, val);
      } else if (name.equalsIgnoreCase(CRL_SIGN)) {
         set(6, val);
      } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
         set(7, val);
      } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
         set(8, val);
      } else {
         throw new IOException("Attribute name not recognized by"
            + " CertAttrSet:KeyUsage.");
      }
      encodeThis();
   }

   /**
    * Get the attribute value.
    */
   public Object get(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
         return Boolean.valueOf(isSet(0));
      } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
         return Boolean.valueOf(isSet(1));
      } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
         return Boolean.valueOf(isSet(2));
      } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
         return Boolean.valueOf(isSet(3));
      } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
         return Boolean.valueOf(isSet(4));
      } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
         return Boolean.valueOf(isSet(5));
      } else if (name.equalsIgnoreCase(CRL_SIGN)) {
         return Boolean.valueOf(isSet(6));
      } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
         return Boolean.valueOf(isSet(7));
      } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
         return Boolean.valueOf(isSet(8));
      } else {
         throw new IOException("Attribute name not recognized by"
            + " CertAttrSet:KeyUsage.");
      }
   }

   /**
    * Delete the attribute value.
    */
   public void delete(String name) throws IOException
   {
      if (name.equalsIgnoreCase(DIGITAL_SIGNATURE)) {
         set(0, false);
      } else if (name.equalsIgnoreCase(NON_REPUDIATION)) {
         set(1, false);
      } else if (name.equalsIgnoreCase(KEY_ENCIPHERMENT)) {
         set(2, false);
      } else if (name.equalsIgnoreCase(DATA_ENCIPHERMENT)) {
         set(3, false);
      } else if (name.equalsIgnoreCase(KEY_AGREEMENT)) {
         set(4, false);
      } else if (name.equalsIgnoreCase(KEY_CERTSIGN)) {
         set(5, false);
      } else if (name.equalsIgnoreCase(CRL_SIGN)) {
         set(6, false);
      } else if (name.equalsIgnoreCase(ENCIPHER_ONLY)) {
         set(7, false);
      } else if (name.equalsIgnoreCase(DECIPHER_ONLY)) {
         set(8, false);
      } else {
         throw new IOException("Attribute name not recognized by"
            + " CertAttrSet:KeyUsage.");
      }
      encodeThis();
   }

   /**
    * Returns a printable representation of the KeyUsage.
    */
   public String toString()
   {
      String s = super.toString() + "KeyUsage [\n";

      try {
         if (isSet(0)) {
            s += "  DigitalSignature\n";
         }
         if (isSet(1)) {
            s += "  Non_repudiation\n";
         }
         if (isSet(2)) {
            s += "  Key_Encipherment\n";
         }
         if (isSet(3)) {
            s += "  Data_Encipherment\n";
         }
         if (isSet(4)) {
            s += "  Key_Agreement\n";
         }
         if (isSet(5)) {
            s += "  Key_CertSign\n";
         }
         if (isSet(6)) {
            s += "  Crl_Sign\n";
         }
         if (isSet(7)) {
            s += "  Encipher_Only\n";
         }
         if (isSet(8)) {
            s += "  Decipher_Only\n";
         }
      } catch (ArrayIndexOutOfBoundsException ex) {
      }

      s += "]\n";

      return (s);
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
         this.extensionId = PKIXExtensions.KeyUsage_Id;
         this.critical = true;
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
      elements.add(DIGITAL_SIGNATURE);
      elements.add(NON_REPUDIATION);
      elements.add(KEY_ENCIPHERMENT);
      elements.add(DATA_ENCIPHERMENT);
      elements.add(KEY_AGREEMENT);
      elements.add(KEY_CERTSIGN);
      elements.add(CRL_SIGN);
      elements.add(ENCIPHER_ONLY);
      elements.add(DECIPHER_ONLY);

      return Collections.enumeration(elements);
   }


   public boolean[] getBits()
   {
      return bitString.clone();
   }

   /**
    * Return the name of this attribute.
    */
   public String getName()
   {
      return (NAME);
   }
}
