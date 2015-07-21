package xpertss.crypto.x509;

import java.io.IOException;

import xpertss.crypto.util.*;


/**
 * Represent the CertificatePolicyId ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class CertificatePolicyId {
   private ObjectIdentifier id;

   /**
    * Create a CertificatePolicyId with the ObjectIdentifier.
    *
    * @param id the ObjectIdentifier for the policy id.
    */
   public CertificatePolicyId(ObjectIdentifier id)
   {
      this.id = id;
   }

   /**
    * Create the object from its Der encoded value.
    *
    * @param val the DER encoded value for the same.
    */
   public CertificatePolicyId(DerValue val) throws IOException
   {
      this.id = val.getOID();
   }

   /**
    * Return the value of the CertificatePolicyId as an ObjectIdentifier.
    */
   public ObjectIdentifier getIdentifier()
   {
      return (id);
   }

   /**
    * Returns a printable representation of the CertificatePolicyId.
    */
   public String toString()
   {
      return "CertificatePolicyId: [" + id.toString() + "]";
   }

   /**
    * Write the CertificatePolicyId to the DerOutputStream.
    *
    * @param out the DerOutputStream to write the object to.
    * @throws IOException on errors.
    */
   public void encode(DerOutputStream out) throws IOException
   {
      out.putOID(id);
   }

   /**
    * Compares this CertificatePolicyId with another, for
    * equality. Uses ObjectIdentifier.equals() as test for
    * equality.
    *
    * @return true iff the ids are identical.
    */
   public boolean equals(Object other)
   {
      if (other instanceof CertificatePolicyId)
         return id.equals(((CertificatePolicyId) other).getIdentifier());
      else
         return false;
   }

   /**
    * Returns a hash code value for this object.
    *
    * @return a hash code value
    */
   public int hashCode()
   {
      return id.hashCode();
   }
}
