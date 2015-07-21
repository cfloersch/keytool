package xpertss.crypto.x509;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import xpertss.crypto.util.*;

/**
 * This class defines the certificate policy set ASN.1 object.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class CertificatePolicySet {

   private final List<CertificatePolicyId> ids;

   /**
    * The default constructor for this class.
    *
    * @param ids the sequence of CertificatePolicyId's.
    */
   public CertificatePolicySet(List<CertificatePolicyId> ids)
   {
      this.ids = ids;
   }

   /**
    * Create the object from the DerValue.
    *
    * @param in the passed DerInputStream.
    * @throws IOException on decoding errors.
    */
   public CertificatePolicySet(DerInputStream in) throws IOException
   {
      ids = new ArrayList<CertificatePolicyId>();
      DerValue[] seq = in.getSequence(5);

      for (int i = 0; i < seq.length; i++) {
         CertificatePolicyId id = new CertificatePolicyId(seq[i]);
         ids.add(id);
      }
   }

   /**
    * Return printable form of the object.
    */
   public String toString()
   {
      String s = "CertificatePolicySet:[\n"
         + ids.toString()
         + "]\n";

      return (s);
   }

   /**
    * Encode the policy set to the output stream.
    *
    * @param out the DerOutputStream to encode the data to.
    */
   public void encode(DerOutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();

      for (int i = 0; i < ids.size(); i++) {
         ids.get(i).encode(tmp);
      }
      out.write(DerValue.tag_Sequence, tmp);
   }

   /**
    * Return the sequence of CertificatePolicyIds.
    *
    * @return A List containing the CertificatePolicyId objects.
    */
   public List<CertificatePolicyId> getCertPolicyIds()
   {
      return Collections.unmodifiableList(ids);
   }
}
