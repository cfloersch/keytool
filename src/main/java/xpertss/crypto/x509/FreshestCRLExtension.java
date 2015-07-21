package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * Represents the Freshest CRL Extension.
 * <p/>
 * <p/>
 * The extension identifies how delta CRL information for a
 * complete CRL is obtained.
 * <p/>
 * <p/>
 * The extension is defined in Section 5.2.6 of
 * <a href="http://www.ietf.org/rfc/rfc3280.txt">Internet X.509 PKI Certific
 * ate and Certificate Revocation List (CRL) Profile</a>.
 * <p/>
 * <p/>
 * Its ASN.1 definition is as follows:
 * <pre>
 *     id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 }
 *
 *     FreshestCRL ::= CRLDistributionPoints
 * </pre>
 *
 * @since 1.6
 */
public class FreshestCRLExtension extends CRLDistributionPointsExtension {

   /**
    * Attribute name.
    */
   public static final String NAME = "FreshestCRL";

   /**
    * Creates a freshest CRL extension.
    * The criticality is set to false.
    *
    * @param distributionPoints the list of delta CRL distribution points.
    */
   public FreshestCRLExtension(List<DistributionPoint> distributionPoints)
      throws IOException
   {

      super(PKIXExtensions.FreshestCRL_Id, false, distributionPoints, NAME);
   }

   /**
    * Creates the extension from the passed DER encoded value of the same.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws IOException on decoding error.
    */
   public FreshestCRLExtension(Boolean critical, Object value)
      throws IOException
   {
      super(PKIXExtensions.FreshestCRL_Id, critical.booleanValue(), value, NAME);
   }

   /**
    * Writes the extension to the DerOutputStream.
    *
    * @param out the DerOutputStream to write the extension to.
    * @throws IOException on encoding errors.
    */
   public void encode(OutputStream out) throws IOException
   {
      super.encode(out, PKIXExtensions.FreshestCRL_Id, false);
   }
}
