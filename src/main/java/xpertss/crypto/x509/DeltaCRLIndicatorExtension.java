package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;

import xpertss.crypto.util.*;

/**
 * Represents the Delta CRL Indicator Extension.
 * <p/>
 * <p/>
 * The extension identifies a CRL as being a delta CRL.
 * Delta CRLs contain updates to revocation information previously distributed,
 * rather than all the information that would appear in a complete CRL.
 * The extension contains a CRL number that identifies the CRL, complete for a
 * given scope, that was used as the starting point in the generation of
 * this delta CRL.
 * <p/>
 * <p/>
 * The extension is defined in Section 5.2.4 of
 * <a href="http://www.ietf.org/rfc/rfc3280.txt">Internet X.509 PKI Certific
 * ate and Certificate Revocation List (CRL) Profile</a>.
 * <p/>
 * <p/>
 * Its ASN.1 definition is as follows:
 * <pre>
 *     id-ce-deltaCRLIndicator OBJECT IDENTIFIER ::= { id-ce 27 }
 *
 *     BaseCRLNumber ::= CRLNumber
 *     CRLNumber ::= INTEGER (0..MAX)
 * </pre>
 *
 * @since 1.6
 */
public class DeltaCRLIndicatorExtension extends CRLNumberExtension {

   /**
    * Attribute name.
    */
   public static final String NAME = "DeltaCRLIndicator";

   private static final String LABEL = "Base CRL Number";

   /**
    * Creates a delta CRL indicator extension with the integer value .
    * The criticality is set to true.
    *
    * @param crlNum the value to be set for the extension.
    */
   public DeltaCRLIndicatorExtension(int crlNum) throws IOException
   {
      super(PKIXExtensions.DeltaCRLIndicator_Id, true,
         BigInteger.valueOf(crlNum), NAME, LABEL);
   }

   /**
    * Creates a delta CRL indictor extension with the BigInteger value .
    * The criticality is set to true.
    *
    * @param crlNum the value to be set for the extension.
    */
   public DeltaCRLIndicatorExtension(BigInteger crlNum) throws IOException
   {
      super(PKIXExtensions.DeltaCRLIndicator_Id, true, crlNum, NAME, LABEL);
   }

   /**
    * Creates the extension from the passed DER encoded value of the same.
    *
    * @param critical true if the extension is to be treated as critical.
    * @param value    an array of DER encoded bytes of the actual value.
    * @throws ClassCastException if value is not an array of bytes
    * @throws IOException        on decoding error.
    */
   public DeltaCRLIndicatorExtension(Boolean critical, Object value)
      throws IOException
   {
      super(PKIXExtensions.DeltaCRLIndicator_Id, critical.booleanValue(),
         value, NAME, LABEL);
   }

   /**
    * Writes the extension to the DerOutputStream.
    *
    * @param out the DerOutputStream to write the extension to.
    * @throws IOException on encoding errors.
    */
   public void encode(OutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      super.encode(out, PKIXExtensions.DeltaCRLIndicator_Id, true);
   }
}
