package xpertss.crypto.x509;

import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * This interface defines the methods required of a certificate attribute.
 * Examples of X.509 certificate attributes are Validity, Issuer_Name, and
 * Subject Name. A CertAttrSet may comprise one attribute or many
 * attributes.
 * <p/>
 * A CertAttrSet itself can also be comprised of other sub-sets.
 * In the case of X.509 V3 certificates, for example, the "extensions"
 * attribute has subattributes, such as those for KeyUsage and
 * AuthorityKeyIdentifier.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @see CertificateException
 */
public interface CertAttrSet<T> {
   /**
    * Returns a short string describing this certificate attribute.
    *
    * @return value of this certificate attribute in
    * printable form.
    */
   String toString();

   /**
    * Encodes the attribute to the output stream in a format
    * that can be parsed by the <code>decode</code> method.
    *
    * @param out the OutputStream to encode the attribute to.
    * @throws CertificateException on encoding or validity errors.
    * @throws IOException          on other errors.
    */
   void encode(OutputStream out)
      throws CertificateException, IOException;

   /**
    * Sets an attribute value within this CertAttrSet.
    *
    * @param name the name of the attribute (e.g. "x509.info.key")
    * @param obj  the attribute object.
    * @throws CertificateException on attribute handling errors.
    * @throws IOException          on other errors.
    */
   void set(String name, Object obj)
      throws CertificateException, IOException;

   /**
    * Gets an attribute value for this CertAttrSet.
    *
    * @param name the name of the attribute to return.
    * @throws CertificateException on attribute handling errors.
    * @throws IOException          on other errors.
    */
   Object get(String name)
      throws CertificateException, IOException;

   /**
    * Deletes an attribute value from this CertAttrSet.
    *
    * @param name the name of the attribute to delete.
    * @throws CertificateException on attribute handling errors.
    * @throws IOException          on other errors.
    */
   void delete(String name)
      throws CertificateException, IOException;

   /**
    * Returns an enumeration of the names of the attributes existing within
    * this attribute.
    *
    * @return an enumeration of the attribute names.
    */
   Enumeration<T> getElements();

   /**
    * Returns the name (identifier) of this CertAttrSet.
    *
    * @return the name of this CertAttrSet.
    */
   String getName();
}
