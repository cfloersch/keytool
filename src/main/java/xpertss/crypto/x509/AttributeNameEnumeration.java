package xpertss.crypto.x509;


import java.util.ArrayList;

/**
 * <p>This class provides the Enumeration implementation used
 * by all the X509 certificate attributes to return the attribute
 * names contained within them.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class AttributeNameEnumeration extends ArrayList<String> {

   private static final long serialVersionUID = -6067440240757099134L;

   /**
    * The default constructor for this class.
    */
   public AttributeNameEnumeration()
   {
      super(4);
   }
}
