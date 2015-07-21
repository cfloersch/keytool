package xpertss.crypto.util;

import java.util.Comparator;

public class ByteArrayTagOrder implements Comparator<byte[]> {

   /**
    * Compare two byte arrays, by the order of their tags,
    * as defined in ITU-T X.680, sec. 6.4.  (First compare
    * tag classes, then tag numbers, ignoring the constructivity bit.)
    *
    * @param bytes1 first byte array to compare.
    * @param bytes2 second byte array to compare.
    * @return negative number if bytes1 < bytes2, 0 if bytes1 == bytes2,
    * positive number if bytes1 > bytes2.
    * @throws <code>ClassCastException</code> if either argument is not a byte array.
    */

   public final int compare(byte[] bytes1, byte[] bytes2)
   {
      // tag order is same as byte order ignoring any difference in
      // the constructivity bit (0x02)
      return (bytes1[0] | 0x20) - (bytes2[0] | 0x20);
   }


}
