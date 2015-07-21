package xpertss.crypto.util;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Interface to an object that knows how to write its own DER
 * encoding to an output stream.
 *
 * @author D. N. Hoover
 */
public interface DerEncoder {

   /**
    * DER encode this object and write the results to a stream.
    *
    * @param out the stream on which the DER encoding is written.
    */
   public void derEncode(OutputStream out)
      throws IOException;

}
