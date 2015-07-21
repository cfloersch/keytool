package xpertss.crypto;

import org.junit.Test;
import xpertss.crypto.pkcs.ContentInfo;
import xpertss.crypto.pkcs.PKCS7;
import xpertss.crypto.pkcs.SignerInfo;
import xpertss.crypto.x509.AlgorithmId;

import javax.net.ssl.*;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * Created by cfloersch on 1/20/2015.
 */
public class PullSSLCertChain {

   public void pullSimulcastSSLCertChain() throws Exception
   {
      SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, new TrustManager[]{
         new X509TrustManager() {

            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
               return null;
            }

            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType)
            {
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType)
            {
               try {
                  PKCS7 pkcs = new PKCS7(new AlgorithmId[0], new ContentInfo(ContentInfo.DATA_OID, null),
                     certs, new SignerInfo[0]);
                  Path store = Paths.get("manheim.p7b");
                  OutputStream out = Files.newOutputStream(store, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
                  pkcs.encodeSignedData(out);
                  out.close();
               } catch(Exception e) {
                  e.printStackTrace();
               }
            }
         }
      }, null);
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
      HttpsURLConnection.setDefaultHostnameVerifier(
         new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session)
            {
               return true;
            }
         });
      // HTTPS instead of raw SSL, so that -Dhttps.proxyHost and
      // -Dhttps.proxyPort can be used. Since we only go through
      // the handshake process, an HTTPS server is not needed.
      // This program should be able to deal with any SSL-based
      // network service.
      Exception ex = null;
      try {
         new URL("https://www.manheim.com").openConnection().connect();
      } catch (Exception e) {
         ex = e;
      }

   }


   // http://www.ietf.org/rfc/rfc3280.txt
   // CA Cert
   // Key usage: Certificate Signing, Off-line CRL Signing, CRL Signing(06)                (Critical)
   // BasicConstraints: Subject Type = CA, PathLen Constraint=None or some integer > 1     (Critical)
   // Certificate Policies
   // CRL Distribution Points

   // Some have key usage- Digital Signature and Non-Repudiation as well

   // I am going to try just the Key usage and basic constraints and see what happens
   // For me since all of our SSL certs will be signed by the root I can set the path length to 2 (aka root and entity certs)

   // looks like Authority Key Identifier extension is used to identify the public key the key
   // was signed by. In the case of a root cert it should be the same as Subject Key Identifier
   // Authority Key Identifier is optional on self-signed root certs but it is required on other
   // types of certs so that a certificate path may be generated.

   // Extended Key Usage is typically only used by end user certificates like code signing or ssl certs


   // For CA certs.
     // Authority Key identifier is the same as Subject Key identifier
     // Basic Constraints (critical), Subject Type=CA, Path Length=None
     // Key usage (critical), Certificate Signing, ?CRL Signing?

   // For SSL Keys
     // Authority Key identifier equals the Subject Key identifier of the signing CA cert
     // Basic Constraints (critical), Subject Type = End Entity, Path Length = None
     // Key usage (critical) Digital Signature, Key Encipherment (a0)
     // Subject Alternative Name (All the DNS names the cert is to be used by)
     // Enhanced Key Usage (Server Authentication, Client Authentication)  DO I REALLY WANT CLIENT AUTH???

   // Code  Signing
     // Authority Key identifier equals the Subject Key identifier of the signing CA cert
     // Basic Constraints (critical), Subject Type = End Entity, Path Length = None
     // Key usage (critical) Digital Signature (80)
     // Enhanced Key Usage (Code Singing)

   // Most have the following which I am not sure if I want to include (Are these just copied down the chain?)
     // CRL Distribution Points
     // Certificate Policies
     // Authority Information Access



}
