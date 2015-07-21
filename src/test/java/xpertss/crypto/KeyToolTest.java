package xpertss.crypto;

import org.junit.Test;
import xpertss.crypto.pkcs.ContentInfo;
import xpertss.crypto.pkcs.PKCS7;
import xpertss.crypto.pkcs.SignerInfo;
import xpertss.crypto.x509.AlgorithmId;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Created by cfloersch on 1/7/2015.
 */
public class KeyToolTest {

   private static final String ALIAS = "test";
   private static final String PASSWD = "password";



   @Test
   public void testGenKeyPairDefaultStoreType() throws Exception
   {
      Path p = Paths.get("gentest.jks");
      try {

         String KEYALG = "RSA";
         PrintStream out = mock(PrintStream.class);
         String[] args = new String[]{
            "-genkeypair",
            "-keyalg", KEYALG,
            "-alias", ALIAS,
            "-keystore", p.toString(),
            "-storepass", PASSWD,
            "-keypass", PASSWD,
            "-validity", "360",
            "-keysize", "2048",
            "-dname", "CN=Chris, OU=Manheim Auctions, O=\"Manheim Remarketing, Inc.\", L=Atlanta, ST=GA, C=US"
         };

         KeyTool kt = new KeyTool();
         kt.run(args, out);

         verifyKey(p, "JKS", KEYALG);
         verify(out, never()).print("");
      } finally {
         Files.deleteIfExists(p);
      }
   }

   @Test
   public void testGenKeyPairPkcs12() throws Exception
   {
      Path p = Paths.get("gentest.pfx");
      try {

         String KEYALG = "RSA";
         PrintStream out = mock(PrintStream.class);
         String[] args = new String[]{
            "-genkeypair",
            "-keyalg", KEYALG,
            "-alias", ALIAS,
            "-keystore", p.toString(),
            "-storetype", "pkcs12",
            "-storepass", PASSWD,
            "-validity", "360",
            "-keysize", "2048",
            "-dname", "CN=Chris, OU=Manheim Auctions, O=\"Manheim Remarketing, Inc.\", L=Atlanta, ST=GA, C=US"
         };
         KeyTool kt = new KeyTool();
         kt.run(args, out);

         verifyKey(p, "PKCS12", KEYALG);
         verify(out, never()).print("");
      } finally {
         Files.deleteIfExists(p);
      }
   }





   private static void verifyKey(Path store, String type, String keyAlg) throws Exception
   {
      InputStream in = Files.newInputStream(store, StandardOpenOption.READ);
      KeyStore ks = KeyStore.getInstance(type);
      ks.load(in, PASSWD.toCharArray());

      if(!ks.containsAlias(ALIAS)) {
         throw new Error(ALIAS + " did not exist in keystore");
      }
      if(ks.entryInstanceOf(ALIAS, KeyStore.PrivateKeyEntry.class)) {
         Key key = ks.getKey(ALIAS, PASSWD.toCharArray());
         if(!key.getAlgorithm().equalsIgnoreCase(keyAlg)) {
            throw new Error("Keystore key was not an " + keyAlg + " key type");
         }
      } else {
         throw new Error("KeyStore did not contain a private key for alias " + ALIAS);
      }
   }



   @Test
   public void testGetCertificateChain() throws Exception
   {
      // Does a self signed key entry have a cert chain of size one,
      // size 0, or null
      Path store = Paths.get("src/test/resources/test.pfx");
      System.out.println(store.toAbsolutePath());
      InputStream in = Files.newInputStream(store, StandardOpenOption.READ);
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(in, PASSWD.toCharArray());
      Certificate[] ca_certs = keyStore.getCertificateChain(ALIAS);
      assertEquals(1, ca_certs.length);   // apparently it is size one.
   }





   private static void dump(Certificate input)
   {
      X509Certificate cert = (X509Certificate) input;
      System.out.println("Subject: " + cert.getSubjectX500Principal());
      System.out.println("Issuer: " + cert.getIssuerX500Principal());
   }
}
