package xpertss.crypto.x509;

import java.io.IOException;

import xpertss.crypto.util.*;

/**
 * @author Ram Marti
 */

public final class AccessDescription {

   private int myhash = -1;

   private ObjectIdentifier accessMethod;

   private GeneralName accessLocation;

   public static final ObjectIdentifier Ad_OCSP_Id =
      ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 48, 1});

   public static final ObjectIdentifier Ad_CAISSUERS_Id =
      ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 48, 2});

   public static final ObjectIdentifier Ad_TIMESTAMPING_Id =
      ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 48, 3});

   public static final ObjectIdentifier Ad_CAREPOSITORY_Id =
      ObjectIdentifier.newInternal(new int[]{1, 3, 6, 1, 5, 5, 7, 48, 5});

   public AccessDescription(ObjectIdentifier accessMethod, GeneralName accessLocation)
   {
      this.accessMethod = accessMethod;
      this.accessLocation = accessLocation;
   }

   public AccessDescription(DerValue derValue) throws IOException
   {
      DerInputStream derIn = derValue.getData();
      accessMethod = derIn.getOID();
      accessLocation = new GeneralName(derIn.getDerValue());
   }

   public ObjectIdentifier getAccessMethod()
   {
      return accessMethod;
   }

   public GeneralName getAccessLocation()
   {
      return accessLocation;
   }

   public void encode(DerOutputStream out) throws IOException
   {
      DerOutputStream tmp = new DerOutputStream();
      tmp.putOID(accessMethod);
      accessLocation.encode(tmp);
      out.write(DerValue.tag_Sequence, tmp);
   }

   public int hashCode()
   {
      if (myhash == -1) {
         myhash = accessMethod.hashCode() + accessLocation.hashCode();
      }
      return myhash;
   }

   public boolean equals(Object obj)
   {
      if (obj == null || (!(obj instanceof AccessDescription))) {
         return false;
      }
      AccessDescription that = (AccessDescription) obj;

      if (this == that) {
         return true;
      }
      return (accessMethod.equals(that.getAccessMethod()) &&
         accessLocation.equals(that.getAccessLocation()));
   }

   public String toString()
   {
      String method = null;
      if (accessMethod.equals(Ad_CAISSUERS_Id)) {
         method = "caIssuers";
      } else if (accessMethod.equals(Ad_CAREPOSITORY_Id)) {
         method = "caRepository";
      } else if (accessMethod.equals(Ad_TIMESTAMPING_Id)) {
         method = "timeStamping";
      } else if (accessMethod.equals(Ad_OCSP_Id)) {
         method = "ocsp";
      } else {
         method = accessMethod.toString();
      }
      return ("Method: " + method + ", " + accessLocation.toString());
   }
}
