import java.security.*;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true TestKeyStores false
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true -Dorg.bouncycastle.fips.approved_only=true TestKeyStores true
*/
public class TestKeyStores {
    private static String [] approvedKeyStoreTypes = {
            "BCFKS",
            "JKS",
            "FIPS"
    };

    private static String [] otherKeyStoreTypes = {
            "PKCS12"
    };

    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        boolean approvedOnly = args.length == 1 && Boolean.parseBoolean(args[0]);
        if (approvedOnly) {
            assertKeyStoresPass(approvedKeyStoreTypes);
            assertKeyStoresFail(otherKeyStoreTypes);
        } else {
            assertKeyStoresPass(approvedKeyStoreTypes);
            assertKeyStoresPass(otherKeyStoreTypes);
        }
    }

    private static void assertKeyStoresPass(String [] storeTypes) throws NoSuchProviderException {
        int failureCount = 0;
        for (String type : storeTypes) {
            try {
                KeyStore ks = KeyStore.getInstance(type, "BCFIPS");
            } catch (KeyStoreException ks) {
                System.out.println("Unexpectedly failed: " + type + " " + ks);
                failureCount++;
            }
        }
        assertEquals(failureCount, 0, "One or more keystore types unexpectedly failed: ");
    }

    private static void assertKeyStoresFail(String [] storeTypes) throws NoSuchProviderException, KeyStoreException {
        int failureCount = 0;
        for (String type : storeTypes) {
            try {
                KeyStore ks = KeyStore.getInstance(type, "BCFIPS");
            } catch (KeyStoreException kse) {
                System.out.println("failed: " + type);
                failureCount ++;
            }
        }
        assertEquals(failureCount, storeTypes.length, "An unsupported keystore type unexpectedly passed: ");
    }
}
