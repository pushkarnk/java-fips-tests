import java.security.*;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true TestKeyStores BCFIPS false
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true -Dorg.bouncycastle.fips.approved_only=true TestKeyStores BCFIPS true
*/
public class TestKeyStores extends TestAlgorithms {

    public TestKeyStores() {
        super("Key Store");
    }

    String [] getApprovedAlgorithms() {
        return new String[] {
            "BCFKS",
            "JKS",
            "FIPS"
        };
    }

    String [] getGeneralAlgorithms() {
        return new String[] {
            "PKCS12"
        };
    }

    void testFunction(String algo, String provider) throws NoSuchProviderException, NoSuchAlgorithmException {
        try {
            KeyStore ks = KeyStore.getInstance(algo, provider);
        } catch (KeyStoreException kse) {
            throw (NoSuchAlgorithmException)(kse.getCause());
        }
    }

    public static void main(String [] args) throws Exception {
        new TestKeyStores().runTest(args);
    }
}
