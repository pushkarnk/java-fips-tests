import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true TestPBKeyDerivationFunctions false
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true -Dorg.bouncycastle.fips.approved_only=true TestPBKeyDerivationFunctions true
*/

public class TestPBKeyDerivationFunctions {
    private static String [] approvedAlgorithms = {
        "PBKDF2",
        "PBKDF2withHmacSHA1",
        "PBKDF2with8BIT",
        "PBKDF2withHmacSHA224",
        "PBKDF2withHmacSHA256",
        "PBKDF2withHmacSHA384",
        "PBKDF2withHmacSHA512"
    };

    private static String [] generalAlgorithms = {
        "PBKDF-OpenSSL",
        "PBKDF2withHmacGOST3411",
        "PBEwithSHA1andDES",
        "PBEwithMD5andDES",
        "PBEwithSHA1andRC2",
        "PBEwithMD5andRC2",
        "PBKDF-PKCS12",
        "PBKDF-PKCS12withSHA256",
        "PBEwithSHA1and40bitRC4",
        "PBEwithSHA1and128bitRC4",
        "PBEwithSHA1and40bitRC2",
        "PBEwithSHA1and128bitRC2",
        "PBEwithSHA1and2-KeyDESede",
        "PBEwithSHA1and3-KeyDESede",
        "PBEwithSHA1and128BitAES-BC",
        "PBEwithSHA1and192BitAES-BC",
        "PBEwithSHA1and256BitAES-BC",
        "PBEwithSHA256and128BitAES-BC",
        "PBEwithSHA256and192BitAES-BC",
        "PBEwithSHA256and256BitAES-BC"
    };

    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        boolean approvedOnly = args.length == 1 && Boolean.parseBoolean(args[0]);
        if (approvedOnly) {
            assertSuccess(approvedAlgorithms);
            assertFailure(generalAlgorithms);
        } else {
            assertSuccess(approvedAlgorithms);
            assertSuccess(generalAlgorithms);
        }
    }

    private static void assertSuccess(String [] algos) throws NoSuchProviderException {
        int failureCount = 0;
        for (String algo : algos) {
            try {
                SecretKeyFactory ks = SecretKeyFactory.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nae) {
                failureCount++;
            }
        }
        assertEquals(failureCount, 0, "One or more algorithm types unexpectedly failed: ");
    }

    private static void assertFailure(String [] algos) throws NoSuchProviderException {
        int failureCount = 0;
        for (String algo : algos) {
            try {
                SecretKeyFactory ks = SecretKeyFactory.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nae) {
                failureCount ++;
            }
        }
        assertEquals(failureCount, algos.length, "An unapproved algorithm unexpectedly passed: ");
    }
}
