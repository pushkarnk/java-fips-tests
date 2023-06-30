import java.security.*;
import javax.crypto.*;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestPBKeyDerivationFunctions BCFIPS false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestPBKeyDerivationFunctions BCFIPS true
*/

public class TestPBKeyDerivationFunctions extends TestAlgorithms {

    public TestPBKeyDerivationFunctions() {
        super("Password Based Key Derivation Functions");
    }

    String [] getApprovedAlgorithms() {
        return new String[] {
            "PBKDF2",
            "PBKDF2withHmacSHA1",
            "PBKDF2with8BIT",
            "PBKDF2withHmacSHA224",
            "PBKDF2withHmacSHA256",
            "PBKDF2withHmacSHA384",
            "PBKDF2withHmacSHA512"
        };
    }

    String [] getGeneralAlgorithms() {
        return new String[] {
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
    }

    public static void main(String [] args) throws Exception {
        new TestPBKeyDerivationFunctions().runTest(args);
    }

    void testFunction(String algo, String provider) throws NoSuchProviderException, NoSuchAlgorithmException {
        SecretKeyFactory.getInstance(algo, provider);
    }
}
