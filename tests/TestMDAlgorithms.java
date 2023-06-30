import java.security.*;
import javax.crypto.*;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true TestMDAlgorithms false
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true -Dorg.bouncycastle.fips.approved_only=true TestMDAlgorithms true
*/

public class TestMDAlgorithms extends TestAlgorithms {

    public TestMDAlgorithms() {
        super("Message Digest");
    }

    String [] getApprovedAlgorithms() {
        return new String[] { 
            "SHA1",
            "SHA-1",
            "SHA224",
            "SHA-224",
            "SHA256",
            "SHA-256",
            "SHA384",
            "SHA-384",
            "SHA512",
            "SHA-512",
            "SHA512(224)",
            "SHA-512(224)",
            "SHA512(256)",
            "SHA-512(256)",
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
        };
    }

    
    String [] getGeneralAlgorithms() {
        return new String[] {
            "GOST3411",
            "RIPEMD128",
            "RIPEMD160",
            "RIPEMD256",
            "RIPEMD320",
            "Tiger",
            "Whirlpool"
        };
    }


    public static void main(String [] args) throws Exception {
        new TestMDAlgorithms().runTest(args);
    }

    void testFunction(String algo) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest.getInstance(algo, "BCFIPS");
    }
}
