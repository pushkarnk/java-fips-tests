import java.security.*;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestDRBGAlgorithms BCFIPS true
*/
public class TestDRBGAlgorithms extends TestAlgorithms {

    public TestDRBGAlgorithms() {
        super("Deterministic Random Bit Generator");
    }

    String [] getApprovedAlgorithms() {
        return new String[] {
            "DEFAULT",
            "NONCEANDIV"
        };
    }

    String [] getGeneralAlgorithms() {
        return new String[] { };
    }

    void testFunction(String algo, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom.getInstance(algo, provider);
    }


    public static void main(String [] args) throws Exception {
        new TestDRBGAlgorithms().runTest(args);
    }
}

