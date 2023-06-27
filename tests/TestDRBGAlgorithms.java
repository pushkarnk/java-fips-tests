import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.*;

import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestDRBGAlgorithms
*/
public class TestDRBGAlgorithms {

    private static String [] approvedDRBGs = {
            "DEFAULT",
            "NONCEANDIV"
    };


    private static void assertAllowed(String [] algos) throws NoSuchProviderException {
        int failureCount = 0;

        for (String algo : algos) {
            try {
                SecureRandom s = SecureRandom.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nsae) {
                failureCount++;
            }
        }
        assertEquals(failureCount, 0, "Some allowed algorithm/s was/were not permitted: ");
    }


    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        assertAllowed(approvedDRBGs);
    }
}

