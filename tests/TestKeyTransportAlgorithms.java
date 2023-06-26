import java.security.*;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestKeyTransportAlgorithms false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestKeyTransportAlgorithms true
*/
public class TestKeyTransportAlgorithms {
    private static String [] keyTransportAlgos = {
            "RSA-KTS-KEM-KWS",
            "RSA-KTS-OAEP"
    };

    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        assertKeyTransportPass(keyTransportAlgos);
    }

    private static void assertKeyTransportPass(String [] keyTransportAlgos) throws NoSuchProviderException, NoSuchPaddingException {
        int failureCount = 0;
        for (String algo : keyTransportAlgos) {
            try {
                SecretKeyFactory c = SecretKeyFactory.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException ks) {
                System.out.println("failed: " + algo);
                failureCount++;
            }
        }
        assertEquals(failureCount, 0, "One or more key transport algorithms unexpectedly failed: ");
    }
}
