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
public class TestKeyTransportAlgorithms extends TestAlgorithms {
    public TestKeyTransportAlgorithms() {
        super("Key Transport");
    }
 
    String [] getApprovedAlgorithms() {
        return new String[] {
            "RSA-KTS-KEM-KWS",
            "RSA-KTS-OAEP"
        };
    }

    String [] getGeneralAlgorithms() {
        return new String[] { };
    }

    public static void main(String [] args) throws Exception {
        new TestKeyTransportAlgorithms().runTest(args);
    }

    public void testFunction(String algo) throws NoSuchAlgorithmException, NoSuchProviderException { 
        SecretKeyFactory c = SecretKeyFactory.getInstance(algo, "BCFIPS");
    }
}
