import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestKeyTransportAlgorithms BCFIPS false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestKeyTransportAlgorithms BCFIPS true
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

    public void testFunction(String algo, String provider) throws NoSuchAlgorithmException, NoSuchProviderException { 
        SecretKeyFactory c = SecretKeyFactory.getInstance(algo, provider);
    }
}
