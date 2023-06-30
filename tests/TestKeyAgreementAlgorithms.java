import javax.crypto.KeyAgreement;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestKeyAgreementAlgorithms false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestKeyAgreementAlgorithms true
*/


public class TestKeyAgreementAlgorithms extends TestAlgorithms {
    String [] getApprovedAlgorithms() {
        return new String[] {
            "DH",
            "DHwithSHA1KDF",
            "DHwithSHA224KDF",
            "DHwithSHA256KDF",
            "DHwithSHA384KDF",
            "DHwithSHA512KDF",
            "DHwithSHA512(224)KDF",
            "DHwithSHA512(256)KDF",
            "DHwithSHA1CKDF",
            "DHwithSHA224CKDF",
            "DHwithSHA256CKDF",
            "DHwithSHA384CKDF",
            "DHwithSHA512CKDF",
            "DHwithSHA512(224)CKDF",
            "DHwithSHA512(256)CKDF",
            "DHwithSHA3-224CKDF",
            "DHwithSHA3-256CKDF",
            "DHwithSHA3-384CKDF",
            "DHwithSHA3-512CKDF",
            "DHUwithSHA1KDF",
            "DHUwithSHA224KDF",
            "DHUwithSHA256KDF",
            "DHUwithSHA384KDF",
            "DHUwithSHA512KDF",
            "DHUwithSHA512(224)KDF",
            "DHUwithSHA512(256)KDF",
            "DHUwithSHA1CKDF",
            "DHUwithSHA224CKDF",
            "DHUwithSHA256CKDF",
            "DHUwithSHA384CKDF",
            "DHUwithSHA512CKDF",
            "DHUwithSHA512(224)CKDF",
            "DHUwithSHA512(256)CKDF",
            "DHUwithSHA3-224CKDF",
            "DHUwithSHA3-256CKDF",
            "DHUwithSHA3-384CKDF",
            "DHUwithSHA3-512CKDF",
            "MQVwithSHA1KDF",
            "MQVwithSHA224KDF",
            "MQVwithSHA256KDF",
            "MQVwithSHA384KDF",
            "MQVwithSHA512KDF",
            "MQVwithSHA512(224)KDF",
            "MQVwithSHA512(256)KDF",
            "MQVwithSHA1CKDF",
            "MQVwithSHA224CKDF",
            "MQVwithSHA256CKDF",
            "MQVwithSHA384CKDF",
            "MQVwithSHA512CKDF",
            "MQVwithSHA512(224)CKDF",
            "MQVwithSHA512(256)CKDF",
            "ECDH",
            "ECDHwithSHA1KDF",
            "ECDHwithSHA224KDF",
            "ECDHwithSHA256KDF",
            "ECDHwithSHA384KDF",
            "ECDHwithSHA512KDF",
            "ECCDH",
            "ECCDHwithSHA1KDF",
            "ECCDHwithSHA224KDF",
            "ECCDHwithSHA256KDF",
            "ECCDHwithSHA384KDF",
            "ECCDHwithSHA512KDF",
            "ECCDHwithSHA512(224)KDF",
            "ECCDHwithSHA512(256)KDF",
            "ECCDHwithSHA1KDF",
            "ECCDHwithSHA224CKDF",
            "ECCDHwithSHA256CKDF",
            "ECCDHwithSHA384CKDF",
            "ECCDHwithSHA512CKDF",
            "ECCDHwithSHA512(224)CKDF",
            "ECCDHwithSHA512(256)CKDF",
            "ECCDHwithSHA3-224CKDF",
            "ECCDHwithSHA3-256CKDF",
            "ECCDHwithSHA3-384CKDF",
            "ECCDHwithSHA3-512CKDF",
            "ECCDHUwithSHA1KDF",
            "ECCDHUwithSHA224KDF",
            "ECCDHUwithSHA256KDF",
            "ECCDHUwithSHA384KDF",
            "ECCDHUwithSHA512KDF",
            "ECCDHwithSHA512(224)CKDF",
            "ECCDHwithSHA512(256)CKDF",
            "ECCDHUwithSHA1KDF",
            "ECCDHUwithSHA224CKDF",
            "ECCDHUwithSHA256CKDF",
            "ECCDHUwithSHA384CKDF",
            "ECCDHUwithSHA512CKDF",
            "ECCDHUwithSHA512(224)CKDF",
            "ECCDHUwithSHA512(256)CKDF",
            "ECCDHUwithSHA3-224CKDF",
            "ECCDHUwithSHA3-256CKDF",
            "ECCDHUwithSHA3-384CKDF",
            "ECCDHUwithSHA3-512CKDF",
            "ECMQV",
            "ECMQVwithSHA1KDF",
            "ECMQVwithSHA224KDF",
            "ECMQVwithSHA256KDF",
            "ECMQVwithSHA384KDF",
            "ECMQVwithSHA512KDF",
            "ECMQVwithSHA1KDF",
            "ECMQVwithSHA224CKDF",
            "ECMQVwithSHA256CKDF",
            "ECMQVwithSHA384CKDF",
            "ECMQVwithSHA512CKDF",
            "ECMQVwithSHA512(224)CKDF",
            "ECMQVwithSHA512(256)CKDF"
        };
    }

    String [] getGeneralAlgorithms() {
        return new String[] {
            "X448",
            "X25519"
        };
    }

    public TestKeyAgreementAlgorithms() {
        super("Key Agreement");
    }

    public void testFunction(String algo) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyAgreement.getInstance(algo, "BCFIPS");
    }

    public static void main(String [] args) throws Exception {
        new TestKeyAgreementAlgorithms().runTest(args);
    }

}

