import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestSignatureAlgorithms false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestSignatureAlgorithms true
*/

public class TestSignatureAlgorithms {

    private static String [] approvedAlgorithms = {
            "SHA1withDSA",
            "SHA224withDSA",
            "SHA256withDSA",
            "SHA384withDSA",
            "SHA512withDSA",
            "SHA512(224)withDSA",
            "SHA512(256)withDSA",
            "SHA3-224withDSA",
            "SHA3-256withDSA",
            "SHA3-384withDSA",
            "SHA3-512withDSA",
            "SHA1withECDSA",
            "SHA224withECDSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
            "SHA512(224)withECDSA",
            "SHA512(256)withECDSA",
            "SHA3-224withDSA",
            "SHA3-256withECDSA",
            "SHA3-384withECDSA",
            "SHA3-512withECDSA",
            "SHA1withRSA",
            "SHA224withRSA",
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA512(224)withRSA",
            "SHA512(256)withRSA",
            "SHA3-224withRSA",
            "SHA3-256withRSA",
            "SHA3-384withRSA",
            "SHA3-512withRSA",
            "SHA1withRSAandMGF1",
            "SHA1withRSA/PSS",
            "SHA224withRSAandMGF1",
            "SHA224withRSA/PSS",
            "SHA256withRSAandMGF1",
            "SHA256withRSA/PSS",
            "SHA384withRSAandMGF1",
            "SHA384withRSA/PSS",
            "SHA512withRSAandMGF1",
            "SHA512withRSA/PSS",
            "SHA512(224)withRSAandMGF1",
            "SHA512(224)withRSA/PSS",
            "SHA512(256)withRSAandMGF1",
            "SHA512(256)withRSA/PSS",
            "SHA3-224withRSAandMGF1",
            "SHA3-224withRSA/PSS",
            "SHA3-256withRSAandMGF1",
            "SHA3-256withRSA/PSS",
            "SHA3-384withRSAandMGF1",
            "SHA3-384withRSA/PSS",
            "SHA3-512withRSAandMGF1",
            "SHA3-512withRSA/PSS",
            "SHA1withRSA/X9.31",
            "SHA224withRSA/X9.31",
            "SHA256withRSA/X9.31",
            "SHA384withRSA/X9.31",
            "SHA512withRSA/X9.31",
            "SHA512(224)withRSA/X9.31",
            "SHA512(256)withRSA/X9.31"
    };

    private static String [] generalAlgorithms = {
            "SHA1withDDSA",
            "SHA224withDDSA",
            "SHA224withDDSA",
            "SHA384withDDSA",
            "SHA512withDDSA",
            "SHA512(224)withDDSA",
            "SHA512(256)withDDSA",
            "SHA3-224withDDSA",
            "SHA3-256withDDSA",
            "SHA3-384withDDSA",
            "SHA3-512withDDSA",
            "GOST3411withDSTU4145",
            "GOST3411withDSTU4145LE",
            "RipeMD160withECDSA",
            "SHA1withECDDSA",
            "SHA224withECDDSA",
            "SHA256withECDDSA",
            "SHA384withECDDSA",
            "SHA512withECDDSA",
            "SHA512(224)withECDDSA",
            "SHA512(256)withECDDSA",
            "SHA3-224withECDDSA",
            "SHA3-256withECDDSA",
            "SHA3-384withECDDSA",
            "SHA3-512withECDDSA",
            "Ed25519",
            "Ed448",
            "GOST3411withGOST3410",
            "GOST3411withECGOST3410",
            "SHA1withRSA/ISO9796-2",
            "SHA224withRSA/ISO9796-2",
            "SHA256withRSA/ISO9796-2",
            "SHA384withRSA/ISO9796-2",
            "SHA512withRSA/ISO9796-2",
            "SHA512(224)withRSA/ISO9796-2",
            "SHA512(256)withRSA/ISO9796-2",
            "RIPEMD128withRSA/ISO9796-2",
            "RIPEMD160withRSA/ISO9796-2",
            "SHA1withRSA/ISO9796-2PSS",
            "SHA224withRSA/ISO9796-2PSS",
            "SHA256withRSA/ISO9796-2PSS",
            "SHA384withRSA/ISO9796-2PSS",
            "SHA512withRSA/ISO9796-2PSS",
            "SHA512(224)withRSA/ISO9796-2PSS",
            "SHA512(256)withRSA/ISO9796-2PSS",
            "RIPEMD128withRSA/ISO9796-2PSS",
            "RIPEMD160withRSA/ISO9796-2PSS",
            "MD5withRSA",
            "RIPEMD128withRSA",
            "RIPEMD160withRSA",
            "RIPEMD256withRSA",
            "RIPEMD128withRSA/X9.31",
            "RIPEMD160withRSA/X9.31",
            "WhirlpoolwithRSA/X9.31"
    };

    private static void assertAllowed(String [] algos) throws NoSuchProviderException {
        int failureCount = 0;

        for (String algo : algos) {
            try {
                Signature sign = Signature.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nsae) {
                failureCount++;
            }
        }
        assertEquals(failureCount, 0, "Some allowed algorithm/s was/were not permitted: ");
    }

    private static void assertNotAllowed(String [] algos) throws NoSuchProviderException {
        int failureCount = 0;

        for (String algo : algos) {
            try {
                Signature sign = Signature.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nsae) {
                failureCount++;
            }
        }
        assertEquals(failureCount, algos.length, "Some allowed algorithm/s was/were not permitted: ");
    }

    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        boolean approvedOnly = args.length == 1 && Boolean.parseBoolean(args[0]);
        if (approvedOnly) {
            assertAllowed(approvedAlgorithms);
            assertNotAllowed(generalAlgorithms);
        } else {
            assertAllowed(approvedAlgorithms);
            assertAllowed(generalAlgorithms);
        }
    }
}
