import java.security.*;
import javax.crypto.*;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import static org.testng.Assert.assertEquals;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true TestMACAlgorithms false
  @run main/othervm -Dorg.bouncycastle.jca.enable_jks=true -Dorg.bouncycastle.fips.approved_only=true TestMACAlgorithms true
*/

public class TestMACAlgorithms {
    private static String [] approvedAlgorithms = {
        "CCMMAC",
	"AESCCMMAC",
        "AES-CCMMAC",
        "CMAC",
        "AES-CMAC",
        "AESCMAC",
        "GMAC",
        "AES-GMAC",
        "AESGMAC",
        "HmacSHA1",
        "Hmac128SHA1",
        "HmacSHA224",
        "Hmac128SHA224",
        "HmacSHA256",
        "Hmac128SHA256",
        "HmacSHA384",
        "Hmac256SHA384",
        "HmacSHA512",
        "Hmac256SHA512",
        "HmacSHA512(224)",
        "Hmac128SHA512(224)",
        "HmacSHA512(256)",
        "Hmac128SHA512(256)",
        "HmacSHA3-224",
        "HmacSHA3-256",
        "HmacSHA3-384",
        "HmacSHA3-512",
        "DESedeCMAC",
        "DESede-CMAC"
    };

    
    private static String [] generalAlgorithms = {
        "BlowfishCMAC",
        "Blowfish-CMAC",
        "CamelliaCCMMAC",
        "Camellia-CCMMAC",
        "CamelliaCMAC",
        "Camellia-CMAC",
        "CamelliaGMAC",
        "Camellia-GMAC",
        "CAST5CMAC",
        "CAST5-CMAC",
        "DESMAC",
        "DESMAC/CFB8",
        "DESMAC64",
        "DESMAC64WITHISO7816-4PADDING",
        "ISO9797ALG3MAC",
        "ISO9797ALG3WITHISO7816-4PADDING",
        "GOST28147MAC",
        "HmacGOST3411",
        "HmacRIPEMD128",
        "HmacRIPEMD160",
        "HmacRIPEMD256",
        "HmacRIPEMD320",
        "HmacTiger", 
        "HmacWhirlpool",
        "IDEACMAC",
        "IDEA-CMAC",
        "IDEAMAC",
        "IDEAMAC/CFB8",
        "Poly1305",
        "SEEDCCMMAC",
        "SEED-CCMMAC",
        "SEEDCMAC",
        "SEED-CMAC",
        "SEEDGMAC",
        "SEED-GMAC",
        "SerpentCCMMAC",
        "Serpent-CCMMAC",
        "SerpentCMAC",
        "Serpent-CMAC",
        "SerpentGMAC",
        "Serpent-GMAC",
        "SHACAL-2CMAC",
        "SHACAL-2-CMAC",
        "DESedeMAC",
        "DESedeMAC/CFB8",
        "DESedeMAC64",
        "DESedeMAC64withISO7816-4Padding",
        "TwofishCCMMAC",
        "Twofish-CCMMAC",
        "TwofishCMAC",
        "Twofish-CMAC",
        "TwofishGMAC",
        "Twofish-GMAC"
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
                Mac mc = Mac.getInstance(algo, "BCFIPS");
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
                Mac mac = Mac.getInstance(algo, "BCFIPS");
            } catch (NoSuchAlgorithmException nae) {
                failureCount ++;
            }
        }
        assertEquals(failureCount, algos.length, "An unapproved algorithm unexpectedly passed: ");
    }
}
