import java.security.*;
import java.util.HashSet;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;

/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestCiphers
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestCiphers true
 */
public class TestCiphers {

    private static String [] approvedCiphers = {
            "AES/ECB", "AES/CBC", "AES/CFB8", "AES/CFB128",
            "AES/OFB", "AES/CTR", "AES/CCM", "AES/GCM",
            "DESEDE/ECB", "DESEDE/CBC", "DESEDE/CFB8", "DESEDE/CFB64",
            "DESEDE/OFB", "DESEDE/CTR"
    };

    private static String [] nonApprovedCiphers = {
            "AES/EAX", "AES/OCB", "AES/OpenPGPCFB",
            //"ARC4/", "RC4/",
            "BlowFish/CBC", "BlowFish/CFB8", "BlowFish/CFB64", "BlowFish/CTR",
            "BlowFish/EAX", "BlowFish/ECB", "BlowFish/OFB", "BlowFish/OpenPGPCFB",

            "Camellia/CBC", "Camellia/CCM", "Camellia/CFB8", "Camellia/CFB128",
            "Camellia/CTR", "Camellia/EAX", "Camellia/ECB", "Camellia/GCM",
            "Camellia/OCB", "Camellia/OFB",

            "CAST5/CBC", "CAST5/CFB8", "CAST5/CFB64", "CAST5/CTR", "CAST5/EAX",
            "CAST5/ECB", "CAST5/OFB", "CAST5/OpenPGPCFB",

            //"ChaCha20",

            "DES/CBC", "DES/CFB8", "DES/CFB64", "DES/CTR", "DES/EAX", "DES/ECB",
            "DES/OFB", "DES/OpenPGPCFB",

            "GOST28147/CBC", "GOST28147/CFB8", "GOST28147/CFB64", "GOST28147/CTR",
            "GOST28147/EAX", "GOST28147/ECB", "GOST28147/GCFB", "GOST28147/GOFB",
            "GOST28147/OFB",

            "RC2/CBC", "RC2/CFB8", "RC2/CFB64", "RC2/CTR", "RC2/EAX", "RC2/ECB", "RC2/OFB",

            "SEED/CBC", "SEED/CCM", "SEED/CFB8", "SEED/CFB128", "SEED/CTR", "SEED/EAX",
            "SEED/ECB", "SEED/GCM", "SEED/OCB", "SEED/OFB",

            "SERPENT/CBC", "SERPENT/CCM", "SERPENT/CFB8", "SERPENT/CFB128", "SERPENT/CTR",
            "SERPENT/EAX", "SERPENT/ECB", "SERPENT/GCM", "SERPENT/GCM", "SERPENT/OFB",

            "SHACAL-2/CBC", "SHACAL-2/CFB8", "SHACAL-2/CFB256", "SHACAL-2/CTR",
            "SHACAL-2/EAX", "SHACAL-2/ECB", "SHACAL-2/OFB",

            "DESEDE/EAX", "DESEDE/OpenPGPCFB",

            "TwoFish/CBC", "TwoFish/CCM", "TwoFish/CFB8", "TwoFish/CFB128",
            "TwoFish/CTR", "TwoFish/EAX", "TwoFish/ECB", "TwoFish/GCM",
            "TwoFish/OCB", "TwoFish/OFB"
    };
    private static String [] paddings = {"NoPadding", "PKCS5Padding"};
    public static void main(String [] args) throws Exception {
        boolean approvedOnly = args.length == 1 && Boolean.parseBoolean(args[0]);
        Security.addProvider(new BouncyCastleFipsProvider());
        testApprovedNoPadding();
        testNonApprovedNoPadding(approvedOnly);
    }

    public static void testApprovedNoPadding() throws NoSuchProviderException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher c;
        for (String cipher : approvedCiphers) {
            Cipher.getInstance(cipher + "/NoPadding", "BCFIPS");
        }
    }

    public static void testNonApprovedNoPadding(boolean approvedOnly) throws NoSuchProviderException, NoSuchPaddingException {
        HashSet<String> algos = new HashSet<>();
        Cipher c;
        int failureCount = 0;
        for (String cipher : nonApprovedCiphers) {
            try {
                Cipher.getInstance(cipher + "/NoPadding", "BCFIPS");
            } catch (NoSuchAlgorithmException e) {
                algos.add(cipher);
                failureCount++;
            }
        }
        if (approvedOnly) {
            assertEquals(failureCount, nonApprovedCiphers.length, "Usage of a non-approved algorithm was permitted");
        } else {
            assertEquals(failureCount, 0, "Unexpected NoSuchAlgorithmException " + algos);
        }
    }
}
