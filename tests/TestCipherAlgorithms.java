import java.security.*;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


/*
  @test
  @library /jars/bc-fips-1.0.2.3.jar
  @library /jtreg/lib/testng-7.3.0.jar
  @run main/othervm TestCipherAlgorithms BCFIPS false
  @run main/othervm -Dorg.bouncycastle.fips.approved_only=true TestCipherAlgorithms BCFIPS true
*/

public class TestCipherAlgorithms extends TestAlgorithms {

    private static String [] approvedCiphers = {
            "AES/ECB", "AES/CBC", "AES/CFB8", "AES/CFB128",
            "AES/OFB", "AES/CTR", "AES/CCM", "AES/GCM",
            "DESEDE/ECB", "DESEDE/CBC", "DESEDE/CFB8", "DESEDE/CFB64",
            "DESEDE/OFB", "DESEDE/CTR"
    };

    private static String [] nonApprovedCiphers = {
            "AES/EAX", "AES/OCB", "AES/OpenPGPCFB",
            //"RC4/NONE", //TODO
            "BlowFish/CBC", "BlowFish/CFB8", "BlowFish/CFB64", "BlowFish/CTR",
            "BlowFish/EAX", "BlowFish/ECB", "BlowFish/OFB", "BlowFish/OpenPGPCFB",

            "Camellia/CBC", "Camellia/CCM", "Camellia/CFB8", "Camellia/CFB128",
            "Camellia/CTR", "Camellia/EAX", "Camellia/ECB", "Camellia/GCM",
            "Camellia/OCB", "Camellia/OFB",

            "CAST5/CBC", "CAST5/CFB8", "CAST5/CFB64", "CAST5/CTR", "CAST5/EAX",
            "CAST5/ECB", "CAST5/OFB", "CAST5/OpenPGPCFB",

            //"ChaCha20", //TODO 

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
            "TwoFish/OCB", "TwoFish/OFB",

    };

    private static String [] paddingsECB = {"NoPadding", "PKCS5Padding", "ISO10126-2Padding",
                                            "X9.23Padding", "ISO7816-4Padding", "TBCPadding"};

    private static String [] paddingsCBC = {"NoPadding", "PKCS5Padding", "ISO10126-2Padding", "ISO7816-4Padding", 
                                            "X9.23Padding", "TBCPadding", "CS1Padding", "CS2Padding", "CS3Padding" };

    

    public TestCipherAlgorithms() {
        super("Cipher(Symmetric/Public Key)");
    }
    
    public static void main(String [] args) throws Exception {
        new TestCipherAlgorithms().runTest(args);
    }

    void testFunction(String algo, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        try {
            Cipher.getInstance(algo, provider);
        } catch (NoSuchPaddingException nspe) {
            NoSuchAlgorithmException nsae = new NoSuchAlgorithmException(nspe);
            throw nsae; 
        }
    }

    String[] getApprovedAlgorithms() {
        ArrayList<String> list = new ArrayList<>();
        for (String cipher : approvedCiphers) {
            list.add(cipher + "/NoPadding");
            if (cipher.endsWith("ECB")) {
                for (String padding : paddingsECB) {
                    list.add(cipher + "/" + padding);
                }
            } else if (cipher.endsWith("CBC")) {
                for (String padding : paddingsCBC) {
                    list.add(cipher + "/" + padding);
                }
            }
        }
        return list.toArray(new String[list.size()]);
    }

    String[] getGeneralAlgorithms() {
        ArrayList<String> list = new ArrayList<>();
        for (String cipher : nonApprovedCiphers) {
            list.add(cipher + "/NoPadding");
            if (cipher.endsWith("ECB")) {
                for (String padding : paddingsECB) {
                    list.add(cipher + "/" + padding);
                }
            } else if (cipher.endsWith("CBC")) {
                for (String padding : paddingsCBC) {
                    list.add(cipher + "/" + padding);
                }
            }
        }

        // public key
        String [] paddings = { "OAEPwithSHA-1andMGF1Padding", "OAEPwithSHA-1andMGF1Padding", "OAEPwithSHA-1andMGF1Padding",
                               "OAEPwithSHA-1andMGF1Padding", "OAEPwithSHA-1andMGF1Padding", "PKCS1Padding" };


        // TODO: RSA/ECB, RSA/NONE should fail in approved_only mode, but they don't
        String [] generalAlgos = { "ElGamal/ECB", "ElGamal/NONE"/*, "RSA/ECB", "RSA/NONE" */ };
        for (String cipher : generalAlgos) {
            list.add(cipher + "/NoPadding");
            if (cipher.endsWith("ECB")) {
                for (String padding : paddings) {
                    list.add(cipher + "/" + padding);
                }
            }
        }
        return list.toArray(new String[list.size()]);
    }
}
