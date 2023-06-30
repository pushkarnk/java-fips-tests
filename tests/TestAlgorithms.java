import java.util.HashSet; 
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyStoreException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Provider;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

abstract public class TestAlgorithms {

    private String type;
    private String providerName;
    private boolean approvedOnly;

    public TestAlgorithms(String type) {
        this.type = type;
    }

    public void runTest(String [] args) throws NoSuchProviderException {
        this.providerName = args[0];
        Security.addProvider(getProvider(this.providerName));
        boolean approvedOnly = args.length == 2 && Boolean.parseBoolean(args[1]);
        if (approvedOnly) {
            assertAllPass(getApprovedAlgorithms());
            assertAllFail(getGeneralAlgorithms());
        } else {
            assertAllPass(getApprovedAlgorithms());
            assertAllPass(getGeneralAlgorithms());
        }
    }

    private void assertAllPass(String [] algorithms) throws NoSuchProviderException {
        HashSet<String> unexpectedFailures = new HashSet<>();
        for (String algo : algorithms) {
            try {
                testFunction(algo, this.providerName);
            } catch (NoSuchAlgorithmException nsae) {
                unexpectedFailures.add(algo);
            }
        }
        assertTrue(unexpectedFailures.isEmpty(),
                        "Creation of " + type + " unexpectedly failed for " + unexpectedFailures + ": "); 
    }

    private void assertAllFail(String [] algorithms) throws NoSuchProviderException {
        HashSet<String> unexpectedSuccesses = new HashSet<>();
        for (String algo : algorithms) {
            try {
                testFunction(algo, this.providerName);
                unexpectedSuccesses.add(algo);
            } catch (NoSuchAlgorithmException nsae) {
            }
        }
        assertTrue(unexpectedSuccesses.isEmpty(),
                        "Creation of " + type + " unexpectedly passed for " + unexpectedSuccesses + ": ");
    }

    private Provider getProvider(String providerName) {
        if (providerName.equals("BCFIPS")) {
            return new BouncyCastleFipsProvider();
        }
        // TODO: handle this better?
        return null;
    }

    abstract void testFunction(String algorithm, String provider) throws NoSuchProviderException, NoSuchAlgorithmException;
    abstract String[] getApprovedAlgorithms();
    abstract String[] getGeneralAlgorithms();
}

