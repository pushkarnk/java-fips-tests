import java.util.HashSet; 
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyStoreException;
import java.security.GeneralSecurityException;
import java.security.Security;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

abstract public class TestAlgorithms {

    private String type;
    private boolean approvedOnly;

    public TestAlgorithms(String type) {
        this.type = type;
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public void runTest(String [] args) throws NoSuchProviderException {
        boolean approvedOnly = args.length == 1 && Boolean.parseBoolean(args[0]);
        if (approvedOnly) {
            assertAllPass(getApprovedAlgorithms());
            assertAllFail(getGeneralAlgorithms());
        } else {
            assertAllPass(getApprovedAlgorithms());
            assertAllPass(getGeneralAlgorithms());
        }
    }

    public void assertAllPass(String [] algorithms) throws NoSuchProviderException {
        HashSet<String> unexpectedFailures = new HashSet<>();
        for (String algo : algorithms) {
            try {
                testFunction(algo);
            } catch (NoSuchAlgorithmException nsae) {
                unexpectedFailures.add(algo);
            }
        }
        assertTrue(unexpectedFailures.isEmpty(),
                        "Creation of " + type + " unexpectedly failed for " + unexpectedFailures + ": "); 
    }

    public void assertAllFail(String [] algorithms) throws NoSuchProviderException {
        HashSet<String> unexpectedSuccesses = new HashSet<>();
        for (String algo : algorithms) {
            try {
                testFunction(algo);
                unexpectedSuccesses.add(algo);
            } catch (NoSuchAlgorithmException nsae) {
            }
        }
        assertTrue(unexpectedSuccesses.isEmpty(),
                        "Creation of " + type + " unexpectedly passed for " + unexpectedSuccesses + ": ");
    }

    abstract void testFunction(String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException;
    abstract String[] getApprovedAlgorithms();
    abstract String[] getGeneralAlgorithms();
}

