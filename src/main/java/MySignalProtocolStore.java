import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.List;

public class MySignalProtocolStore implements SignalProtocolStore, KeyStore.Entry {

    private final MyPreKeyStore       preKeyStore       = new MyPreKeyStore();
    private final MySessionStore      sessionStore      = new MySessionStore();
    private final MySignedPreKeyStore signedPreKeyStore = new MySignedPreKeyStore();

    private final MyIdentityKeyStore  identityKeyStore;


    private static final String STORE_ENTRY_NAME = "JayPadIdentityStore";
    private static final KeyStore.ProtectionParameter STORE_PASSWD = new KeyStore.PasswordProtection("T0t0 j9 sup9r t@jné h9sl0!".toCharArray());


    public static MySignalProtocolStore getInstance() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableEntryException {
        KeyStore st = getKeyStore();
        if (st.containsAlias(STORE_ENTRY_NAME)) {
            return (MySignalProtocolStore)st.getEntry(STORE_ENTRY_NAME, STORE_PASSWD);
        }
        return new MySignalProtocolStore();
    }

    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyStore.getIdentityKeyPair();
    }

    public int getLocalRegistrationId() {
        return identityKeyStore.getLocalRegistrationId();
    }

    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        boolean ret = identityKeyStore.saveIdentity(address, identityKey);
        updateStorage();
        return ret;
    }

    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
    }

    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        return preKeyStore.loadPreKey(preKeyId);
    }

    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeyStore.storePreKey(preKeyId, record);
        updateStorage();
    }

    public boolean containsPreKey(int preKeyId) {
        return preKeyStore.containsPreKey(preKeyId);
    }

    public void removePreKey(int preKeyId) {
        preKeyStore.removePreKey(preKeyId);
        updateStorage();
    }

    public SessionRecord loadSession(SignalProtocolAddress address) {
        return sessionStore.loadSession(address);
    }

    public List<Integer> getSubDeviceSessions(String name) {
        return sessionStore.getSubDeviceSessions(name);
    }

    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessionStore.storeSession(address, record);
        updateStorage();
    }

    public boolean containsSession(SignalProtocolAddress address) {
        return sessionStore.containsSession(address);
    }

    public void deleteSession(SignalProtocolAddress address) {
        sessionStore.deleteSession(address);
        updateStorage();
    }

    public void deleteAllSessions(String name) {
        sessionStore.deleteAllSessions(name);
        updateStorage();
    }

    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
    }

    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return signedPreKeyStore.loadSignedPreKeys();
    }

    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
        updateStorage();
    }

    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
    }

    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
        updateStorage();
    }

    private MySignalProtocolStore() {
        this(generateIdentityKeyPair(), generateRegistrationId());
    }

    private MySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyStore = new MyIdentityKeyStore(identityKeyPair, registrationId);
    }

    private static IdentityKeyPair generateIdentityKeyPair() {
        ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

        return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                identityKeyPairKeys.getPrivateKey());
    }

    private static int generateRegistrationId() {
        return KeyHelper.generateRegistrationId(false);
    }

    private void updateStorage() {
        //TODO add exception handling
        KeyStore ks = null;
        try {
            ks = getKeyStore();
            ks.setEntry(STORE_ENTRY_NAME,this,STORE_PASSWD);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static KeyStore getKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }
}

