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

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

public class MySignalProtocolStore implements SignalProtocolStore, Serializable {

    private final MyPreKeyStore       preKeyStore       = new MyPreKeyStore();
    private final MySessionStore      sessionStore      = new MySessionStore();
    private final MySignedPreKeyStore signedPreKeyStore = new MySignedPreKeyStore();

    private final MyIdentityKeyStore  identityKeyStore;


    private String STORE_FILENAME;

    public static MySignalProtocolStore getInstance() throws IOException, ClassNotFoundException {
        return getInstance("JayPadKeyStore");
    }

    //PUBLIC for test purposes only
    public static MySignalProtocolStore getInstance(String storeName) throws IOException, ClassNotFoundException {
        File f = new File(storeName);
        MySignalProtocolStore ret;
        if (f.exists()) {
            FileInputStream fis = new FileInputStream(f);
            ObjectInputStream is = new ObjectInputStream(fis);
            ret = (MySignalProtocolStore) is.readObject();
            is.close();
            fis.close();
            return ret;
        }
        ret = new MySignalProtocolStore(storeName);
        ret.updateStorage();
        return ret;
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

    private MySignalProtocolStore(String storeName) {
        this(generateIdentityKeyPair(), generateRegistrationId(), storeName);
    }

    private MySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId, String storeName) {
        this.STORE_FILENAME = storeName;
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
        File f = new File(STORE_FILENAME);
        FileOutputStream fout = null;
        //TODO exception handling
        try {
            fout = new FileOutputStream(f);
            ObjectOutputStream out = new ObjectOutputStream(fout);
            out.writeObject(this);
            out.close();
            fout.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

