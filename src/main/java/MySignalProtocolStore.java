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

import java.util.List;

public class MySignalProtocolStore implements SignalProtocolStore {

    private final MyPreKeyStore       preKeyStore       = new MyPreKeyStore();
    private final MySessionStore      sessionStore      = new MySessionStore();
    private final MySignedPreKeyStore signedPreKeyStore = new MySignedPreKeyStore();

    private final MyIdentityKeyStore  identityKeyStore;

    public MySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
        this.identityKeyStore = new MyIdentityKeyStore(identityKeyPair, registrationId);
    }

    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyStore.getIdentityKeyPair();
    }

    public int getLocalRegistrationId() {
        return identityKeyStore.getLocalRegistrationId();
    }

    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        return identityKeyStore.saveIdentity(address, identityKey);
    }

    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
    }

    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        return preKeyStore.loadPreKey(preKeyId);
    }

    public void storePreKey(int preKeyId, PreKeyRecord record) {
        preKeyStore.storePreKey(preKeyId, record);
    }

    public boolean containsPreKey(int preKeyId) {
        return preKeyStore.containsPreKey(preKeyId);
    }

    public void removePreKey(int preKeyId) {
        preKeyStore.removePreKey(preKeyId);
    }

    public SessionRecord loadSession(SignalProtocolAddress address) {
        return sessionStore.loadSession(address);
    }

    public List<Integer> getSubDeviceSessions(String name) {
        return sessionStore.getSubDeviceSessions(name);
    }

    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        sessionStore.storeSession(address, record);
    }

    public boolean containsSession(SignalProtocolAddress address) {
        return sessionStore.containsSession(address);
    }

    public void deleteSession(SignalProtocolAddress address) {
        sessionStore.deleteSession(address);
    }

    public void deleteAllSessions(String name) {
        sessionStore.deleteAllSessions(name);
    }

    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
    }

    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        return signedPreKeyStore.loadSignedPreKeys();
    }

    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
    }

    public boolean containsSignedPreKey(int signedPreKeyId) {
        return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
    }

    public void removeSignedPreKey(int signedPreKeyId) {
        signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
    }

    //TODO zbavit sa tohoto

    public MySignalProtocolStore() {
        this(generateIdentityKeyPair(), generateRegistrationId());
    }

    private static IdentityKeyPair generateIdentityKeyPair() {
        ECKeyPair identityKeyPairKeys = Curve.generateKeyPair();

        return new IdentityKeyPair(new IdentityKey(identityKeyPairKeys.getPublicKey()),
                identityKeyPairKeys.getPrivateKey());
    }

    private static int generateRegistrationId() {
        return KeyHelper.generateRegistrationId(false);
    }


}

