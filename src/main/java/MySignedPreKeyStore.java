import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class MySignedPreKeyStore implements SignedPreKeyStore, Serializable {

    private final Map<Integer, byte[]> store = new HashMap<Integer, byte[]>();

    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        try {
            if (!store.containsKey(signedPreKeyId)) {
                throw new InvalidKeyIdException("No such signedprekeyrecord! " + signedPreKeyId);
            }

            return new SignedPreKeyRecord(store.get(signedPreKeyId));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        try {
            List<SignedPreKeyRecord> results = new LinkedList<SignedPreKeyRecord>();

            for (byte[] serialized : store.values()) {
                results.add(new SignedPreKeyRecord(serialized));
            }

            return results;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        store.put(signedPreKeyId, record.serialize());
    }

    public boolean containsSignedPreKey(int signedPreKeyId) {
        return store.containsKey(signedPreKeyId);
    }

    public void removeSignedPreKey(int signedPreKeyId) {
        store.remove(signedPreKeyId);
    }
}

