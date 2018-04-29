import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.io.Serializable;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

public class MyIdentityKeyStore implements IdentityKeyStore, Serializable {
    private final Map<Pair<String, Integer>, byte[]> trustedKeys = new HashMap<Pair<String, Integer>, byte[]>();

    private final byte[] identityKeyPair;
    private final int             localRegistrationId;

    public MyIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
        this.identityKeyPair     = identityKeyPair.serialize();
        this.localRegistrationId = localRegistrationId;
    }

    public IdentityKeyPair getIdentityKeyPair() {
        try {
            return new IdentityKeyPair(identityKeyPair);
        } catch (InvalidKeyException e) {
            return null;
        }
    }

    public int getLocalRegistrationId() {
        return localRegistrationId;
    }

    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        IdentityKey existing = null;
        try {
            byte[] tmp = trustedKeys.get(new Pair<String, Integer>(address.getName(), address.getDeviceId()));
            if (tmp != null)
                existing = new IdentityKey(tmp,0);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        if (!identityKey.equals(existing)) {
            trustedKeys.put(new Pair<String, Integer>(address.getName(), address.getDeviceId()), identityKey.serialize());
            return true;
        } else {
            return false;
        }
    }

    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        byte[] trusted = trustedKeys.get(new Pair<String, Integer>(address.getName(), address.getDeviceId()));
        try {
            return (trusted == null || (new IdentityKey(trusted,0)).equals(identityKey));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }
}
