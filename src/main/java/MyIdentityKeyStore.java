import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.IdentityKeyStore;

import java.util.HashMap;
import java.util.Map;

public class MyIdentityKeyStore implements IdentityKeyStore {
    private final Map<SignalProtocolAddress, IdentityKey> trustedKeys = new HashMap<SignalProtocolAddress, IdentityKey>();

    private final IdentityKeyPair identityKeyPair;
    private final int             localRegistrationId;

    public MyIdentityKeyStore(IdentityKeyPair identityKeyPair, int localRegistrationId) {
        this.identityKeyPair     = identityKeyPair;
        this.localRegistrationId = localRegistrationId;
    }

    public IdentityKeyPair getIdentityKeyPair() {
        return identityKeyPair;
    }

    public int getLocalRegistrationId() {
        return localRegistrationId;
    }

    public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        IdentityKey existing = trustedKeys.get(address);

        if (!identityKey.equals(existing)) {
            trustedKeys.put(address, identityKey);
            return true;
        } else {
            return false;
        }
    }

    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
        IdentityKey trusted = trustedKeys.get(address);
        return (trusted == null || trusted.equals(identityKey));
    }
}
