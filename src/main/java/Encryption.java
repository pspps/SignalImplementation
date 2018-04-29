import org.whispersystems.libsignal.*;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.*;

public class Encryption {
    private SignalProtocolStore store;
    private SignalProtocolAddress myAddress;

    private static Map<SignalProtocolAddress, IdentityKey> identityKeys = new HashMap<SignalProtocolAddress, IdentityKey>();
    private static Map<SignalProtocolAddress, Pair<Integer,Pair<ECPublicKey,byte[]>>> signedKeys = new HashMap<SignalProtocolAddress, Pair<Integer, Pair<ECPublicKey, byte[]>>>();
    private static Map<SignalProtocolAddress, List<PreKeyBundle>> oneTimeKeys = new HashMap<SignalProtocolAddress, List<PreKeyBundle>>();

    public Encryption(SignalProtocolAddress myAdress) throws IOException, ClassNotFoundException {
        store = MySignalProtocolStore.getInstance();
        this.myAddress = myAdress;
    }

    public void sendIdentityKey() {
        //Needs to be called install time
        sendIdentityKey(store.getIdentityKeyPair().getPublicKey());
    }

    public void rotateSingnedPreKey() throws InvalidKeyException {
        //Needs to be called periodicly
        int prekeyId;
        do {
            prekeyId = new Random().nextInt(Medium.MAX_VALUE);
        } while (store.containsSignedPreKey(prekeyId));

        SignedPreKeyRecord signedPreKey  = KeyHelper.generateSignedPreKey(store.getIdentityKeyPair(), prekeyId);
        store.storeSignedPreKey(prekeyId,signedPreKey);
        sendSignedPrekey(prekeyId, signedPreKey.getKeyPair().getPublicKey(), Curve.calculateSignature(store.getIdentityKeyPair().getPrivateKey(), signedPreKey.getKeyPair().getPublicKey().serialize()));
    }

    public void addOnetimePreKeys(int numberOfNewKeys) {
        //Needs to be called when server lack of one time passwords
        List<Pair<Integer,ECPublicKey>> toSend = new LinkedList<Pair<Integer, ECPublicKey>>();
        for (int i = 0; i < numberOfNewKeys; i++) {
            int prekeyId;
            do {
                prekeyId = new Random().nextInt(Medium.MAX_VALUE);
            } while (store.containsPreKey(prekeyId));

            PreKeyRecord preKey = new PreKeyRecord(prekeyId, Curve.generateKeyPair());
            store.storePreKey(prekeyId, preKey);
            toSend.add(new Pair<Integer, ECPublicKey>(prekeyId, preKey.getKeyPair().getPublicKey()));
        }
        sendPrekey(toSend);
    }

    public byte[] encrypt(SignalProtocolAddress address, byte[] message) throws UntrustedIdentityException, InvalidKeyException {
        if (!store.containsSession(address)) {
            SessionBuilder sessionBuilder = new SessionBuilder(store, address);
            sessionBuilder.process(getPrekeyBundle(address));
        }
        SessionCipher sessionCipher = new SessionCipher(store, address);

        return sessionCipher.encrypt(message).serialize();
    }

    public byte[] decrypt(SignalProtocolAddress address, byte[] message) throws LegacyMessageException, DuplicateMessageException, NoSessionException, UntrustedIdentityException, InvalidVersionException, InvalidKeyException, InvalidKeyIdException, InvalidMessageException {
        SessionCipher sessionCipher = new SessionCipher(store, address);

        try {
            PreKeySignalMessage parsedMessage = new PreKeySignalMessage(message);
            return sessionCipher.decrypt(parsedMessage);
        } catch (InvalidMessageException e) {
            SignalMessage parsedMessage = new SignalMessage(message);
            return sessionCipher.decrypt(parsedMessage);
        }
    }

    private PreKeyBundle getPrekeyBundle(SignalProtocolAddress address) {
        //TODO vratit so serveru


        return oneTimeKeys.get(address).remove(0);
    }

    private void sendIdentityKey(IdentityKey key) {
        //TODO implement me
        System.out.printf("Sending identity key to server\n");

        assert (!identityKeys.containsKey(myAddress));
        identityKeys.put(myAddress, key);
    }

    private void sendSignedPrekey(Integer i, ECPublicKey key, byte[] signature) throws InvalidKeyException {
        //TODO implement me
        System.out.printf("Sending signed pre key to server\n");

        if (signedKeys.containsKey(myAddress))
            signedKeys.remove(myAddress);
        Pair<ECPublicKey,byte[]> vnutorny = new Pair<ECPublicKey,byte[]>(key, signature);
        signedKeys.put(myAddress, new Pair<Integer,Pair<ECPublicKey,byte[]>>(i,vnutorny));
    }

    private void sendPrekey(List<Pair<Integer,ECPublicKey>> keys) {
        //TODO implement me
        System.out.printf("Sending signed pre key to server\n");

        List<PreKeyBundle> to_add = new LinkedList<PreKeyBundle>();

        Pair<Integer,Pair<ECPublicKey,byte[]>> signed = signedKeys.get(myAddress);

        for (Pair<Integer,ECPublicKey> key : keys) {
            PreKeyBundle n = new PreKeyBundle(store.getLocalRegistrationId(), myAddress.getDeviceId(), key.getLeft(), key.getRight(), signed.getLeft(), signed.getRight().getLeft(), signed.getRight().getRight(), store.getIdentityKeyPair().getPublicKey());
             to_add.add(n);
        }

        if (oneTimeKeys.containsKey(myAddress)) {
            oneTimeKeys.get(myAddress).addAll(to_add);
        }
        else {
            oneTimeKeys.put(myAddress, to_add);
        }
    }
}
