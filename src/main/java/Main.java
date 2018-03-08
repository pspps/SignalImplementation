import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SessionBuilder;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.Medium;

import java.util.Random;


public class Main {
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("+14151231234", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("+14159998888", 1);

    private static final ECKeyPair aliceSignedPreKey = Curve.generateKeyPair();
    private static final ECKeyPair bobSignedPreKey   = Curve.generateKeyPair();

    private static final int aliceSignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
    private static final int bobSignedPreKeyId   = new Random().nextInt(Medium.MAX_VALUE);


    public static void main(String[] args) {
        System.out.println("Ahoj svet!");


        try {
            SignalProtocolStore aliceStore = new MySignalProtocolStore();
            SignalProtocolStore bobStore = new MySignalProtocolStore();

            PreKeyBundle alicePreKeyBundle = createAlicePreKeyBundle(aliceStore);
            PreKeyBundle bobPreKeyBundle = createBobPreKeyBundle(bobStore);

            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BOB_ADDRESS);
            SessionBuilder bobSessionBuilder = new SessionBuilder(bobStore, ALICE_ADDRESS);

            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BOB_ADDRESS);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, ALICE_ADDRESS);

            aliceSessionBuilder.process(bobPreKeyBundle);
            bobSessionBuilder.process(alicePreKeyBundle);

            CiphertextMessage messageForBob = aliceSessionCipher.encrypt("hey there".getBytes());
            CiphertextMessage messageForAlice = bobSessionCipher.encrypt("sample message".getBytes());

            byte[] alicePlaintext = aliceSessionCipher.decrypt(new PreKeySignalMessage(messageForAlice.serialize()));
            byte[] bobPlaintext = bobSessionCipher.decrypt(new PreKeySignalMessage(messageForBob.serialize()));

            System.out.printf("Alicka precitala spravu '%s'\n", new String(alicePlaintext));
            System.out.printf("Bob precitala spravu '%s'\n", new String(bobPlaintext));
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }
    }

    //TODO zbavit sa
    private static PreKeyBundle createAlicePreKeyBundle(SignalProtocolStore aliceStore) throws InvalidKeyException {
        ECKeyPair aliceUnsignedPreKey   = Curve.generateKeyPair();
        int       aliceUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[]    aliceSignature        = Curve.calculateSignature(aliceStore.getIdentityKeyPair().getPrivateKey(),
                aliceSignedPreKey.getPublicKey().serialize());

        PreKeyBundle alicePreKeyBundle = new PreKeyBundle(1, 1,
                aliceUnsignedPreKeyId, aliceUnsignedPreKey.getPublicKey(),
                aliceSignedPreKeyId, aliceSignedPreKey.getPublicKey(),
                aliceSignature, aliceStore.getIdentityKeyPair().getPublicKey());

        aliceStore.storeSignedPreKey(aliceSignedPreKeyId, new SignedPreKeyRecord(aliceSignedPreKeyId, System.currentTimeMillis(), aliceSignedPreKey, aliceSignature));
        aliceStore.storePreKey(aliceUnsignedPreKeyId, new PreKeyRecord(aliceUnsignedPreKeyId, aliceUnsignedPreKey));

        return alicePreKeyBundle;
    }

    private static PreKeyBundle createBobPreKeyBundle(SignalProtocolStore bobStore) throws InvalidKeyException {
        ECKeyPair bobUnsignedPreKey   = Curve.generateKeyPair();
        int       bobUnsignedPreKeyId = new Random().nextInt(Medium.MAX_VALUE);
        byte[]    bobSignature        = Curve.calculateSignature(bobStore.getIdentityKeyPair().getPrivateKey(),
                bobSignedPreKey.getPublicKey().serialize());

        PreKeyBundle bobPreKeyBundle = new PreKeyBundle(1, 1,
                bobUnsignedPreKeyId, bobUnsignedPreKey.getPublicKey(),
                bobSignedPreKeyId, bobSignedPreKey.getPublicKey(),
                bobSignature, bobStore.getIdentityKeyPair().getPublicKey());

        bobStore.storeSignedPreKey(bobSignedPreKeyId, new SignedPreKeyRecord(bobSignedPreKeyId, System.currentTimeMillis(), bobSignedPreKey, bobSignature));
        bobStore.storePreKey(bobUnsignedPreKeyId, new PreKeyRecord(bobUnsignedPreKeyId, bobUnsignedPreKey));

        return bobPreKeyBundle;
    }

}
