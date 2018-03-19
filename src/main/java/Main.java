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
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("Bobik", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("Alicka", 1);

    public static void main(String[] args) {
        System.out.println("Ahoj svet!");


        try {
            Encryption alickaEnc = new Encryption(ALICE_ADDRESS);
            Encryption bobikEnc = new Encryption(BOB_ADDRESS);

            alickaEnc.sendIdentityKey();
            alickaEnc.rotateSingnedPreKey();
            alickaEnc.addOnetimePreKeys(10);
            bobikEnc.sendIdentityKey();
            bobikEnc.rotateSingnedPreKey();
            bobikEnc.addOnetimePreKeys(10);

            String alicaMsgOutCl = "Ahoj, ja som ALica";
            byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl.getBytes());

            String bobMsgInCl = new String(bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher));
            System.out.printf("Bob dostal sprabu '%s'\n", bobMsgInCl);
            assert (bobMsgInCl == alicaMsgOutCl);


            String bobMsgOutCl = "Nazdar, ja som Bob";
            byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl.getBytes());

            String alicaMsgInCl = new String(alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher));
            System.out.printf("Alica dostala sprabu '%s'\n", alicaMsgInCl);
            assert (alicaMsgInCl == bobMsgOutCl);
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }
    }
}
