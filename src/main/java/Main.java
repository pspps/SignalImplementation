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

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;


public class Main {
    private static final SignalProtocolAddress BOB_ADDRESS   = new SignalProtocolAddress("Bobik", 1);
    private static final SignalProtocolAddress ALICE_ADDRESS = new SignalProtocolAddress("Alicka", 1);

    private static Encryption initUser(String storeName, SignalProtocolAddress nname) throws InvalidKeyException, IOException, ClassNotFoundException {
        Encryption ret = new Encryption(nname, storeName);
        ret.sendIdentityKey();
        ret.rotateSingnedPreKey();
        ret.addOnetimePreKeys(10);
        return ret;
    }

    private static void removeFile(String filename) {
        assert(new File(filename).delete());
    }

    public static void main(String[] args) {
        System.out.println("Ahoj svet!");


        try {
            final String TEST_NAME = "Test jednoduchej komunikacie";
            final String ALICA_STORENAME = "alicaStore.dat";
            final String BOB_STORENAME = "bobStore.dat";

            System.out.printf("Pustam test z názvom '%s'\n", TEST_NAME);

            Encryption alickaEnc = initUser(ALICA_STORENAME,ALICE_ADDRESS);
            Encryption bobikEnc = initUser(BOB_STORENAME,BOB_ADDRESS);







            String alicaMsgOutCl = "Ahoj, ja som ALica";
            byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl.getBytes());

            String bobMsgInCl = new String(bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher));
            assert (bobMsgInCl.equals(alicaMsgOutCl));


            String bobMsgOutCl = "Nazdar, ja som Bob";
            byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl.getBytes());

            String alicaMsgInCl = new String(alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher));
            assert (alicaMsgInCl.equals(bobMsgOutCl));






            System.out.printf("Skoncil test z názvom '%s'\n\n", TEST_NAME);

            removeFile(ALICA_STORENAME);
            removeFile(BOB_STORENAME);
            Encryption.cleanLocal();
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }


        try {
            final String TEST_NAME = "Test subeznej inicializacie";
            final String ALICA_STORENAME = "alicaStore.dat";
            final String BOB_STORENAME = "bobStore.dat";

            System.out.printf("Pustam test z názvom '%s'\n", TEST_NAME);

            Encryption alickaEnc = initUser(ALICA_STORENAME,ALICE_ADDRESS);
            Encryption bobikEnc = initUser(BOB_STORENAME,BOB_ADDRESS);







            String alicaMsgOutCl = "Ahoj, ja som ALica";
            byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl.getBytes());
            String bobMsgOutCl = "Nazdar, ja som Bob";
            byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl.getBytes());

            String bobMsgInCl = new String(bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher));
            assert (bobMsgInCl.equals(alicaMsgOutCl));


            String alicaMsgInCl = new String(alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher));
            assert (alicaMsgInCl.equals(bobMsgOutCl));






            System.out.printf("Skoncil test z názvom '%s'\n\n", TEST_NAME);

            removeFile(ALICA_STORENAME);
            removeFile(BOB_STORENAME);
            Encryption.cleanLocal();
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }




        try {
            final String TEST_NAME = "Test binarnych hodnot";
            final String ALICA_STORENAME = "alicaStore.dat";
            final String BOB_STORENAME = "bobStore.dat";

            System.out.printf("Pustam test z názvom '%s'\n", TEST_NAME);

            Encryption alickaEnc = initUser(ALICA_STORENAME,ALICE_ADDRESS);
            Encryption bobikEnc = initUser(BOB_STORENAME,BOB_ADDRESS);







            byte[] alicaMsgOutCl = new byte[256];
            byte it = 0;
            for (int i = 0; i < 256; i++) {
                alicaMsgOutCl[i] = it;
                it++;
            }
            byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl);

            byte[] bobMsgInCl = bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher);
            assert (Arrays.equals(bobMsgInCl,alicaMsgOutCl));

            byte[] bobMsgOutCl = new byte[256];
            it = (byte) 255;
            for (int i = 0; i < 256; i++) {
                bobMsgOutCl[i] = it;
                it--;
            }
            byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl);


            byte[] alicaMsgInCl = alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher);
            assert (Arrays.equals(alicaMsgInCl,bobMsgOutCl));






            System.out.printf("Skoncil test z názvom '%s'\n\n", TEST_NAME);

            removeFile(ALICA_STORENAME);
            removeFile(BOB_STORENAME);
            Encryption.cleanLocal();
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }

        System.out.printf("\n");
        System.out.printf("==========================\n");
        System.out.printf("Skalovacie testy\n");
        System.out.printf("==========================\n");
        System.out.printf("\n");



        try {
            final String TEST_NAME = "Test 128MB subor";
            final String ALICA_STORENAME = "alicaStore.dat";
            final String BOB_STORENAME = "bobStore.dat";
            //final int size =  256*1048576;
            final int size =  128*1024*1024;

            System.out.printf("Pustam test z názvom '%s'\n", TEST_NAME);
            long start = System.currentTimeMillis();

            Encryption alickaEnc = initUser(ALICA_STORENAME,ALICE_ADDRESS);
            Encryption bobikEnc = initUser(BOB_STORENAME,BOB_ADDRESS);







            byte[] alicaMsgOutCl = new byte[size];
            SecureRandom random = new SecureRandom();
            random.nextBytes(alicaMsgOutCl);
            byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl);

            byte[] bobMsgInCl = bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher);
            assert (Arrays.equals(bobMsgInCl,alicaMsgOutCl));

            byte[] bobMsgOutCl = new byte[size];
            random.nextBytes(bobMsgOutCl);
            byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl);


            byte[] alicaMsgInCl = alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher);
            assert (Arrays.equals(alicaMsgInCl,bobMsgOutCl));






            System.out.printf("Skoncil test z názvom '%s'\n\n", TEST_NAME);
            System.out.printf("Odhadovane trvanie '%d' milisekund\n\n", System.currentTimeMillis() - start);

            removeFile(ALICA_STORENAME);
            removeFile(BOB_STORENAME);
            Encryption.cleanLocal();
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }



        try {
            final String TEST_NAME = "Test 100k sprav";
            final String ALICA_STORENAME = "alicaStore.dat";
            final String BOB_STORENAME = "bobStore.dat";

            System.out.printf("Pustam test z názvom '%s'\n", TEST_NAME);
            long start = System.currentTimeMillis();

            Encryption alickaEnc = initUser(ALICA_STORENAME,ALICE_ADDRESS);
            Encryption bobikEnc = initUser(BOB_STORENAME,BOB_ADDRESS);






            for (int i = 0; i < 100000; i++) {
                String alicaMsgOutCl = "Ahoj, ja som ALica. Toto je sprava cislo '"+Integer.toString(i)+"'\n";
                byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl.getBytes());

                String bobMsgInCl = new String(bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher));
                assert (bobMsgInCl.equals(alicaMsgOutCl));

                if((i+1)%10000 == 0)
                    System.out.printf("Sekvencia cislo 1., Iteracia cislo %d.\n", i+1);

            }
            System.out.printf("Odhadovane trvanie 100k sprav od alice '%d' milisekund\n\n", System.currentTimeMillis() - start);
            start = System.currentTimeMillis();

            for (int i = 0; i < 100000; i++) {
                String bobMsgOutCl = "Nazdar, ja som Bob. Toto je sprava cislo '"+Integer.toString(i)+"'\n";
                byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl.getBytes());

                String alicaMsgInCl = new String(alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher));
                assert (alicaMsgInCl.equals(bobMsgOutCl));

                if((i+1)%10000 == 0)
                    System.out.printf("Sekvencia cislo 2., Iteracia cislo %d.\n", i+1);
            }
            System.out.printf("Odhadovane trvanie 100k sprav od boba '%d' milisekund\n\n", System.currentTimeMillis() - start);
            start = System.currentTimeMillis();

            for (int i = 0; i < 100000; i++) {
                String alicaMsgOutCl = "Ahoj, ja som ALica. Toto je sprava cislo '"+Integer.toString(i)+"'\n";
                byte[] alicaMsgOutCipher = alickaEnc.encrypt(BOB_ADDRESS, alicaMsgOutCl.getBytes());

                String bobMsgInCl = new String(bobikEnc.decrypt(ALICE_ADDRESS, alicaMsgOutCipher));
                assert (bobMsgInCl.equals(alicaMsgOutCl));


                String bobMsgOutCl = "Nazdar, ja som Bob. Toto je sprava cislo '"+Integer.toString(i)+"'\n";
                byte[] bobMsgOutCipher = bobikEnc.encrypt(ALICE_ADDRESS, bobMsgOutCl.getBytes());

                String alicaMsgInCl = new String(alickaEnc.decrypt(BOB_ADDRESS, bobMsgOutCipher));
                assert (alicaMsgInCl.equals(bobMsgOutCl));

                if((i+1)%10000 == 0)
                    System.out.printf("Sekvencia cislo 3., Iteracia cislo %d.\n", i+1);
            }

            System.out.printf("Odhadovane trvanie 100k sprav od od alice a naspet '%d' milisekund\n\n", System.currentTimeMillis() - start);
            start = System.currentTimeMillis();






            System.out.printf("Skoncil test z názvom '%s'\n\n", TEST_NAME);

            removeFile(ALICA_STORENAME);
            removeFile(BOB_STORENAME);
            Encryption.cleanLocal();
        }
        catch (Exception e) {
            System.out.printf("Nieco je velmi zle '%s'...\n", e.getMessage());
        }
    }
}
