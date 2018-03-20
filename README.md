V prvom rade je dolezita trieda SignalProtocolAddress. Táto trieda ma na vstupe unikatny identifikator uzivatela(string)
a unikatny identifikator zariadenia(int). Tym padom je tato trieda schopna unikatne komunikujuce zariadenie(NIE
UZIVATELA!!!).

Ku kazdemu platnemu SignalProtocolAddress je potrebne mat na serveri ulozene 3 typi klucov:
 - identity key(pozostava s IdentityKey triedi(serializovatelna))
   Tento objekt sa install-time nahra na server a za standarnych okolnosit by sa nemal menit
 - signed pre-shared key(pozostava s identifikatora(int), public key(ECPublicKey trieda(serializovatelna)) a podpisu(byte[]))
   tento kluc je potrebne raz za cas(napr. raz za mesiac) znnova vygenerovat a nahrat na server novu verziu
 - one time key(pozostava s identifikatora(int) a public key(ECPublicKey trieda(serializovatelna)))
   server by vzdi mal mat v zasobe ulozenych viacero one time key. Vzdi ked si uzivatel vypita one time key
   nejakeho uzivatela, server by mu mal dat nahodny one-time key a vymazat ho so svojej databazi, aby sa vzdi pouzil
   nanajvis raz

Ak chce Alica poslat spravu Bobovi, potrebuje na to poznat jeho identity key, signed preshared key a jeden one time key.
Kedze dohromadi to tvori celkom slusnu kopku premennych, vznikla trieda PreKeyBundle. Jedinim ucelom tejto triedi je
zdruzovat vsetky kluce ktore su potrebne na komunikaciu(do konstruktoru sa jej daju jednotlive kluce, a potom ma
getteri, inak tato trieda nic viac nevie).

Od vas potrebujem naimplementovat tieto 4 metody:

```java
class Encryption {
    private SignalProtocolAddress myAddress;

    private void sendIdentityKey(IdentityKey key) {
        //Na vstupe ma serializovatelnu triedu IdentityKey a naviac ma k dispozicii membra myAddress ktory
        //obsahuje adresu aktualneho uzivatela. Ulohou tejto metodi je uloit address argument ako identity key daneho
        //uzivatela na serveri
    }

    private void sendSignedPrekey(Integer i, ECPublicKey key, byte[] signature) throws InvalidKeyException {
        //Na vstupe ma trojicu argumentov ktore spolu tvoria Signed prekey(identifikator daneho key, publick key
        //a podpis). Dalej ma k dispozicii membra myAddress. Ulohou tejto triedi je ulozit vsetky argumenti na server
        //ako signed pre key daneho uzivatela.
    }

    private void sendPrekey(List<Pair<Integer,ECPublicKey>> keys) {
        //Podobne ako predchadzajuce metodi, na vstupe je list one time keys(dvojica identifikator, public key).
        //Ulohou tejto metodi je appendnut tento zoznam na server do zoznamu one time keys
    }

    private PreKeyBundle getPrekeyBundle(SignalProtocolAddress address) {
        //Na vstupe je adresa uzivatela s ktorim chceme komunikovat. ulohou tejto metodi je ziskat so serveru kluce,
        //daneho uzivatela(identity, signed a jeden one time, ktori rovno vymaze). Tieto ziskane kluce dat ako argument
        //do triedi PreKeyBundle a vratit objekt tejto triedi.
    }
}
```

Dalej je potrebne aby sa raz za cas zavolala metoda rotateSingnedPreKey, a aby sa zavolala
metoda addOnetimePreKeys(int pocet) vzdi, ked dochadzaju one time keys na serveri. argument pocet hovori kolko novich
one time keys sa ma pridat.

V tomto momente je tieto metodi spolu s metodou sendIdentityKey nutne zavolat aj install time, ale ked sa naimplementuje
persistentne ulozisko privatnych klucov, tak tato povinnost odbudne.

Ukazka ako moze vyzerat, ked alica chce poslat zasifrovanu spravu bobovi.

```java

    SignalProtocolAddress alicina_adresa = SignalProtocolAddress("Alica", 1);
    SignalProtocolAddress bobova_adresa = SignalProtocolAddress("Bob", 1);


    //Alica posiela spravu
    Encryption alickaEnc = new Encryption(alicina_adresa); //Vytvori objekt encryption, ktora sa stara o vsetko spojene
                                                           //so sifrovanim. Potrebuje vediet svoju adresu.

    //V tomto momente je install-time potrebne zavolat tieto 3 metodi. V pribehu implementovania storage pre kluce
    //tato povinnost odbudne
    alickaEnc.sendIdentityKey();
    alickaEnc.rotateSingnedPreKey();
    alickaEnc.addOnetimePreKeys(10);

    String alicaMsgOutCl = "Ahoj, ja som ALica"; //Sprava ktoru chceme poslat
    byte[] alicaMsgOutCipher = alickaEnc.encrypt(bobova_adresa, alicaMsgOutCl.getBytes());  //Zasifruje spravu
    doruc_spravu_bobovi(alicaMsgOutCipher);   //Odosle spravu na server





    //Bob prima odpoved
    Encryption bobikEnc = new Encryption(bobova_adresa);//Vytvori objekt encryption, ktora sa stara o vsetko spojene
                                                        //so sifrovanim. Potrebuje vediet svoju adresu.

    byte[] msgIn = primi_spravu_od_alice(); //Prime spravu so serveru
    String bobMsgInCl = new String(bobikEnc.decrypt(alicina_adresa, msgIn));  //desifruje spravu a prekonveruje ju
                                                                              //s byte[] na string
    System.out.printf("Bob dostal sprabu '%s'\n", bobMsgInCl);
```