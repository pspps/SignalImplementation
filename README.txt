Jedna sa o aplikaciu JayPad( https://jaypad.io/ ). Je to viac menej chat, kde je potrebne doimplementov e2e sifrovanie
pomocou signal protokolu, aby spravca serveru nebol schopny citat komunikaciu vramci chatu.

Momentalne je implementacia postavena na unit testoch. V maine mam Alicku a Boba, ktori si vytvoria kluce
a poslu zasifrovanu spravu.

Pouziva sa signal protocol kniznicu
https://github.com/signalapp/libsignal-protocol-java

V readme ku kniznici je nieco popisane, ale velmi strucne a je tam kopa nedokumentovanych features

Najdolezitejsie je naimplementovat storages ktore su vypisane v sekcii "Building a session" v readme ku kniznici.
Momentalne je tam testovacia implementacia ktora si ich uklada len do pamete(My*Store triedi, ukradnute s kniznice),
to treba prerobit na persistentnu pamet. Idealne by bolo private keys ulozit pomocou niecoho kompatibilneho
s API androidu pre ukladanie private keys(Android by mal mat nieco aby sa k tomu ine aplikacie nedostali).
Aj kebi to bolo ulozene len nejak lokalne, stale treba perzistentnejsiu storage ako memory.

Dalej je otazka akym sposobom sa maju distribuovat public keys. Ta testovacia implementacia vyuziva nejaky PreKeyBundle,
ale neviem do akej mieri je dobri napad to nechat v tej triede a co vsetko vlastne treba zdielat,
a co je najdolezitejsie, ci to staci proste raz odoslat a nechat to tam alebo to treba raz za cas zmenit
po nejakom pocte sprav/seansi. To by bolo idealne urobit nejakych 1M testovacich seansi po 1M sprav a sledovat ci to
bude funkgovat bo ci nje.

Co sa tika samotnej distribucie, to riesit netreba, len treba nechat nejake metodi ktore sa doimplementuju na strane
splikacie ze stiahnutPubKeys a odoslatPubKeys, ale tie implementovat netreba.

V principe, treba urobit nejaku triedu ktora bude mat par metod ze zavolajMaInstallTime(ta by mala vytvorit storage
a vygenerovat kluce, pripadne ich poslat), potom ze zavolajMaNaVytvorenieSeansi, tej asi clovek podstrci public keys a
ona vytvori seansu, potom nieco kam sa asi da seansa a sprava a ono ju to zasifruje a vytvori seansu pri prijatu spravu
a desifruje ju desifruje. Nasledne tam budu este 2 neimplementovane metodi ktore sa budu starat o zdielanie pubKeys.
Ta trieda moze vyzerat viac menej hociako, len je treba aby presla na review a mala by riesit vsetky situacie ktore bude
treba riesit vramci sifrovania v tej aplikacii.