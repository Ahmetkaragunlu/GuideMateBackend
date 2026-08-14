# GuideMate Backend Calisma Kurallari

Bu dosya, backend gelistirmesi boyunca unutulmamasi gereken operasyonel
kurallarin ve ertelenen maddelerin kisa takip listesidir. Ayrintili domain ve API
kararlari icin ana kaynak:

`/Users/ahmetkaragunlu/AndroidStudioProjects/GuideMate/docs/backend-implementation-handoff.md`

Bir celiski olursa kullanicinin en son acik karari uygulanir. Android kaynak
kodu backend fazlarinda degistirilmez.

Faz 6 icin kullanicinin acikca onayladigi tek Android istisnasi Firebase
bootstrap konfigurasyonudur: ignore edilen `app/google-services.json`, Google
Services Gradle plugin'i, Firebase BoM/Messaging bagimliligi ve manifest
`POST_NOTIFICATIONS` izin bildirimi hazirlanabilir. Android Kotlin/Java servis,
Firebase Installation ID (FID) kaydi, notification channel/runtime permission,
repository, UI ve entegrasyon kodu backend tamamlandiktan sonraki Android
calismasina kalir. STOMP istemci bagimliligi da backend WebSocket sozlesmesi
kesinlestikten sonra secilir.

## Faz Kapsami

- Yalniz mevcut fazi dogrudan veya dolayli etkileyen kararlar ele alinir.
- Sonraki faza ait ve mevcut fazi etkilemeyen konu, zamani gelene kadar
  ertelenir; gecici kod veya sahte entegrasyon yazilmaz.
- Her feature migration'dan calisan API sozlesmesine kadar dikey tamamlanir.
- Sonraki faza gecmeden once mevcut fazin veri butunlugu, yetki, hata sozlesmesi,
  OpenAPI ve Android'in ihtiyac duydugu response alanlari kontrol edilir.
- Uygulanmis Flyway migration dosyalari degistirilmez; yeni sema degisikligi yeni
  surumlu migration olarak eklenir.

## Kod Kalitesi

- SOLID, dusuk bagimlilik, okunabilirlik, test edilebilirlik, dogru isimlendirme,
  feature-first paketleme ve gercek kod tekrarinin azaltilmasi hedeflenir.
- Sirf dosya uzun, tek bir benzerlik var veya ileride kullanilabilir diye yeni
  katman, interface, helper, base class ya da use-case eklenmez.
- Mevcut dogru mimari korunur; somut paket, katman, sorumluluk, bagimlilik veya
  tekrar sorunu varsa en kucuk davranis-koruyucu degisiklik yapilir.
- Yeni yazilan veya degisiklikten etkilenen her sinifin feature ve katman konumu
  kontrol edilir. Yanlis paket, katman veya bagimlilik yonu gorulurse kullaniciya
  somut nedeni ve onerilen yeni konumu acikca bildirilir; gerekli import, test ve
  konfigurasyonlar birlikte guncellenir.
- Paket ve sinif isimleri teknik ayrintidan once domain sorumlulugunu anlatir.
  Controller, DTO, mapper, service/application, repository, domain, config ve
  external adapter sinirlari birbirine karistirilmaz.
- Sinif veya metod yalniz satir sayisi nedeniyle mekanik olarak parcalanmaz.
  Ancak asiri uzunluk okunabilirligi, gezinmeyi veya davranisi anlamayi gercekten
  zorlastiriyorsa; dogal ve isimlendirilebilir sorumluluk sinirlarindan, yapay
  katman olusturmadan parcalanabilir.
- Mevcut auth paketlemesinde zorunlu bir katman hatasi bulunmamistir ve auth
  mimarisi korunur. `AuthServiceImpl` yalniz uzun oldugu icin bolunmez; daha da
  buyuyup okunabilirligi bozarsa ayrisabilen auth akislarina gore, davranis
  korunarak parcalanmasi yeniden degerlendirilir.
- JPA entity API'ye sizmaz. Controller HTTP sinirinda, service/application is
  kurali ve transaction sinirinda, repository persistence sinirinda kalir.
- Kod degisikligiyle tamamen bosa dusen ve bilincli ertelenmemis kod, paket,
  property ve log temizlenir.
- Secret, token, kart verisi, tam IBAN ve teknik exception ayrintisi source
  control'e, Android'e, response'a veya loglara girmez.

## Dis Bagimlilik Kontrolu

Her faz baslamadan once su gereksinimler kontrol edilip degerleri acik edilmeden
kullaniciya bildirilir:

- Harici hesap, urun yetkisi ve panel ayari
- API key, secret, service account ve client ID
- Local secret/environment property'leri
- Public callback/webhook URL, HTTPS ve ag erisimi
- Maven kutuphanesi ve surum uyumlulugu
- PostgreSQL, Docker, Testcontainers veya gerekli runtime
- Ucret, production etkisi, veri silme veya geri dondurulemez islem riski

Codex'in guvenle yapabilecegi kurulum kullaniciya birakilmaz. Kullanici yalniz
harici hesap erisimi, secret girisi veya riskli islem onayi gerektiginde devreye
girer.

## Test Politikasi

- Her fazda compile, Spring context, Flyway/migration ve ilgili OpenAPI/API
  sozlesmesi dogrulanir.
- Yalniz o an kod calisiyor mu diye daha sonra silinecek gecici testler
  uretilmez.
- Guvenlik, para, concurrency veya bulunan bir hatayi kalici olarak koruyan test
  gerekiyorsa bekletilmeden production regression testi olarak yazilabilir.
- Kapsamli kalici unit, controller, security, PostgreSQL/Testcontainers,
  concurrency, idempotency ve entegrasyon test paketi Faz 8'de tamamlanir.
- Proje sonunda tum testler taranir. Gercek is kurali, guvenlik, API sozlesmesi
  ve regression degeri olanlar korunur; tekrarlayan, gecersiz davranisi test
  eden, yalniz implementation detayina baglanan veya gecici olanlar kaldirilir.
- Test sayisi veya coverage yuzdesi tek basina hedef degildir; kritik davranisin
  guvenilir ve anlamli senaryolarla korunmasi esastir.

## Faz Durumu

- Faz 0 Android endpoint'i uretmez. Iyzico Card Storage/hosted save destegi
  destek cevabiyla dogrulanmis ve backend uygulamasi tamamlanmistir. Payout modu
  Marketplace/Mass Payout yetkisi olmadigi icin acikca `SIMULATED` olarak
  sabitlenmistir.
- Faz 1'in gerekli ortak backend temeli hazirdir: `UuidAuditedEntity`, ortak
  pagination response, method security altyapisi ve OpenAPI/JWT standardi.
- Faz 1 tek basina Android'in cagiracagi yeni business endpoint sunmaz. Yeni
  Android entegrasyon sozlesmesi Faz 2'de medya ve rehber profili API'leriyle
  baslar.
- Mevcut auth API'si bu fazlardan bagimsiz olarak korunur.
- Faz 2 backend kapsami tamamlanmistir: `V3` semasi, local `MediaStorage`, medya
  lifecycle/cleanup, owner-public erisim, rehber profili/dilleri/avatari,
  role-ownership kontrolleri ve OpenAPI sozlesmesi birlikte dogrulanmistir.
- Faz 3 backend kapsami tamamlanmistir: `V4` semasi, tur ve oturum lifecycle'i,
  yeni tur ve kritik degisiklik inceleme akisi, rehber yonetimi, admin onayi,
  public tur/rehber kesfi, dashboard, medya referanslari, yetki ve hata
  sozlesmeleri birlikte uygulanmistir.
- Faz 4 backend kapsami tamamlanmistir: `V5` rezervasyon/yorum semasi, `V6`
  rehber session iptal idempotency'si, seat hold ve kapasite kilidi, satin alma
  snapshot'i, turist gezi/detail/iptal API'leri, yorum uygunlugu, puan/populerlik
  sorgulari ve ortak `GuidePerformanceSummary` projection'i uygulanmistir.
- Faz 5 backend kod kapsami tamamlanmistir: `V7` payment/wallet/finance ve `V8`
  provider-backed saved-card semasi, iyzico Checkout Form
  initialize/retrieve/callback/webhook adapter'i, strict
  `X-IYZ-SIGNATURE-V3`, payment event ve reconciliation girisi, atomik wallet
  top-up/tur alimi, refund, guide earning, sifreli IBAN, banka hesabi ve
  `SIMULATED` withdrawal API'leri uygulanmistir. Public booking API gercek
  verified payment veya atomik wallet debit ile acilmistir. Saved-card listesi,
  silme ve varsayilan kart API'leri uygulanmistir; ham kart numarasi, SKT ve CVV
  GuideMate backend'ine gelmez, provider key/tokenlari sifreli saklanir.
- Faz 5'in `V7` ve `V8` kapsami test profili, OpenAPI ve local PostgreSQL
  uzerinde dogrulanmis; local sema `V8`'e gecmistir. Quick Tunnel uzerinden USD
  Checkout Form,
  callback/retrieve, basarili tek wallet credit ve basarisiz odemede credit
  olusmamasi Sandbox'ta dogrulanmistir. Iyzico destek ekibi
  `X-IYZ-SIGNATURE-V3` ozelligini hesapta aktif etmistir. Gercek imzali webhook,
  ilk kart kaydetme, maskeli listeleme, sonraki Checkout Form'da kayitli kartla
  odeme, varsayilan kart, provider-backed silme ve duplicate callback
  idempotency E2E senaryolari tamamlanmistir. Faz 5 provider kapsami kapanmistir.
- Final Android odeme entegrasyonunda odeme aksiyonu istek/hosted checkout devam
  ederken devre disi kalir. Ayni kullanici odeme niyetinde idempotency key ve
  mevcut payment/checkout yeniden kullanilir; retry, yeniden cizim veya process
  recreation yeni odeme baslatmaz. UI korumasi tamamlayicidir; asil cift islem
  guvencesi backend idempotency, provider event deduplication ve veritabani
  kisitlarinda kalir.
- Coklu provider tahsilat para birimi backend kapsami tamamlanmistir: canonical
  platform, tur, wallet, kazanc ve withdrawal parasi USD kalir; hosted kart
  tahsilati config ile etkin `USD`, `TRY`, `EUR`, `GBP` alt kumesinden secilir.
  `V13` kalici, kullanici/amaca bagli ve kisa omurlu FX quote'larini; payment ve
  refund charge snapshot'larini ekler. Frankfurter ECB referans kuru API key
  istemeden dar provider adapter'i, timeout ve `BigDecimal` minor-unit yuvarlama
  politikasi arkasinda kullanilir.
- Currency-options, tur quote ve wallet top-up quote API'leri eklenmistir. Hosted
  initialize yalniz gecerli `quoteId` ve dinamik `TR/EN` locale ile baslar;
  retrieve/webhook/reconciliation gercek charge amount/currency snapshot'ini
  dogrular. Provider iadesi ayni charge currency'de, internal ledger reversal
  canonical USD olarak calisir. Ayni quote ikinci bir odemede kullanilamaz.
- Faz 6 backend kapsami tamamlanmistir: `V9` notification, `V10` chat ve `V11`
  Firebase Installation ID semalari; kalici notification history/unread,
  tercihler, FID kaydi, commit-sonrasi FCM teslimati, lifecycle bildirimleri,
  guide-tourist tekil sohbeti, REST history/read/unread akislari ve JWT korumali
  private STOMP kuyruklari uygulanmistir. Android entegrasyonu bu backend
  sozlesmesini tuketecek ayri calismadir; backend tamamlama sirasinda Android
  kaynak kodu degistirilmez.
- Faz 6; temiz test migration/context'i, OpenAPI sozlesmesi, kalici chat/unread
  ve FCM transaction-siniri regression testleri ile; ayrica local PostgreSQL
  `V11`, Hibernate validate, Firebase credential ve STOMP broker baslangiciyla
  dogrulanmistir.
- Faz 7 backend kapsami tamamlanmistir: `V12` operasyonel recovery semasi,
  bounded reservation timeout, payment reconciliation, refund recovery,
  guide earning availability, FCM retry, yaklasan tur hatirlatma ve eski FID
  cleanup scheduler'lari uygulanmistir. Session ve medya scheduler'lari da ayni
  batch sinirina alinmistir. Provider ve FCM cagrilari acik DB transaction'i
  tasimaz; refund commit-sonrasi teslimati bounded async executor kullanir.
- Gec `TIMEOUT` tour payment'i artik otomatik iade edilmez; session/reservation
  lock altinda kapasite yeniden kontrol edilir, yer varsa rezervasyon kesinlesir,
  yoksa mevcut idempotent tek tam iade akisi calisir.
- Local demo seed yalniz `local` profilde, `DEMO_SEED_ENABLED=true` ve Git disi
  password ile idempotent guide/tourist hesaplari ve guide profili olusturur.
  Varsayilan olarak kapalidir; production migration'i demo veri icermez.
- Faz 7 tamamlandiginda test profili, Flyway `V1-V12`, Spring context/OpenAPI ve
  local PostgreSQL `V12` migration + Hibernate validate + gercek uygulama
  baslangiciyla dogrulanmistir. Final backend dogrulamasinda test profilinin
  canonical veritabani PostgreSQL 18 Testcontainers'a tasinmis ve H2
  kaldirilmistir. Iki cihazli gercek LAN UI akisi Android'in FID, REST ve STOMP
  entegrasyonu tamamlandiginda yapilacak final E2E kontroludur.
- Iki cihazli LAN UI kontrolu tur satin alma ve odeme testini zorunlu olarak
  kapsamaz. Kart ve wallet ile tur satin alma; Android odeme entegrasyonu
  tamamlandiginda payment/reservation/refund sonucu, bakiye, kapasite ve ayni
  odeme niyetinin tekrar kullanimi birlikte dogrulanarak ayri E2E test edilir.
- `SIMULATED` withdrawal ayni transaction'da `PENDING -> PROCESSING -> COMPLETED`
  olur ve external provider belirsizligi tasimaz. Bu nedenle sahte withdrawal
  reconciliation job'u eklenmemistir; gercek payout modu eklenirse provider
  status/retrieve sozlesmesiyle birlikte uygulanmasi zorunludur.
- Faz 8 teknik backend dogrulamasi tamamlanmistir: Colima/Docker ve PostgreSQL 18
  Testcontainers kalici local runtime'i kurulmus, temiz `V1-V13` migration ve
  Hibernate validate dogrulanmis, 36 test sinifindaki 72 kalici testin tamami
  gecmistir. Repository, PostgreSQL `JSONB`/`TIMESTAMPTZ`/unique constraint,
  pessimistic lock, concurrency, idempotency, atomik wallet purchase/iptal/iade,
  gec odeme/tek iade, auth lifecycle, role/ownership, medya guvenligi ve orphan
  cleanup, guide projection, chat/FCM ve OpenAPI sozlesmeleri korunur.
- Final secret/log/test denetiminde tracked gercek secret, gecici konsol logu,
  hassas deger logu veya production degeri olmayan gecici test bulunmamistir.
  Spring Boot 3.5.x hattinin son OSS patch'i, PostgreSQL surucusu, Flyway 12,
  springdoc 2.x, JJWT, Google API client, Lombok ve Testcontainers uyumlu patch
  surumlerine alinmistir; uyumsuz major surumlere gecilmemistir.
- Local profil PostgreSQL 18.3 uzerinde `V13`, Hibernate validate, Firebase ve
  STOMP baslangiciyla acilmis; canli `/v3/api-docs` endpoint'i 70 path ve bearer
  security sozlesmesiyle dogrulanip uygulama kontrollu kapatilmistir.
- Altin Kural denetimi tamamlanmistir. Repository katmaninin DTO/service
  paketlerine ters bagimlilik olusturan arama ve siralama politikalari domain'e
  tasinmis; tekrar eden version, tur konumu, rol ve iade bildirim kurallari yalniz
  gercek tekrar bulunan noktalarda merkezilestirilmistir. Iade bildirim payload'i
  `tourId` dahil tek sozlesmeye alinmis, kullanilmayan hata kodlari ve gereksiz
  entity setter'lari temizlenmis, field injection constructor injection'a
  cevrilmistir. Uzun fakat tek sorumlulugu koruyan servisler sirf bolmek icin
  parcalanmamis ve yeni spekulatif katman eklenmemistir.

## Ertelenen Maddeler

Asagidaki maddeler unutulmus degildir; gercek kullanimlarinin bulundugu fazda
eklenecektir:

| Madde | Uygulanacagi zaman |
| --- | --- |
| Ilk yeni domain semasi icin `V3` Flyway migration | Tamamlandi: `V3__create_media_and_guide_profile_schema.sql` |
| Somut role ve ownership `@PreAuthorize` kontrolleri | Faz 2 media/profile icin tamamlandi; sonraki domainlerde devam eder |
| Domain'e ozel stabil `ErrorCode` ve mesaj anahtarlari | Faz 2 icin tamamlandi; sonraki feature yazilirken devam eder |
| Endpoint'e ozel page/size/sort sinirlari | Faz 3 liste endpoint'leri icin tamamlandi; sonraki liste endpoint'lerinde devam eder |
| `MEDIA_STORAGE_ROOT`, public media URL ve storage dogrulamalari | Tamamlandi: local secret/environment + kontrollu content endpoint'i |
| Tur/oturum projection'larindaki rezervasyon, kapasite, puan, yorum ve rehber performans metrikleri | Tamamlandi: `ReservationCapacityService`, `ReviewQueryService` ve `GuidePerformanceService` gercek sorgulara baglandi; rehber tur karti `capacity` alaninda toplam kapasiteyi, tur bazli `averageRating`/`reviewCount` ve session bazli nullable `netEarningsMinor` degerini N+1 olusturmayan toplu sorgularla dondurur. Kazanca `PENDING`/`AVAILABLE` dahil, `REVERSED` harictir; iptal edilen veya kazanc olusmayan session `null` dondurur |
| Dashboard ve aylik rehber kazanc projection'lari | Tamamlandi: dashboard `currentMonthEarningsMinor` ve `GET /api/v1/guide/earnings/monthly?year=...` ayni `createdAt`/`REVERSED` haric hesap kuralini kullanir. Aylik response `year`, `month`, `netEarningsMinor`, `currencyCode` tasir ve yeniden eskiye siralanir; yeni tablo yoktur |
| Bildirim aktor adi ve wallet hareketi referans basligi | Tamamlandi: kullanici kaynakli bildirim `actorDisplayName`, sistem bildirimi `null` dondurur. Turla baglantili `TOUR_PURCHASE`, `REFUND`, `GUIDE_EARNING`, `EARNING_REVERSAL` hareketleri rezervasyon satin alma snapshot'indan `referenceTitle` alir; `TOP_UP`/`WITHDRAWAL` `null` kalir ve liste sorgulari N+1 olusturmaz |
| Booking API ve `ReservationBookingService` payment/wallet baglantisi | Tamamlandi: hosted verified payment ve atomik wallet debit ayni canonical response'u kullanir |
| Turist/rehber/admin iptalinde gercek refund ve guide earning duzeltmesi | Tamamlandi: uygun iade ve earning reversal transaction/reconciliation akisina baglandi |
| Rezervasyon ve yorum lifecycle bildirimleri | Tamamlandi: notification history ayni domain transaction'inda, FCM teslimati commit sonrasinda calisir |
| Suresi dolmus `PENDING_PAYMENT` hold'larini `EXPIRED` yapan scheduler | Tamamlandi: bounded aday sorgusu, session-first lock, reservation re-check ve ilgili non-terminal payment timeout ayni transaction'da uygulanir |
| Gec verified payment icin session/reservation lock, kapasite ve tek refund karari | Tamamlandi: session-first lock sirasi, kapasite yeniden kontrolu ve deterministik tek full refund uygulanir |
| Google Places kaynakli konum verisinin sunucu tarafinda yeniden dogrulanmasi | Production hazirlik kontrolunde; Faz 3 MVP akisinda Android'den gelen canonical konum alanlari dogrulanip saklanir |
| Iyzico callback/webhook public base URL konfigurasyonu | Quick Tunnel ve `PAYMENT_CALLBACK_BASE_URL` tamamlandi; callback/retrieve Sandbox'ta dogrulandi, degisen Quick Tunnel URL'si yeni test oturumunda backend ve iyzico panelinde yenilenecek |
| Hosted checkout callback ve Android WebView siniri | Backend callback JSON + CF Retrieve akisi idempotent kalir; ayni provider event ikinci payment, reservation veya wallet hareketi olusturmaz. POST callback algilama, SSL fail-closed davranisi ve canonical payment/reservation/wallet refresh Android entegrasyonunda uygulanir; backend redirect veya JavaScript bridge eklenmez |
| Iyzico `X-IYZ-SIGNATURE-V3` hesap aktivasyonu | Tamamlandi: destek ekibi hesapta ozelligi aktif etti; strict backend dogrulamasi ve gercek imzali webhook E2E basarili |
| Iyzico Card Storage/hosted save destegi | Backend kapsami tamamlandi: destek onayi, `V8`, sifreli provider key/token saklama, maskeli listeleme, sonraki hosted checkout'ta kayitli kartla odeme, varsayilan kart, provider-backed silme ve duplicate callback idempotency E2E dogrulandi. Android mock kart verisi final Android entegrasyonunda bu API ile degistirilecek |
| Coklu provider tahsilat para birimi ve backend FX quote'u | Backend tamamlandi: `V13`, Frankfurter ECB adapter'i, config-backed `USD/TRY/EUR/GBP`, currency-options + quote API'leri, quote-bound initialize, charge retrieve/refund snapshot'i ve hata sozlesmesi uygulanip temiz test/local PostgreSQL/OpenAPI ile dogrulandi. Android secim/quote UI'i ve her etkin para birimindeki iyzico Sandbox E2E final Android entegrasyonu/Faz 8 kontrolunde yapilacak |
| Marketplace/submerchant yetkisi ve `IYZICO`/`SIMULATED` payout karari | Tamamlandi: tahsilat/iade gercek Sandbox, rehber payout `SIMULATED` |
| Payment/refund timeout ve reconciliation scheduler'lari | Tamamlandi: kalici attempt/timestamp state'i, bounded retry ve stale `PROCESSING` refund icin guvenli `MANUAL_REVIEW` uygulanir |
| `PENDING` guide earning kayitlarini zamani gelince `AVAILABLE` yapma | Tamamlandi: bounded earning scheduler mevcut idempotent wallet credit akisini kullanir |
| FCM service account, FID kaydi ve push adapter'i | Tamamlandi: credential Git disinda, FID API'si ve semantic payload siniri uygulanmistir |
| WebSocket/STOMP bagimliliklari ve realtime guvenligi | Tamamlandi: CONNECT JWT, katilimci kontrolu ve yalniz private user queue teslimati uygulanmistir |
| `PENDING/FAILED` FCM teslimatlarini bounded yeniden deneme ve yaklasan tur hatirlatmalari | Tamamlandi: kalici retry sayaci/zamani, maksimum deneme, reminder deduplication ve tourist/guide reminder marker'lari uygulanir |
| Android FID kaydi, FCM service/channel/permission ve REST/STOMP repository entegrasyonu | Backend tamamlandiktan sonraki Android entegrasyonunda; backend endpoint ve destination sozlesmeleri degistirilmeden tuketilir |
| Docker ve PostgreSQL Testcontainers altyapisi | Tamamlandi: Colima Homebrew servisi, kullaniciya ozel Testcontainers Docker host ayari ve test-scope PostgreSQL 18 container'i ile Maven testleri ek komut gerektirmeden calisir |
| Tum kalici testlerin gereklilik, tekrar ve production degeri denetimi | Tamamlandi: 36 sinif/72 test korundu; gecici, tekrarlayan veya yalniz implementation detayini test eden dosya bulunmadi. Guide card aggregate/kapasite, aylik kazanc, bildirim aktoru, wallet referans basligi ve OpenAPI sozlesmeleri ek testlerle korunur |
| Test profilindeki H2 2.2.224/Flyway destek araligi uyarisi | Tamamlandi: PostgreSQL'e ozel sema, JSONB, lock ve concurrency icin ek deger saglamadigindan H2 kaldirildi; test profilinin canonical DB'si PostgreSQL 18 Testcontainers oldu |
| PostgreSQL 18 icin mevcut Flyway destek uyarisinin yeniden degerlendirilmesi | Tamamlandi: Flyway 12.8.1 ile temiz PostgreSQL 18.6 ve local PostgreSQL 18.3 `V1-V13` migration/validate uyarisiz calisti |

Bu liste her faz sonunda yeniden kontrol edilir. Tamamlanan satirlar silinmek
yerine gercek uygulama dosyasina veya teste referans verilerek tamamlandi olarak
isaretlenebilir.
