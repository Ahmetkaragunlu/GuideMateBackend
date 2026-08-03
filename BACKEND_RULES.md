# GuideMate Backend Calisma Kurallari

Bu dosya, backend gelistirmesi boyunca unutulmamasi gereken operasyonel
kurallarin ve ertelenen maddelerin kisa takip listesidir. Ayrintili domain ve API
kararlari icin ana kaynak:

`/Users/ahmetkaragunlu/AndroidStudioProjects/GuideMate/docs/backend-implementation-handoff.md`

Bir celiski olursa kullanicinin en son acik karari uygulanir. Android kaynak
kodu backend fazlarinda degistirilmez.

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

- Faz 0 Android endpoint'i uretmez. Iyzico Card Storage ve
  Marketplace/submerchant yetkileri Faz 5 basinda dogrulanmak uzere
  ertelenmistir; payout modu henuz kararlastirilmamistir.
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
| Tur/oturum projection'larindaki rezervasyon, kapasite, puan, yorum ve rehber performans metrikleri | Faz 4 reservation/review tablolariyla gercek sorgulara baglanacak; Faz 3'te olmayan veriler sahte uretilmeyip kanonik `0` veya toplam kapasite olarak doner |
| Dashboard `currentMonthEarningsMinor` degeri | Faz 5 `guide_earnings` kayitlariyla gercek sorguya baglanacak; o zamana kadar kanonik `0` doner |
| Google Places kaynakli konum verisinin sunucu tarafinda yeniden dogrulanmasi | Production hazirlik kontrolunde; Faz 3 MVP akisinda Android'den gelen canonical konum alanlari dogrulanip saklanir |
| Iyzico callback/webhook public base URL konfigurasyonu | Faz 5 basinda |
| Iyzico Card Storage/hosted save destegi | Faz 5 dis bagimlilik kontrolunde |
| Marketplace/submerchant yetkisi ve `IYZICO`/`SIMULATED` payout karari | Faz 5 dis bagimlilik kontrolunde |
| FCM service account ve push adapter'i | Faz 6 basinda |
| WebSocket/STOMP bagimliliklari ve realtime guvenligi | Faz 6 basinda |
| Docker ve PostgreSQL Testcontainers altyapisi | Faz 8 basinda |
| Tum kalici testlerin gereklilik, tekrar ve production degeri denetimi | Faz 8 sonunda |
| PostgreSQL 18 icin mevcut Flyway destek uyarisinin yeniden degerlendirilmesi | Production hazirlik kontrolunde |

Bu liste her faz sonunda yeniden kontrol edilir. Tamamlanan satirlar silinmek
yerine gercek uygulama dosyasina veya teste referans verilerek tamamlandi olarak
isaretlenebilir.
