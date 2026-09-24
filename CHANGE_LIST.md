# GuideMate Backend Degisim Listesi

## Altin Kural

- SOLID, dogru bagimlilik yonu, okunabilirlik, test edilebilirlik,
  genisletilebilirlik, dogru isimlendirme ve feature-first paket sahipligi
  korunur.
- Gercek kod tekrari uygun ortak yapida merkezilestirilir; yalniz benzer gorundugu
  icin farkli is kurallari birbirine baglanmaz.
- Sirf dosya uzun, constructor kalabalik veya tek bir benzerlik var diye yeni
  katman, interface, facade, helper, base class ya da wrapper eklenmez.
- Siniflar yalniz satir sayisi nedeniyle parcalanmaz. Okunabilirligi gercekten
  bozan ve dogal olarak isimlendirilebilen ayri sorumluluk varsa en kucuk
  davranis-koruyucu ayrim yapilir.
- Controller, DTO, mapper, service/application, repository, domain, config ve
  external adapter sinirlari karistirilmaz. Her dosya gercek sahibinin feature ve
  katman paketinde bulunur.
- Mevcut dogru mimari ve API davranisi korunur. Bir sorun bulmak icin gereksiz
  refactor yapilmaz; her degisikligin somut guvenlik, dogruluk, sahiplik,
  bagimlilik, tekrar veya okunabilirlik gerekcesi olur.
- Normal kullanici akisi, Android/API sozlesmesi, endpoint request/response
  yapilari ve mevcut is kurallari kullanicinin acik onayi olmadan degistirilmez.
  Her kabul edilen madde uygulanmadan once davranis etkisi aciklanir; uygulama
  sonrasinda ilgili regression testleri ve sozlesme kontrolleriyle davranisin
  korundugu dogrulanir. Guvenlik maddelerinde yalniz acikca kabul edilen kotuye
  kullanim veya gecersiz istek davranisi degisebilir.
- Kod degisikligiyle tamamen bosa dusen ve bilincli olarak ertelenmemis kod,
  import, property, paket ve log temizlenir.
- Secret, token, kart verisi, tam IBAN ve teknik exception ayrintisi source
  control'e, response'a veya loglara sizdirilmaz.

## Test Kalitesi

- Degisen davranis gecici testlerle degil, gercek regression degeri olan kalici
  testlerle korunur.
- Testler is kurali, guvenlik, API sozlesmesi, transaction, concurrency,
  idempotency ve hata senaryolarini riskleriyle orantili olarak dogrular.
- Test sayisi veya coverage yuzdesi tek basina hedef degildir. Anlamli davranisi
  korumayan, tekrarlayan ya da yalniz implementation detayina baglanan test
  yazilmaz.
- Persistence davranisi gereken yerde gercek PostgreSQL/Testcontainers ve Flyway
  semasiyla; izole is kurallari uygun unit testlerle dogrulanir.
- Yeni degisiklik tamamlanmadan once ilgili testler, production compile ve gerekli
  sozlesme/migration kontrolleri calistirilir.

## Onaylanan Degisiklikler

### 1. Public Base URL Yapilandirmasini Merkezilestirme

- `app.public-base-url`, `@ConfigurationProperties(prefix = "app")` kullanan
  typed bir `AppProperties` yapisindan yonetilir.
- `MediaUrlFactory`, `ProductionConfigurationValidator` ve `EmailServiceImpl`
  ayni property'yi ayri `@Value` parametreleriyle okumak yerine bu ortak
  yapilandirmaya baglanir.
- Ortak URL bicim dogrulamasi ve sondaki `/` normalizasyonu tek yerde yapilir;
  production profiline ozel public HTTPS kontrolu mevcut validator sinirinda
  korunur.
- Endpoint, e-posta linki, medya URL'si, API sozlesmesi ve kullanici davranisi
  degismez.
- Property binding, URL dogrulamasi ve mevcut URL uretim davranisi anlamli
  regression testleriyle korunur.

### 2. Yalniz Olusturulma Zamani Tutan UUID Entity Tabanini Ortaklastirma

- `Notification`, `WalletLedgerEntry` ve `PaymentEvent` icinde tekrarlanan UUID
  `id` ve `createdAt` alanlari ortak `UuidCreatedEntity` mapped superclass'ina
  tasinir.
- Taban sinif yalniz gercek ortak alanlari kapsar; `updatedAt` eklemez ve alt
  entity'leri immutable kabul eden ek bir davranis dayatmaz.
- Mevcut UUID uretimi, `created_at` kolonlari, tablo semasi ve olusturulma zamani
  davranisi korunur; Flyway migration gerekmez.
- API response'lari, repository davranisi ve is akislari degismez.
- Ortak persistence davranisi PostgreSQL/Flyway entegrasyon testleriyle ve ilgili
  mevcut regression testleriyle dogrulanir.

### 3. Admin Hesap Seed Yapilandirmasini Merkezilestirme

- `auth.admin-seed` altindaki email, password, first-name ve last-name ayarlari
  typed bir `AdminAccountSeedProperties` yapisinda toplanir.
- `AdminAccountSeeder`, ilgili degerleri ayri `@Value` parametreleriyle okumak
  yerine bu ortak yapilandirmaya baglanir.
- Admin seed kapaliyken mevcut davranis korunur; zorunlu alan kontrolleri yalniz
  seed etkin oldugunda uygulanir.
- Admin olusturma akisi, parola politikasi, veritabani semasi ve kullanici
  davranisi degismez.
- Property binding ve etkin/devre disi admin seed senaryolari kalici regression
  testleriyle dogrulanir.

### 4. SMTP E-posta Servisini Somut Saglayiciyla Adlandirma

- `EmailServiceImpl`, kullandigi altyapiyi acikca anlatan `SmtpEmailService`
  olarak yeniden adlandirilir.
- `EmailService` sozlesmesi ve mevcut constructor bagimliliklari korunur; tek
  implementasyon icin yeni alt paket veya ek soyutlama olusturulmaz.
- E-posta icerigi, link uretimi, gonderim sekli ve hata esleme davranisi
  degismez.
- Mevcut servis testi yeni sinif adina tasinir ve ayni davranislari dogrulamaya
  devam eder.

### 5. Production Odeme Callback Adresini Baslangicta Dogrulama

- Yalniz `prod` profilinde `PAYMENT_CALLBACK_BASE_URL` uygulama baslangicinda
  fail-fast olarak dogrulanir.
- Adres bos olamaz; HTTPS ve public bir host kullanmalidir. Localhost, LAN ve
  private IP adresleri production callback adresi olarak kabul edilmez.
- Local ve demo profilleri ile Quick Tunnel tabanli gelistirme akisi etkilenmez.
- Gecerli production yapilandirmasinda odeme, callback, API ve veritabani
  davranisi degismez; yalniz hatali production ayari backend acilirken reddedilir.
- Public, bos, HTTP ve private callback adresleri odakli yapilandirma testleriyle
  dogrulanir.

### 6. Dil Kodu Politikasinin Is Kurallarini Test Etme

- `LanguageCodePolicyTest`, production sinifini aynalayan `common/validation`
  test paketine eklenir.
- ISO dil kodu kabul/red davranisi, trim ve `Locale.ROOT` ile kucuk harfe
  donusturme, tekrarlarin kaldirilmasi, `und` reddi ve optional bos deger
  davranisi dogrulanir.
- Yalniz anlamli is kurallari test edilir; Java `Locale` kutuphanesinin kendi
  implementasyon ayrintilari tekrar test edilmez.

### 7. Canonical Odeme Response Donusumunu Test Etme

- `PaymentQueryServiceTest`, production sinifini aynalayan
  `payment/service/payment` test paketine eklenir.
- Ownership bulunamamasi, refund ve reservation bilgilerinin response'a
  aktarilmasi ve `paymentPageUrl` alaninin yalniz `REQUIRES_ACTION` durumunda
  gosterilmesi dogrulanir.
- Testler para akisinin Android'e donen canonical response sozlesmesini korur;
  repository implementasyonunu veya basit getter'lari tekrar test etmez.

### 8. Notification Push Event Zincirini Tamamlama

- `NotificationPushDeliveryEventListenerTest`, production listener'i aynalayan
  `notification/event` test paketine eklenir.
- `pushRequested=true` durumunda delivery'nin tetiklendigi,
  `pushRequested=false` durumunda tetiklenmedigi dogrulanir.
- Mevcut `NotificationServiceTest`, kullanici tercihinden uretilen push kararinin
  `NotificationCreatedEvent.pushRequested` alanina dogru aktarildigini
  dogrulayacak sekilde genisletilir.
- Async altyapiyi taklit eden kirilgan bekleme testleri yazilmaz; listener kosulu
  ve event sozlesmesi deterministik unit testlerle korunur.

### 9. Chat ve Notification OpenAPI Sozlesmelerinin Sahipligini Ayirma

- `CommunicationOpenApiContractTest` tek bir `common` testine tasinmaz.
- Chat endpoint ve DTO kontrolleri `chat/ChatOpenApiContractTest` sinifina;
  notification, preference ve FCM device kontrolleri
  `notification/NotificationOpenApiContractTest` sinifina ayrilir.
- Mevcut OpenAPI assertion'lari korunur; API sozlesmesi veya endpoint davranisi
  degismez.
- Genel API ve hassas alan sizintisi kontrolleri mevcut
  `common/OpenApiCompletenessContractTest` sinirinda kalir.

### 10. Media Service Testini Kapsamini Anlatan Isimle Adlandirma

- `MediaServiceAccessTest`, artik access kontrolunun yaninda upload, canonical
  metadata, storage failure ve delete davranislarini da kapsadigi icin
  `MediaServiceTest` olarak yeniden adlandirilir.
- Test paketi `media/service` olarak korunur; test icerigi ve production davranisi
  degismez.
