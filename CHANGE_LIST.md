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
