# GuideMate Backend Degisim Listesi

Bu dosya yalniz kullaniciyla tek tek gorusulup kabul edilen yeni backend
degisikliklerini takip eder. Kabul edilmemis, ertelenmis veya yalniz fikir olarak
konusulmus maddeler bu listeye eklenmez.

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

## Kabul Edilen Degisiklikler

1. E-posta dogrulama ve sifre sifirlama tokenlari veritabaninda ham olarak
   saklanmayacak. Ham token yalniz kullaniciya gonderilecek; backend kalici olarak
   guvenli hash degerini saklayacak ve gelen tokeni hashleyerek arayacak. Mevcut
   API ve kullanici davranisi degismeyecek, Android degisikligi gerekmeyecek.
   Gerekli Flyway migration'i ile repository/service kodu ve kalici guvenlik
   regression testleri birlikte guncellenecek.

2. Kayit endpoint'i profesyonel, konfigurasyonla yonetilen rate limit ile
   korunacak. Farkli e-posta adresleriyle ayni bilgisayardan pes pese normal hesap
   olusturma engellenmeyecek; IP ve normalize e-posta icin ayri sinirlar yalniz
   otomatik veya asiri denemeleri durduracak. Limit asildiginda kullanici kaydi ve
   e-posta gonderimi yapilmadan `429 Too Many Requests` ile `Retry-After`
   dondurulecek. Local/demo profilleri kullanici testlerini engellemeyecek uygun
   sinirlara sahip olacak. Mevcut merkezi hata ve rate-limit yapisi kullanilacak;
   gereksiz yeni katman veya harici altyapi eklenmeyecek.

3. Google giris endpoint'i konfigurasyonla yonetilen ve normal kullanimi
   engellemeyen rate limit ile korunacak. IP ve canonical `installationId`
   birlikte degerlendirilecek; ayni cihazda farkli Google hesaplariyla normal
   giris yapilabilecek. Yalniz otomatik veya asiri isteklerde Google token
   dogrulama cagrisi yapilmadan `429 Too Many Requests` ve `Retry-After`
   dondurulecek. Local/demo sinirlari kullanici testlerini engellemeyecek. Endpoint,
   request/response DTO'lari, Android sozlesmesi ve mevcut Google auth hata
   kodlari degismeyecek; kayit rate limit'iyle ayni merkezi mekanizma tekrar
   olusturmadan kullanilacak.

4. Tur aramasinda `cityPlaceId` degeri yalniz trim edilecek; buyuk/kucuk harfleri
   degistirilmeyecek. Serbest arama metni `q` mevcut case-insensitive davranisini
   koruyacak. Boylece kaydedilirken karakterleri korunan harici Place ID ile
   repository'nin tam esitlik sorgusu ayni canonical degeri kullanacak. Endpoint,
   DTO, tablo, mevcut veri ve Android sozlesmesi degismeyecek; yalniz hatali bos
   sonuc uretebilen Place ID filtresi duzeltilecek. Degisiklik kucuk ve feature
   icinde kalacak; mixed-case Place ID ile serbest metin aramasini koruyan kalici
   regression testleri eklenecek.

5. SMTP konfigurasyonu tek guvenli kaynaktan yonetilecek. IntelliJ Run
   Configuration'da etkili olan mevcut `MAIL_USERNAME` ve `MAIL_PASSWORD`
   degerleri acik edilmeden, Git disindaki ve dosya izni `600` olan
   `config/application-local-secrets.properties` dosyasina tasinacak; ardindan
   yalniz bu iki IntelliJ override'i kaldirilacak. `SPRING_PROFILES_ACTIVE=demo`
   simdilik korunacak. Demo ve normal local profil ayni local secret kaynagini
   kullanacak; demo kaldirildiktan sonra normal veritabaninda da ayni SMTP hesabi
   calismaya devam edecek. Kullanilan degerler, e-posta davranisi, endpoint'ler ve
   Android sozlesmesi degismeyecek; backend yeniden baslatilarak ayni SMTP
   kaynaginin etkin oldugu degerleri loglamadan dogrulanacak.

6. GitHub'a giden `config/application-local-secrets.example.properties`
   sablonuna zorunlu `MEDIA_STORAGE_ROOT` anahtari yalniz ornek/placeholder
   degerle eklenecek. Bu sablon sadece ayarin varligini ve beklenen bicimini
   gosterecek; kullanicinin gercek klasor yolu, bilgisayar bilgisi veya herhangi
   bir secret Git'e eklenmeyecek. Git disindaki gercek local secrets dosyasi,
   mevcut medya konumu, avatar/tur gorseli davranisi, veritabani, endpoint'ler ve
   Android sozlesmesi degismeyecek.

7. Public auth request alanlarina veritabani ve protokol sinirlariyla uyumlu
   maksimum uzunluk dogrulamalari eklenecek. Ad/soyad sinirlari entity kolonlari,
   e-posta siniri standart ve DB kolonu, Google ID token ile refresh/confirmation/
   reset token sinirlari gercek token bicimleri dikkate alinarak belirlenecek.
   Mevcut 8-64 parola kurali korunacak. Normal Android istekleri, endpoint ve
   request/response sozlesmeleri ile auth basari/hata akislarinin anlami
   degismeyecek; yalniz mantiksiz derecede buyuk veya gecersiz girdiler DB ya da
   dis servis cagrisi yapilmadan merkezi validation cevabiyla reddedilecek. Sinir
   degerleri ve mevcut gecerli istekler kalici regression testleriyle korunacak.

8. Kayit sirasinda olusan her `DataIntegrityViolationException` otomatik olarak
   `EMAIL_ALREADY_EXISTS` hatasina cevrilmeyecek. DB unique constraint'iyle
   korunan eszamanli kayit yarisi sonrasinda normalize e-postanin gercekten mevcut
   oldugu dogrulanirsa mevcut `EMAIL_ALREADY_EXISTS` davranisi korunacak; farkli
   bir veri butunlugu problemi yanlis e-posta mesaji arkasinda gizlenmeden merkezi
   uygun hata sozlesmesine birakilacak. PostgreSQL hata metni parse edilmeyecek ve
   yeni exception katmani kurulmayacak. Normal kayit, duplicate e-posta, endpoint,
   DTO ve Android davranisi degismeyecek; duplicate yarisi ile e-posta disi
   butunluk hatasi odakli regression testleri eklenecek.

9. JWT konfigurasyonu dogrulanan typed `JwtProperties` altinda
   merkezilestirilecek. Mevcut `JWT_SECRET`, `JWT_EXPIRATION_MS` ve
   `JWT_REFRESH_EXPIRATION_MS` environment kaynaklari, secret degeri, 15 dakikalik
   access suresi ve 30 gunluk refresh suresi aynen korunacak. `JwtService` ile
   `RefreshSessionService` daginik `@Value` parametreleri yerine ayni anlamli
   config nesnesini constructor uzerinden kullanacak. Secret/key uzunlugu ve
   surelerin gecerli olmasi uygulama baslangicinda fail-fast dogrulanacak. Token
   icerigi, imzasi, rotation/replay davranisi, endpoint'ler ve Android sozlesmesi
   degismeyecek; gecerli ve gecersiz config senaryolari odakli kalici testlerle
   korunacak.

10. Auth rate-limit konfigurasyonu dogrulanan typed
    `AuthRateLimitProperties` altinda merkezilestirilecek. Mevcut login,
    resend-verification ve forgot-password limitleri ile environment kaynaklari
    aynen korunacak; kabul edilen register ve Google login sinirlari da ayni
    feature-owned config yapisindan beslenecek. Saniye tabanli daginik `@Value`
    parametreleri anlamli `Duration` ve limit gruplarina donusecek; sifir/negatif
    degerler ve birbiriyle celisen blok sureleri uygulama baslangicinda fail-fast
    dogrulanacak. `429`, `Retry-After`, endpoint'ler, DTO'lar, Android sozlesmesi
    ve normal kullanici davranisi degismeyecek. Property binding ve sinir
    dogrulamalari kalici config testleriyle korunacak.

11. E-posta dogrulama ve sifre sifirlama tokenlarinin kesin an bildiren
    `expiresAt`, `usedAt` ve `confirmedAt` alanlari `LocalDateTime` ve
    `ZoneId.systemDefault()` yerine `Instant` ile yonetilecek. PostgreSQL kolonlari
    zaman dilimi bilgili tipe yeni Flyway migration'iyla donusturulecek ve mevcut
    aktif kayitlar ayni gercek ani gosterecek sekilde acik zaman dilimiyle
    korunacak. Token gecerlilik sureleri, e-posta baglantilari, endpoint'ler,
    kullanici akisi ve Android sozlesmesi degismeyecek. Bu degisiklik kabul edilen
    token-hash migration'iyla birlikte, ayni dosyalari tekrar tekrar degistirmeden
    uygulanacak; zaman sinirlari ve migration davranisi kalici testlerle
    dogrulanacak. Yalniz kesin anlar `Instant` kullanacak; tarih-only alanlar,
    kullanici yerel saatleri ve sureler kendi semantik tiplerini koruyacak.

12. Backend'in kullaniciya ulasabilen metinleri Android'deki mevcut kaynak
    mantigiyla uyumlu olarak tek Turkce `messages.properties` kaynaginda
    merkezilestirilecek. API hata ve validation fallback metinleri, e-posta konu/
    icerikleri ile hesap dogrulama ve sifre sifirlama web metinleri anahtar
    uzerinden bu kaynaktan alinacak; bu kapsamdaki hardcoded veya tutarsiz
    Ingilizce metinler Turkce karsiliklariyla merkezi kaynaga tasinacak. Loglar,
    makine tarafindan okunan hata kodlari, provider cevaplari ve yalniz
    gelistiriciye yonelik teknik metinler sirf ortaklastirmak icin property'ye
    tasinmayacak. Simdilik `messages_en.properties` veya ayri bir Turkce locale
    dosyasi eklenmeyecek; mevcut Turkce kullanici davranisi korunacak. Anahtar
    yapisi ileride ayni anahtarlarla yeni dil dosyalari eklenebilecek sekilde
    eksiksiz ve tutarli olacak. Endpoint'ler, DTO'lar, Android'in hata kodlarini
    kendi XML kaynaklarina esleme davranisi ve is akislari degismeyecek; kaynak
    anahtarlari ile dogrudan kullaniciya ulasan metinler odakli kalici testlerle
    korunacak.

13. Uygulamadaki log kullanimi amac ve guvenlik acisindan taranacak. Yalniz
    gelistirme sirasinda terminalden akis veya degisken gormek icin eklenmis
    `System.out`, `System.err`, `printStackTrace`, gecici debug loglari ve ayni
    hatayi fayda saglamadan tekrar yazan kayitlar kaldirilacak. Odeme/webhook,
    e-posta, scheduler, FCM, dis servis ve guvenlik sorunlarini production'da
    teshis etmeye yarayan operasyonel loglar; dogru `debug`, `info`, `warn` veya
    `error` seviyesinde ve yeterli baglamla korunacak. Secret, access/refresh
    token, parola, kart verisi, tam IBAN, provider tokeni, e-posta icerigi ile ham
    provider request/response payload'lari loglanmayacak. Scheduler ve diger
    operasyonel arka plan hatalarinda, hassas veri tasimadigi dogrulanan exception
    stack trace'i kok nedeni teshis etmek icin kaydedilebilecek. Log temizligi uygulama akisini,
    hata yonetimini, endpoint'leri, Android sozlesmesini veya is kurallarini
    degistirmeyecek; yalniz gereksiz terminal kalabaligini ve hassas veri sizma
    riskini azaltacak.

14. Request DTO ve endpoint parametrelerindeki kullaniciya ulasabilen validation
    mesajlari hardcoded metinler yerine merkezi `messages.properties`
    anahtarlarindan alinacak. Java degiskenleri, alan adlari ve
    `validation.user.avatarMediaId.notNull` benzeri property anahtarlari mevcut
    proje standardina uygun olarak Ingilizce kalacak; kullaniciya gosterilen
    property degerleri Turkce olacak. Ayni anlama gelen dogrulamalar uygun ortak
    anahtari kullanacak, farkli alan veya is kurallari yalniz benzer gorundukleri
    icin tek mesaja baglanmayacak. Validation kosullari, field adlari, makine
    tarafindan okunan hata kodlari, HTTP durumlari, endpoint/DTO yapilari ve
    Android'in kendi XML mesaj eslemesi degismeyecek. Yalniz fallback mesajlari
    merkezi, tutarli ve ileride yeni dil dosyasi eklenebilir hale gelecek; ilgili
    validation sozlesmesi anlamli regression testleriyle korunacak.
    Merkezi `ErrorCode` enum'u ve tek `messages.properties` dosyasi
    parcalanmayacak; auth, media, tour, reservation/review, payment/wallet ve
    chat/notification gibi anlamli bloklar kisa Ingilizce bolum yorumlariyla
    ayrilacak. Yorumlar yalniz dosya icinde gezinmeyi kolaylastiracak, her sabiti
    aciklayan gereksiz yorum kalabaligi olusturulmayacak.

15. Yalniz auth yasam dongusunde kullanilan `SecureTokenService`, yanlis ortak
    sahiplik izlenimi veren `common/security` paketinden `auth/security` paketine
    tasinacak; sinifin teknik gorevini dogru anlatan `SecureTokenService` adi
    korunacak.
    E-posta dogrulama, sifre sifirlama, refresh session ve auth rate-limit
    servisleri sinifi ayni feature icinden kullanacak. JWT, HTTP/WebSocket
    security handler'lari ve payment/wallet tarafindan paylasilan sifreleme
    bilesenleri gercekten ortak olduklari icin `common/security` altinda kalacak.
    `auth/security` paketi estetik bir gruplandirma degil, sinifin auth'a ait
    guvenlik teknigi olmasini ifade eden gercek sahiplik siniri olacak. Yeni
    interface veya wrapper eklenmeyecek. Token uretme ve hashleme
    algoritmasi, endpoint'ler, DTO'lar, Android sozlesmesi ve kullanici davranisi
    degismeyecek; mevcut token testleri yeni paket ve sinif sahipligiyle ayni
    davranisi dogrulamaya devam edecek.

16. Kalabalik ve farkli sorumluluklari ayni seviyede gosteren
    `notification/service` paketi, gercek birlikte-degisim sinirlarina gore
    duzenlenecek. Cihaz kaydi ve temizligi `notification/service/device`, push
    teslimati/durum gecisi/retry `notification/service/delivery`, yaklasan tur
    hatirlatmalari `notification/service/reminder` altinda gruplanacak.
    `NotificationCreatedEvent`, push teslimatini baslatan listener ve realtime
    listener ise service sinifi olmadiklari icin `notification/event` paketinde
    birlikte bulunacak. Yalniz push teslimatini baslatan genel adli
    `NotificationCreatedEventListener`, gorevini acik anlatan
    `NotificationPushDeliveryEventListener` adini alacak. Temel
    `NotificationService`, `NotificationPreferenceService`,
    `NotificationPublisher`, `NotificationCommand` ve `NotificationPayloadCodec`
    ana service paketinde kalacak. Yeni interface, facade veya davranis katmani
    eklenmeyecek; yalniz paketler, importlar ve belirtilen listener adi
    degisecek. Bildirim olusturma, FCM, WebSocket, retry, scheduler, transaction,
    endpoint'ler, Android sozlesmesi ve kullanici davranisi aynen korunacak;
    mevcut notification testleri yeni paket sahipligiyle calismaya devam edecek.

17. Yaklasan tur hatirlatmalarinda scheduler'in aday sorgusu ile service'in
    kilit altindaki son dogrulamasi tarafindan ayri ayri tanimlanan ayni
    `OPEN_FOR_BOOKING` ve `CLOSED` session durumlari, yeni reminder paketindeki
    package-private `UpcomingTourReminderPolicy` icinde tek kaynakta tutulacak.
    Scheduler veritabani on filtresini, service ise eszamanli durum degisikligine
    karsi islem oncesi yeniden dogrulamayi yapmaya devam edecek; bu iki kontrol
    birlestirilmeyecek veya kaldirilmayacak. Policy yalniz reminder is kuralini
    ifade edecek; genel helper, interface ya da Spring bileseni olmayacak.
    Hatirlatma zamanlamasi, gecerli durumlar, sorgular, kilitler, notification
    payload'i, endpoint'ler ve Android davranisi degismeyecek. Ortak listenin iki
    kullanim noktasinda ayni kaldigi odakli regression testleriyle korunacak.

18. `ReservationMapper`, avatar ve tur kapagi icin `MediaReferenceResponse` ile
    public medya URL'sini elle olusturmak yerine mevcut ortak
    `MediaReferenceMapper` bileşenini kullanacak. Mapper'in dogrudan
    `MediaUrlFactory` bagimliligi ve tekrar eden null/URL donusum kodu
    kaldirilacak; yeni helper, interface veya mapper olusturulmayacak. Nullable
    rehber avatari ile veritabani ve snapshot uretiminde zorunlu olan tur kapagi
    mevcut JSON bicimini ve URL degerini koruyacak. Endpoint, DTO, snapshot,
    medya erisim kurali ve Android davranisi degismeyecek; avatar var/yok ve
    kapak donusumleri mapper regression testleriyle dogrulanacak.

19. `User` entity'sindeki tum alanlara kontrolsuz yazma yetkisi veren sinif
    seviyesindeki Lombok `@Setter` kaldirilacak. Zorunlu ilk kullanici bilgileri
    sade bir constructor veya anlamli olusturma metodu ile verilecek; sonraki
    degisiklikler `activate`, `disable`, `changePasswordHash`, `selectRole`,
    `bindGoogleSubject`, `incrementTokenVersion` ve `updateAvatar` gibi islem
    niyetini ve domain kuralini anlatan metotlardan yapilacak. Yalnizca setter
    sayisini azaltmak icin builder, value object veya factory katmani
    olusturulmayacak; JPA field access korunacak. Auth, admin ve demo olusturma
    kodlari ayni baslangic degerlerini yeni kontrollu API ile kuracak, test veri
    hazirligi okunabilir fixture'larla uyarlanacak. Kullanici kaydi, hesap durumu,
    rol secimi, Google baglantisi, parola, token version ve avatar davranisi ile
    endpoint/DTO/Android sozlesmesi degismeyecek; domain gecisleri ve mevcut auth
    akislari kalici regression testleriyle korunacak.

20. `User` entity'sinin normalize edilmis ve veritabaninda benzersiz olan e-posta
    tabanli natural-key `equals/hashCode` davranisi korunacak. Kabul edilen setter
    kaldirma degisikligiyle e-posta olusturma aninda zorunlu olacak ve sonradan
    degistirilemeyecek; boylece hash degeri entity yasam dongusu boyunca sabit
    kalacak. Mevcut kesin sinif karsilastirmasi Hibernate proxy'leriyle ayni
    kullaniciyi yanlislikla farkli saymayacak proxy-uyumlu bir kontrole
    cevrilecek; normalize e-posta disinda degisebilir alanlar equality'ye dahil
    edilmeyecek. Endpoint, repository sorgulari, veritabani kimligi, auth ve
    Android davranisi degismeyecek. Ayni/farkli e-posta, transient entity ve
    Hibernate proxy senaryolari odakli kalici equality testleriyle korunacak;
    ileride e-posta degistirme ozelligi eklenirse strateji yeniden
    degerlendirilecek.

21. Google ID token dogrulamasinin gerektiginde yaptigi dis ag erisimi icin acik
    connect ve read timeout sinirlari tanimlanacak. Google client ID ile timeout
    degerleri auth feature'ina ait, fail-fast dogrulanan typed
    `GoogleAuthProperties` altinda gruplanacak; mevcut `GOOGLE_CLIENT_ID` secret
    kaynagi korunacak. Saglikli Google girisi ve token dogrulama davranisi
    degismeyecek; Google veya ag yanit vermediginde backend thread'i gereksiz uzun
    sure beklemek yerine kontrollu olarak mevcut `GOOGLE_LOGIN_FAILED` kodunu
    dondurecek. Android bu kodu mevcut `error_google_login_failed` XML kaynagina
    esleyerek kullaniciya teknik ayrinti icermeyen yerel mesaji gostermeye devam
    edecek. Ham Google tokeni, timeout veya dis servis ayrintisi response'a ya da
    loga sizdirilmayacak; otomatik retry ile login gecikmesi buyutulmeyecek.
    Endpoint, DTO ve Android sozlesmesi degismeyecek. Property validation, timeout
    yapilandirmasi, basarili dogrulama ve kontrollu hata davranisi odakli kalici
    testlerle korunacak.

22. Kullanici tarafindan yuklenen yeni avatar ve tur kapaklari backend guvenlik
    sinirinda gercek goruntu olarak decode edilecek, genislik/yukseklik ile toplam
    piksel sinirlari kontrol edilecek ve guvenli bicimde yeniden encode edilen
    temiz cikti saklanacak. Mevcut boyut, MIME/signature ve dosya adi kontrolleri
    korunacak; bozuk dosyalar, sikistirma bombalari, gereksiz metadata/EXIF ve
    ham dosyaya eklenmis farkli icerikler storage'a ulasmadan reddedilecek veya
    temizlenecek. Android'in mevcut 2048 px, JPEG kalite 85, EXIF yon duzeltme ve
    5 MB on-normalizasyonu degistirilmeyecek; istemci performansi ile backend
    guvenligi ayri sorumluluklar olarak birlikte korunacak. JPEG, PNG ve WebP
    kabul sozlesmesi devam edecek; kullanilan goruntu kutuphanesi aktif bakimli ve
    yalniz gerekli decode/encode kapsamini saglayacak. Islem, validation ve
    storage sorumluluklarini karistirmayan anlamli bir `MediaImageProcessor`
    bileseninde tutulacak; gereksiz abstraction eklenmeyecek. Eski medya
    dosyalari, endpoint'ler, DTO'lar, medya URL'leri ve Android sozlesmesi
    degismeyecek. Gecerli formatlar, bozuk/sahte dosya, piksel siniri, metadata
    temizligi ve kaydedilen temiz cikti kalici guvenlik testleriyle dogrulanacak.

23. Scheduler'larin kayit bazli hatalari yakalayip yalniz "retry" ve kayit
    kimligi yazmasi nedeniyle kaybolan kok neden bilgisi guvenli bicimde
    korunacak. Odeme reconciliation, iade recovery, rezervasyon timeout, push
    retry, cihaz temizligi, tur hatirlatmasi, kazanc availability ve medya
    cleanup gibi arka plan islemlerinde catch edilen exception; hassas veri
    tasimadigi dogrulanan stack trace ile uygun `warn` veya gercekten nihai
    basarisizlikta `error` seviyesinde kaydedilecek. Global exception handler'a
    ulasmayan bu hatalar icin tek sahip scheduler olacak; ayni exception farkli
    katmanlarda tekrar tekrar loglanmayacak. Basarili periyodik calismalar ve
    gecici terminal debug mesajlari eklenmeyecek. Parola, token, kart, tam IBAN,
    provider payload'i ve secret loglanmayacak. Retry, transaction, scheduler
    zamanlamasi, hata kodlari, endpoint'ler ve kullanici/Android davranisi
    degismeyecek; yalniz operasyonel teshis kalitesi artacak ve log guvenligi
    odakli test/contract kontrolleri korunacak.

24. Ayni is olayinin eszamanli veya tekrar teslim edilmesi sonucunda ayni
    bildirimin birden fazla kez olusmasi, yalniz gercek tekrar riski tasiyan
    bildirim turlerinde veritabani seviyesinde engellenecek. Bu bildirimler icin
    olay turu ve kaynak kaydi gibi kararlı alanlardan anlamli bir
    `deduplicationKey` uretilecek; veritabanindaki unique constraint nihai
    eszamanlilik guvencesi olacak. Uygulama seviyesindeki mevcut idempotency
    kontrolleri korunacak ancak tek basina "once sorgula, sonra ekle" kontrolune
    guvenilmeyecek. Ayni webhook, scheduler veya domain olayi tekrar geldiginde
    ikinci notification, push ya da WebSocket mesaji uretilmeyecek; ilk kayit
    korunacak veya islem guvenli bicimde atlanacak. Her bildirim turune zorunlu
    anahtar eklenmeyecek ve genel bir event framework kurulmayacak. Normal
    bildirim icerigi, sirasi, endpoint'ler, DTO'lar ve Android davranisi
    degismeyecek; yalniz kullanicinin ayni bildirimi iki kez gormesi onlenecek.
    Flyway migration'i, repository/service uyarlamasi ve eszamanli iki uretimin
    tek kalici bildirim olusturdugunu dogrulayan PostgreSQL concurrency testi
    birlikte eklenecek.

25. FCM data payload'i bildirimin hedef kullanicisini acikca belirten
    `recipientUserId` alanini tasiyacak. Android bildirimi gostermeden veya yerel
    notification state'ine aktarmadan once oturumun acik oldugunu ve bu kimligin
    aktif kullanicinin kimligiyle eslestigini dogrulayacak; eslesmeyen ya da
    kullanici oturumu yokken gelen bildirim sessizce yok sayilacak. Boylece
    logout isteginin ag kesintisi nedeniyle backend'e ulasmadigi kisa aralikta
    eski hesaba ait push bildirimi cikis ekraninda veya baska kullanicinin
    oturumunda gosterilmeyecek. Mevcut basarili logout; refresh token iptali,
    cihaz kaydinin pasiflestirilmesi, yerel bildirim/chat/payment state
    temizligi ve yeni giriste cihaz kaydinin yeni kullaniciya baglanmasi
    davranislarini koruyacak. Logout kuyrugu, access-token blacklist'i, yeni
    tablo veya genel bir bildirim framework'u eklenmeyecek. Backend push
    payload'i ve Android FCM alicisi en kucuk kapsamda guncellenecek; normal
    bildirim icerigi, navigation hedefleri, REST DTO'lari, veritabanindaki
    bildirim gecmisi ve kullanici akisi degismeyecek. Dogru kullanici, farkli
    kullanici ve oturumsuz cihaz senaryolari odakli kalici backend/Android
    testleriyle korunacak.

26. Access JWT'leri token'i ureten sistemi belirten `issuer` ve token'in hedefi
    olan API'yi belirten `audience` claim'lerini tasiyacak; backend imza, sure ve
    `tokenVersion` kontrollerine ek olarak bu iki degeri de zorunlu olarak
    dogrulayacak. Degerler kabul edilen merkezi ve fail-fast dogrulanan
    `JwtProperties` icinde yonetilecek; environment ile gerektiğinde
    yapilandirilabilecek ancak local varsayimlar tek GuideMate backend/API
    sinirini acikca ifade edecek. Token blacklist veya tekil token iptali
    kullanilmadigi icin gercek sahibi olmayan `jti` claim'i eklenmeyecek.
    Degisiklikten once uretilmis access token reddedilirse Android'in mevcut
    authenticator'u gecerli refresh token ile kullaniciyi cikarmadan yeni token
    alacak; refresh token da gecersizse mevcut yeniden giris davranisi
    uygulanacak. Sohbet, bildirim, odeme, cuzdan, rezervasyon ve profil gibi
    kalici kullanici verileri etkilenmeyecek. Endpoint'ler, DTO'lar, JWT subject,
    sureler, refresh rotation/replay korumasi ve Android kodu degismeyecek.
    Dogru/yanlis issuer ve audience, eski claim'siz access token reddi ve gecerli
    refresh ile kesintisiz yenileme kalici guvenlik/regression testleriyle
    dogrulanacak.

27. Kullanilmayan kaynak kod temizligi yapilacak. `UserRepository` icinde tanimli
    olup production kodunda ve testlerde hicbir yerde cagrilmayan
    `existsByEmail(String email)` metodu kaldirilacak. E-posta kontrolu yapan
    mevcut akislar kullandiklari `findByEmail` sorgularini ve veritabani unique
    constraint guvencesini aynen koruyacak. Ayrica `Tour` icindeki kullanilmayan
    `java.util.Collection`, `AdminTourReviewService` ve `TourRepository` icindeki
    kullanilmayan `java.util.List`, `TourSessionService` icindeki kullanilmayan
    `java.time.Instant` ve `TourSessionLifecycleService` icindeki kullanilmayan
    `TourSession` importlari kaldirilacak. Yeni repository metodu, helper veya
    test eklenmeyecek. Git tarafindan izlenen `GoogleLoginRequest`,
    `LoginRequest`, `RefreshTokenRequest`, `EmailService`, `RoleRepository` ve
    `RoleType` Java dosyalarinin eksik dosya sonu newline karakterleri standart
    bicimde tamamlanacak; yerel `.idea` dosyalarina dokunulmayacak. Tablo, kolon,
    sorgu davranisi, endpoint'ler ve Android sozlesmesi degismeyecek. Production
    compile ve mevcut test paketiyle cagri noktasi kalmadigi ve kaynak
    temizliginin davranisi etkilemedigi dogrulanacak.

28. Kalabalik `payment` paketinin mevcut teknik katmanlari korunacak, ancak
    domain sahipligi ve birlikte-degisim sinirlari acik olan dosyalar anlamli alt
    paketlerde gruplanacak. Yeni katman, interface, facade veya wrapper
    olusturulmayacak; sinif adlari ve sorumluluklari degismeyecek.
    `payment/domain` altinda `checkout` (`CheckoutLocale`, `PaymentFxQuote`),
    `payment` (`Payment`, `PaymentEvent`, `PaymentMethod`, `PaymentPurpose`,
    `PaymentStatus`), `provider` (`PaymentProvider`,
    `PaymentProviderCustomer`), `refund` (`Refund`, `RefundStatus`) ve
    `savedcard` (`SavedCardMetadata`, `SavedPaymentMethod`,
    `SavedPaymentMethodStatus`) paketleri kullanilacak.
    `payment/dto` mevcut tour DTO standardiyla uyumlu `request`
    (`IyzicoWebhookRequest`, `TourCheckoutRequest`, `TourPaymentQuoteRequest`,
    `WalletTopUpQuoteRequest`, `WalletTopUpRequest`) ve `response`
    (`CheckoutCurrenciesResponse`, `CheckoutCurrencyOptionResponse`,
    `PaymentCallbackResponse`, `PaymentQuoteResponse`, `PaymentResponse`,
    `SavedPaymentMethodResponse`) paketlerine ayrilacak.
    Service olmayan Spring olaylari `payment/event` altinda toplanacak:
    `ProviderVerifiedEvent`, `RefundRequestedEvent` ve
    `RefundRequestedEventListener`.
    `payment/gateway` altinda `buyer` (`BuyerProfile`, `BuyerProfileProvider`,
    `SandboxBuyerProfileProvider`), `exchange` (`ExchangeRate`,
    `ExchangeRateProvider`, `ExchangeRateUnavailableException`,
    `FrankfurterExchangeRateProvider`), provider sozlesme ve sonuc modelleri icin
    `provider` (`HostedCheckoutCommand`, `HostedCheckoutSession`,
    `HostedPaymentGateway`, `PaymentGatewayException`, `ProviderRefundCommand`,
    `ProviderRefundResult`, `VerifiedPaymentResult`), iyzico adapterleri icin
    `iyzico` (`IyzicoGatewaySupport`, `IyzicoPaymentGateway`,
    `IyzicoSavedCardGateway`) ve `savedcard` (`ProviderCardDetails`,
    `SavedCardGateway`) paketleri kullanilacak.
    `payment/service` altinda `payment` (`HostedPaymentIntent`,
    `PaymentCheckoutService`, `PaymentIntentService`, `PaymentQueryService`,
    `PaymentResultService`, `PaymentVerificationService`,
    `ProviderFailureCodeMapper`), `quote` (`FxCalculation`,
    `PaymentQuoteService`, `PaymentQuoteStateService`), `recovery`
    (`PaymentReconciliationService`, `PaymentReconciliationStateService`,
    `PaymentRecoveryScheduler`, `RefundRecoveryScheduler`), `refund`
    (`PaymentRefundProcessor`, `PaymentRefundService`,
    `PaymentRefundStateService`, `RefundNotificationPublisher`,
    `RefundProcessingCommand`), `savedcard` (`SavedCardDeletion`,
    `SavedPaymentMethodService`, `SavedPaymentMethodStateService`) ve `webhook`
    (`IyzicoWebhookService`, `IyzicoWebhookSignatureVerifier`) paketleri
    kullanilacak.
    `config`, `controller` ve `repository` mevcut katman paketlerinde kalacak.
    Tasima sirasinda package-private sinirlar incelenecek; yalniz import kolayligi
    icin sinif veya metod gorunurlugu genisletilmeyecek, gercekten birlikte
    kalmasi gereken dosyalar ayni pakette tutulacak. Test paketleri ve importlari
    production sahipligini yansitacak sekilde guncellenecek. Endpoint yollari,
    request/response JSON alanlari, JPA tablo/kolonlari, transaction sinirlari,
    odeme ve iade davranisi, iyzico entegrasyonu ve Android sozlesmesi
    degismeyecek. Production compile ile tum mevcut payment ve entegrasyon
    testleri ayni davranisi dogrulayacak; sirf paket tasimasi icin yeni test
    yazilmayacak.

29. Giris yapmis rehberin kendisine ait kaynaklari kullanan API yollari,
    yayimlanmamis tek Android istemcisiyle birlikte tutarli
    `/api/v1/guides/me/...` sozlesmesine tasinacak. `GuideTourController` ve
    `GuideFinanceController` taban yollari `/api/v1/guide` yerine
    `/api/v1/guides/me` olacak; rehberin tur yorumlari
    `/api/v1/guides/me/tours/{tourId}/reviews` yolunu kullanacak. Mevcut
    `/api/v1/guides/me/profile` ve `/api/v1/guides/me/dashboard` yollari ile
    public `/api/v1/guides/search`, `/top` ve `/{guideId}/public-profile`
    sozlesmeleri korunacak. Android `GuideTourApi`, `GuideFinanceApi` ve
    `ReviewApi` Retrofit yollari ayni degisiklikte guncellenecek; eski `/guide`
    yollari icin alias, ikinci controller veya `/api/v2` eklenmeyecek.
    Security matcher'lari public guide endpoint'lerini dar kapsamda acik tutacak,
    `/guides/me/**` yollarini mevcut kimlik/rehber rol kontrolleriyle korumaya
    devam edecek. Controller servis cagrilari, DTO/JSON alanlari, transaction ve
    is kurallari, JWT'ler, PostgreSQL tablolari ile normal ve demo verileri,
    medya, sohbet, bildirim, tur, rezervasyon, odeme ve cuzdan kayitlari
    degismeyecek. Yalniz HTTP yol sozlesmesi standartlasacak; guncellenmis Android
    ile kullanici akisi ayni kalacak. Backend OpenAPI/controller/security
    contract testleri, demo API testleri ve ilgili Android API/repository testleri
    yeni kesin yollarla guncellenecek; eski yollarin yanlislikla acik kalmadigi da
    dogrulanacak.

30. `WalletAccountService` icindeki `credit`, `debit` ve
    `recordMandatoryDebit` metotlarinda birlikte hareket eden islem alanlari,
    `wallet/service` paketindeki `WalletEntryCommand` record'unda toplanacak.
    Command `amountMinor`, `LedgerEntryType`, `referenceType`, `referenceId`,
    `idempotencyKey` ve `occurredAt` alanlarini tasiyacak; `Wallet` ayri servis
    baglami olarak kalacak. CREDIT/DEBIT direction command icine eklenmeyecek;
    islemin niyeti mevcut anlamli metot adlariyla ifade edilmeye devam edecek.
    Tek dosyalik `command` alt paketi, interface, factory, builder veya ek value
    object olusturulmayacak. Production ve testlerdeki mevcut cagri noktalari
    yeni imzaya tasinacak. Bakiye ve available-balance hesaplari, zorunlu debit
    farki, idempotency, transaction/lock sinirlari, ledger entity'si, tablo ve
    kolonlar, endpoint/DTO'lar ve Android davranisi degismeyecek. Mevcut wallet,
    payment ve PostgreSQL concurrency testleri yeni imzayla ayni is kurallarini
    dogrulayacak; yalniz record olusturuldugu icin trivial test yazilmayacak.
