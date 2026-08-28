# GuideMate Gercekci Demo Veri Plani

Bu belge, GuideMate uygulamasini gercek kullanici akislarina yakin verilerle
manuel ve coklu cihaz uzerinden test etmek icin hazirlanacak izole demo
ortaminin tek referansidir. Demo uygulamasi baslamadan once bu belge guncel
backend ve Android kaynaklariyla yeniden dogrulanir.

## Degistirilemez Guvenlik Kurallari

- Mevcut `guidemate_db` veritabani, tablolari, kolonlari, verileri ve mevcut
  medya klasoru hicbir demo adiminda silinmez, sifirlanmaz veya degistirilmez.
- `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, toplu `DELETE`, Flyway `clean`,
  schema reset veya mevcut veriyi yeniden olusturma komutlari ana local ortama
  karsi calistirilmaz.
- Demo yalniz ayri `guidemate_demo` veritabani ve ayri demo medya kokunde
  calisir. Demo profili aktif hedefin tam olarak bu degerler oldugunu
  dogrulamadan seed veya temizleme baslatmaz.
- Aktif veritabani adi `guidemate_db` ise demo seed ve demo temizleme fail-closed
  davranarak calismayi reddeder.
- Demo veritabani veya demo medya klasoru olusturulmadan once kullanicidan acik
  onay alinir. Demo temizligi icin de ayrica acik onay alinir.
- Demo temizligi yalniz `guidemate_demo`, demo medya koku ve bu calisma icin
  eklenen demo dosyalarini kapsar. Normal local ortam ve production davranisi
  temizleme kapsaminda degildir.
- Ilk yazma isleminden once temiz Git commit'i, ana veritabani yedegi ve mevcut
  medya envanteri kaydedilir. Temizlik sonrasinda bu baslangic durumu yeniden
  dogrulanir.
- Iyzico Sandbox veya e-posta gibi harici servislerde kalan test kayitlari local
  kodu, ana veritabanini ya da uygulama isleyisini degistirmez; buna ragmen
  hangi dis etkinin kalabilecegi testten once acikca belirtilir.

## Kapsam

- Demo nufusu tam olarak 250 turist ve 50 rehberdir.
- Kontrollu admin seed'i bu 300 kullanicinin disindadir.
- Veri seti gercekci fonksiyonel, UX, sayfalama, filtreleme ve coklu cihaz
  testleri icindir; yuk veya performans testi degildir.
- Kullanici tarafindan doldurulabilen avatar, hakkimda, diller, uzmanliklar,
  aciklamalar ve tur medyalari mantiken uygulanabildigi her kayitta dolu olur.
- Yalniz belirli lifecycle durumlarinda anlamli olan red nedeni, iptal zamani,
  refund veya provider alanlari zorla doldurulmaz.
- Puan, yorum sayisi, tur sayisi, kapasite kullanimi, seviye, bakiye, kazanc ve
  diger turetilmis degerler dogrudan yazilmaz. Yetkili temel kayitlar uretilir
  ve mevcut backend kurallari bu degerleri hesaplar.
- Demo verisi backend tarafinda uretilir. Android'e mock repository, sahte veri
  kaynagi veya demo-ozel UI kodu eklenmez; Android normal API sozlesmesini
  tuketir.

## Medya Karari

- Profil fotograflari gercek kisilere ait olmayan sentetik avatarlardir.
- Tur kapak fotograflari Eyfel Kulesi, Sultanahmet Camii ve benzeri
  gercek destinasyonlari gosteren lisansi uygun Wikimedia Commons dosyalarindan
  secilir.
- Wikimedia runtime bagimliligi eklenmez ve hotlink yapilmaz. Dosyalar hazirlik
  sirasinda bir kez indirilir, demo medya kokune alinir ve mevcut backend medya
  akisi uzerinden iliskilendirilir.
- Her dosya icin kaynak URL, eser sahibi, lisans ve lisans URL'si deterministik
  bir manifestte saklanir. Oncelik Public Domain/CC0, ardindan uygun atifla
  CC BY veya CC BY-SA'dir.

## Uygulama ve Temizlik Siniri

- Demo icin yazilacak kod ayri profil, paket, konfigurasyon, manifest ve
  temizleme sinirlarinda tutulur; production is kurallari degistirilmez.
- Yeni schema ihtiyaci beklenmemektedir. `guidemate_demo`, mevcut Flyway
  migration'lariyla production ile ayni schema yapisina sahip olur.
- Test sirasinda kaydedilen yeni kullanici ve islemler de `guidemate_demo` ve
  demo medya kokunde kalir.
- Test bitince kullanici onayiyla demo veritabani, demo medya koku ve demo-ozel
  kod/dosyalar kaldirilir. Ana local ortam demo oncesindeki haliyle korunur.
- Tarama gercek bir production veya Android entegrasyon hatasi bulursa demo
  degisikligine karistirilmaz; once raporlanir ve yalniz ayri onayla duzeltilir.

## Calisma Sirasi

1. Bu belgeyi olustur ve guvenlik sinirlarini sabitle.
2. Backend tablo, iliski, servis, lifecycle ve hesaplanan degerlerini salt
   okunur tara.
3. Android ekran, DTO, repository ve kullanici akislarini salt okunur tara.
4. Ekran -> endpoint -> DTO -> yetkili tablo/iliski -> hesaplanan deger
   eslesmesini tamamla ve kullaniciya sun.
5. 250 turist/50 rehber dagilimini ve butun anlamli senaryolari tasarla.
6. Medya katalogu ve lisans manifestini kesinlestir.
7. Demo profilini, fail-closed korumalari, idempotent seed ve kontrollu
   temizleme aracini uygula.
8. Kullanici onayiyla `guidemate_demo` ve demo medya kokunu olustur; Flyway
   migration'larini yalniz demo veritabaninda calistir.
9. Veriyi domain bazinda dikey uret ve her grup sonrasinda iliski, hesaplama,
   yetki ve API sonuclarini dogrula.
10. Android ve coklu cihaz kullanici testlerini tamamla.
11. Ayrica kullanici onayiyla yalniz demo ortam ve demo-ozel kodu temizle;
    baslangic durumunun korundugunu dogrula.

## Backend Envanteri

### Genel yapi

- Backend 13 feature kokunde production Java kaynaklari icerir: `auth`, `chat`,
  `common`, `demo`, `media`, `notification`, `payment`, `profile`,
  `reservation`, `review`, `tour`, `user` ve `wallet`.
- Schema Flyway V1-V14 ile kurulur. Demo icin yeni tablo veya migration ihtiyaci
  beklenmemektedir; ayri demo veritabani ayni migration setiyle kurulacaktir.
- Mevcut `demo` paketi yalniz bir rehber ve bir turist olusturan local seed'dir.
  Aktif local veritabanina yazabildigi icin 300 kullanicilik demo icin oldugu
  gibi kullanilmayacaktir. Sonraki uygulama, ayri `demo` profili ve fail-closed
  veritabani/medya hedef kontrolleri ile yapilacaktir.

### Yetkili tablo gruplari

| Alan | Yetkili tablolar | Demo amaci |
| --- | --- | --- |
| Kimlik ve rol | `roles`, `users` | 250 ACTIVE turist, 50 ACTIVE rehber; kontrollu admin ayri |
| Auth yasam dongusu | `confirmation_tokens`, `password_reset_tokens`, `refresh_tokens` | Yalniz gercek auth akisinda olusur; toplu sahte token yazilmaz |
| Medya | `media_assets` | Turist/rehber kullanici avatarlari ve tekil tur kapaklari |
| Rehber profili | `guide_profiles`, `guide_languages` | Biyografi, sehir, uzmanlik ve diller |
| Tur | `tours`, `tour_languages`, `tour_sessions`, `tour_change_requests` | Farkli onay, yayin, gecmis/gelecek ve degisiklik durumlari |
| Rezervasyon ve yorum | `reservations`, `reviews` | Katilimci, snapshot, iptal, tamamlanma ve puan senaryolari |
| Odeme | `payments`, `payment_events`, `refunds`, `payment_fx_quotes` | Wallet/kart, quote, basari/basarisizlik/iade senaryolari |
| Kayitli kart | `payment_provider_customers`, `saved_payment_methods` | Yalniz gercek iyzico Sandbox kart saklama akisiyla |
| Cuzdan ve finans | `wallets`, `wallet_ledger_entries`, `guide_earnings`, `bank_accounts`, `withdrawals` | Bakiye, kazanc, ters kayit, banka ve cekim durumlari |
| Bildirim | `notification_preferences`, `device_registrations`, `notifications` | Tercihler, okunmus/okunmamis kayitlar ve gercek cihaz FID'leri |
| Mesajlasma | `chat_conversations`, `chat_messages`, `chat_read_state` | Iki yonlu konusmalar, mesaj gecmisi ve okunmamis sayilari |

V11 sonunda aktif cihaz tablosunun adi `device_registrations`'dir;
`device_tokens` yalniz eski migration adidir.

### Durum ve lifecycle kapsami

- Kullanici hesaplari `PENDING_VERIFICATION`, `ACTIVE`, `DISABLED`; roller
  `TOURIST`, `GUIDE`, `ADMIN` durumlarini destekler. Ana 300 kisilik kullanici
  nufusu gercek ekranlari kullanabilmek icin ACTIVE ve rol secimi tamamlanmis
  olur. Auth hata senaryolari gerekirse ayrica adlandirilmis teknik hesaplarla
  temsil edilir.
- Turlar `PENDING_REVIEW`, `APPROVED`, `REJECTED`, `ARCHIVED`; session'lar
  `OPEN_FOR_BOOKING`, `CLOSED`, `COMPLETED`, `CANCELLED`; degisiklik talepleri
  `PENDING`, `APPROVED`, `REJECTED`, `CANCELLED` dagilimlarini kapsar.
- Rezervasyonlar `PENDING_PAYMENT`, `CONFIRMED`, `COMPLETED`, `CANCELLED`,
  `EXPIRED`; odemeler `PENDING`, `REQUIRES_ACTION`, `VERIFYING`, `SUCCEEDED`,
  `FAILED`, `CANCELLED`, `TIMEOUT` dagilimlarini tutar.
- Iadeler `REQUESTED`, `PROCESSING`, `SUCCEEDED`, `FAILED`, `MANUAL_REVIEW`;
  rehber kazanclari `PENDING`, `AVAILABLE`, `REVERSED`; para cekimleri
  `PENDING`, `PROCESSING`, `COMPLETED`, `FAILED`, `CANCELLED` durumlarini
  gercek neden-sonuc iliskileriyle kapsar.
- Kayitli kartlarda `ACTIVE`, `DELETED`, `EXPIRED`; bildirim push durumunda
  `NOT_REQUESTED`, `PENDING`, `SENT`, `FAILED` kullanilir.

### Dogrudan yazilmayacak turetilmis degerler

- Rehber seviyesi gercek tamamlanan session, ortalama puan ve yorum sayisindan
  hesaplanir. Esikler: LEGENDARY icin en az 100/4.8/30, SUPER icin
  20/4.5/10, SILVER icin 5/3.7/3; diger onayli rehberler APPROVED olur.
- Rehber performansi `COMPLETED` session sayisi, `COMPLETED` rezervasyonlardaki
  katilimci sayisi ve gercek yorumlardan uretilir.
- Tur ve rehber siralamasi gercek yorum, tamamlanma ve katilim kayitlarini
  kullanir. Puanlari veya siralama sonucunu demo seed dogrudan yazmaz.
- Dashboard aktif/pending sayilari tur, session ve degisiklik taleplerinden;
  aylik kazanc `guide_earnings` kayitlarindan ve REVERSED haric tutularak
  hesaplanir.
- Dolu kapasite CONFIRMED/COMPLETED rezervasyonlar ile suresi dolmamis
  PENDING_PAYMENT hold'larindan hesaplanir. `bookedCount` ve kalan kapasite
  elle uydurulmaz.
- Rezervasyon toplami session birim fiyati ile katilimci sayisindan uretilir.
  Rezervasyon snapshot alanlari ilgili rezervasyon akisi olusturulurken
  sabitlenir.
- Cuzdan bakiyesi ledger credit toplamindan debit toplami cikarilarak; kullanilabilir
  bakiye buna ek olarak PENDING/PROCESSING cekimler dusulerek hesaplanir.
- Rehber kazanci rezervasyon brut tutari, yapilandirilmis platform komisyonu ve
  gercek lifecycle uzerinden uretilir. Session tamamlaninca kullanilabilir olur;
  iade/iptalde tersine cevrilir.
- Aylik kazanc, tur karti kazanci ve islem basligi mevcut earning, ledger,
  reservation snapshot ve tour kayitlarindan uretilir.
- Chat ve bildirim okunmamis sayilari mesaj/read-state ile notification
  `read_at` kayitlarindan hesaplanir.

### Gercek akistan uretilmesi gereken kayitlar

- Confirmation, sifre sifirlama ve refresh tokenlari ancak ilgili auth islemiyle
  olusur; kalici demo icerigi gibi topluca doldurulmaz.
- `payment_provider_customers`, `saved_payment_methods`, iyzico provider tokenlari,
  gercek callback/webhook eventleri ve 3DS sonucu sahte degerlerle doldurulmaz.
  Secili test hesaplarinda iyzico Sandbox akisi bunlari olusturur.
- `device_registrations` gercek Android Firebase Installation ID ile olusur.
  Sahte FID, FCM basarisi varmis gibi bir sonuc uretmek icin kullanilmaz.
- Tarihsel uygulama ici bildirimler `NOT_REQUESTED` olarak kurulabilir; gercek
  push teslimi yalniz Firebase baglantili cihaz testinde dogrulanir.
- Payment event, refund, ledger, earning ve lifecycle kayitlari kendi aralarinda
  tutarli bir neden-sonuc zinciri olmadan bagimsiz satirlar olarak yazilmaz.

## Android Envanteri

### Genel yapi

- Android uygulamasi feature-first yapida 535 Kotlin/Java kaynak dosyasi,
  41 `*Screen.kt`, 37 ViewModel ve 13 Retrofit API tanimi icerir.
- Auth, chat, media, notification, payment, profile, reservation, review, tour
  ve wallet feature'larinda domain repository arayuzu, data repository
  implementasyonu ve Retrofit API katmani bulunur.
- Demo verisi Android tarafina eklenmeyecektir. Ekranlar mevcut repository ve
  mapper zinciri uzerinden normal backend endpoint'lerini kullanmaya devam eder.

### Ekran gruplari

- Auth: onboarding, giris, kayit, sifre unutma, rol secimi ve sifre degistirme.
- Ortak: sohbet listesi/detayi, bildirim listesi/onizlemesi ve bildirim ayarlari.
- Turist: ana sayfa, kesfet/filtre, tur detayi, rehber public profil, checkout,
  hosted odeme/durum, geziler, rezervasyon detayi/yorum, cuzdan/islemler,
  kayitli kartlar ve profil.
- Rehber: ana sayfa/dashboard, profil/hakkinda/onizleme, tur listesi/detay/
  duzenleme/yayinlama, cuzdan/islemler, aylik kazanc ve banka hesaplari.
- Onboarding, yasal metinler ve yardim/destek gibi statik ekranlar demo
  veritabanindan veri beklemez.

### Mevcut urun sinirlari

- Favori tablosu, endpoint'i, repository'si veya Android favori ozelligi yoktur.
  Demo plani favori kaydi uretmeyecektir.
- Turist ve rehber avatarini ortak kullanici kimligi tasir. Android kamera veya
  galeriden sectigi yerel resmi `USER_AVATAR` amaciyla yukler; backend kalici
  `mediaAssetId`/URL uretir ve `/api/v1/users/me/avatar` ile kullaniciya baglar.
- Medya feature'i yalniz `USER_AVATAR` ve `TOUR_COVER` amaclarini destekler.
  Tur galerisi yoktur; her tur icin tek kapak kullanilir.
- Android admin ekrani yoktur. Backend admin tur inceleme endpoint'leri mevcut
  olsa da 300 kisilik mobil demo akisi admin UI eklemeyecektir.
- Chat UI'daki PENDING/FAILED gonderim durumlari Android'in yerel durumudur;
  backend'in kalici mesaj teslim durumu SENT'tir.

## Ekran ve Veri Eslesmesi

| Android ekran/akis | Endpoint ve ana response | Yetkili tablo/iliski | Demo senaryosu ve turetilmis deger |
| --- | --- | --- | --- |
| SignIn, SignUp, ForgotPassword, RoleSelection, ChangePassword | `/api/v1/auth/*`; `AuthResponse`, `CurrentUserResponse` | `users`, `roles`, auth token tablolari | ACTIVE turist/rehber girisleri; teknik auth durumlari ayri hesaplarla; tokenlar gercek akista |
| TouristHome | `/api/v1/tours/popular`, `/api/v1/guides/top`, `/api/v1/auth/me`; `TourSearchItemResponse`, `GuideSearchItemResponse` | `tours`, `tour_sessions`, `guide_profiles`, `reviews`, `reservations` | Farkli sehir/kategori/fiyat/puan ve doluluk; populerlik gercek kayitlardan |
| TouristExplore ve TouristFilter | `/api/v1/tours/search`, `/api/v1/guides/search`; sayfali arama DTO'lari | Tur, session, rehber profil/language, review ve reservation iliskileri | Sayfalama, bos/dolu sonuc, konum, dil, tarih, fiyat ve siralama kombinasyonlari |
| TouristTourDetail | `/api/v1/tours/{id}`, `/api/v1/tour-sessions/{id}`, `/api/v1/tours/{id}/reviews`; `TourDetailResponse`, `TourSessionResponse`, `TourReviewResponse` | Tur/session, guide profile, cover media, reviews, reservations | Tek kapak, acik/kapali/dolu session, puan/yorum ve kapasite gercek kayitlardan |
| GuidePublicProfile | `/api/v1/guides/{id}/public-profile`, `/api/v1/tours/popular`, `/api/v1/tours/{id}/reviews`; `GuideProfileResponse`, `GuidePerformanceSummary` | Guide profile/languages/avatar, tours, sessions, reviews, reservations | Dolu biyografi/diller/uzmanlik; APPROVED/SILVER/SUPER/LEGENDARY gercek esiklerden |
| TourCheckout, HostedPayment, PaymentStatus, SavedCards | `/api/v1/payments/checkout/*`, `/api/v1/payments/{id}`, `/api/v1/payment-methods/cards`; payment/quote/card DTO'lari | Payments, FX quotes, reservations, wallets, provider customer/cards | Wallet ve hosted card, coklu charge para birimi, basari/basarisizlik/iade; provider kartlari yalniz Sandbox akisi |
| TouristTrips ve ReservationDetail | `/api/v1/reservations/me`, `/api/v1/reservations/{id}`, cancel; `ReservationResponse`, `ReservationSnapshotResponse` | Reservations, tour/session snapshot, payments/refunds | Upcoming/completed/cancelled/expired; iptal penceresi, aktor ve refund sonucu tutarli |
| Review form ve tur yorumlari | `/api/v1/reservations/{id}/reviews`, `/api/v1/tours/{id}/reviews`; `ReviewResponse`, `TourReviewResponse` | Completed reservations ve reviews | Yalniz uygun tamamlanmis rezervasyona tek yorum; dagilim puan/ranking hesaplarini besler |
| TouristWallet ve islemler | `/api/v1/wallet`, `/api/v1/wallet/transactions`, top-up endpoint'leri; `WalletResponse`, `WalletTransactionResponse` | Wallet, ledger, payments, refunds, reservation snapshots | Bakiye elle yazilmaz; top-up/satin alma/iade hareket zincirinden hesaplanir |
| TouristProfile | `/api/v1/auth/me`, `/api/v1/users/me/avatar`, `/api/v1/media`, `/api/v1/wallet`; current user/media/wallet DTO'lari | Users, media ve wallet/ledger | Ad/soyad/e-posta, ortak kullanici avatari ve hesaplanan bakiye; avatar kamera/galeriden normal API ile degisir |
| GuideHome | `/api/v1/guides/me/dashboard`; `GuideDashboardResponse` | Tours, sessions, change requests, reservations, reviews, earnings | Aktif/pending sayilari, performans ve aylik kazanc temel kayitlardan hesaplanir |
| GuideProfile, GuideAbout, GuideProfilePreview | `/api/v1/guides/me/profile`, `/api/v1/users/me/avatar`, `/api/v1/media`; `GuideProfileResponse` ve media DTO'lari | Guide profile/languages, users avatar referansi, media ve performans iliskileri | Tum istege bagli profil alanlari dolu; ortak kullanici avatari demo medya kokunden sunulur |
| GuideMyTours, GuideTourDetail, GuideTourEdit | `/api/v1/guide/tours*`, session/change/archive endpoint'leri; `GuideTourCardResponse`, `TourProposalResponse` | Tours, sessions, change requests, reservations, reviews, earnings | Aktif/inceleme/gecmis sekmeleri; onay/red/arsiv, doluluk, puan ve net kazanc tutarli |
| GuideTourPublish Step 1-4 | `/api/v1/media`, `/api/v1/guide/tours`, session endpoint'i; create request/response DTO'lari | Media, tours, languages, sessions | Demo onceden zengin yayinlar sunar; manuel testte yeni tur normal API ile ayni demo DB'ye eklenir |
| GuideMyWallet ve islemler | `/api/v1/wallet`, `/api/v1/wallet/transactions`; wallet/transaction DTO'lari | Wallet, ledger, earnings, reservations | PENDING/AVAILABLE/REVERSED kazanclar ve hesaplanan kullanilabilir bakiye |
| GuideEarnings | `/api/v1/guide/earnings`, `/api/v1/guide/earnings/monthly`; earning DTO'lari | Guide earnings, reservations, sessions | Aylik siralama ve session bazli net kazanc; REVERSED kayitlar toplama dahil edilmez |
| GuideBankAccounts ve para cekme | `/api/v1/guide/bank-accounts`, `/api/v1/guide/withdrawals`; bank/withdrawal DTO'lari | Bank accounts, withdrawals, wallet ledger | Varsayilan banka, gecersiz/silinmis durumlar ve SIMULATED cekim lifecycle'i |
| ChatList ve ChatDetail | `/api/v1/chats*` REST + STOMP; chat DTO'lari | Conversations, messages, read state ve users avatar referansi | Turist-rehber iki yonlu konusmalar, iki tarafin avatari, sayfalama ve okunmamis sayisi; cihaz testi gercek WebSocket ile |
| Bildirim listesi ve ayarlar | `/api/v1/notifications*`, `/api/v1/devices/fcm-registration`; notification/preference DTO'lari | Notifications, preferences, device registrations | Okunmus/okunmamis ve farkli semantic tipler; gercek push yalniz gercek cihaz FID/FCM ile |
| Onboarding, LegalAgreements, HelpSupport | Backend endpoint'i yok | Veritabani kaydi yok | Statik Android kaynaklari; demo seed kapsaminda degil |

### Eslesme sonucu

- Android'in kullandigi user-facing akislarda backend endpoint, DTO ve yetkili
  tablo karsiliklari mevcuttur. Tarama sirasinda bulunan turist avatar boslugu,
  turist ve rehber icin ortak kullanici-avatar sozlesmesiyle kapatilmistir.
- Demo yeni kullanici kayitlarini engellemez. Test sirasinda normal auth ile
  olusturulan kullanici ve islemler yalniz aktif `guidemate_demo` veritabanina
  ve demo medya kokune kaydolur.
- Sonraki adimda once 250 turist/50 rehber icin deterministik senaryo dagilimi,
  test hesap katalogu ve domainler arasi neden-sonuc matrisi tasarlanacaktir.
  Bu dagilim kullaniciya sunulup onaylanmadan seed kodu yazilmayacaktir.

## Acik Kararlar

- Ilk dort madde tamamlanmistir; bu belge kullaniciya sunulmadan ve sonraki
  senaryo dagilimi ayrica onaylanmadan demo kodu yazilmaz.
- Demo veritabani veya medya klasoru kullanicinin ayri onayi olmadan
  olusturulmaz.
