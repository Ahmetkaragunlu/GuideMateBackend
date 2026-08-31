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
- Tur kapak fotograflari yalniz Turkiye'deki gercek destinasyonlari gosteren,
  lisansi uygun Wikimedia Commons dosyalarindan secilir.
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

Bu 37 adim, demo calismasinin degistirilmeden izlenecek ana sirasidir.

### Birinci calisma: Salt okunur hazirlik

1. `DEMO.md` olusturulur.
2. Backend tamamen taranir.
3. Android tamamen taranir.
4. Ekran, endpoint, DTO, tablo ve hesaplanan deger eslesmesi cikarilir.

Bu asamada kod, medya ve veritabani degismez.

### Ikinci calisma: Veri tasarimi

5. 250 turist ve 50 rehberin dagilimi belirlenir.
6. Butun anlamli kullanici ve lifecycle senaryolari hazirlanir.
7. Backend'in hesapladigi alanlar ve bunlari olusturacak yetkili temel kayitlar
   belirlenir.
8. Avatar, tur gorselleri ve lisans manifesti planlanir.

Bu asamada da kod, medya ve veritabani degismez. Bu belgedeki kesin veri
tasarimi ikinci calismanin ciktisidir.

### Ucuncu calisma: Guvenli demo altyapisi

9. Baslangic Git durumu, eski veritabani ve medya bilgileri kaydedilir.
10. Eski veritabaninin yedegi alinir.
11. Ayri `demo` profili ve fail-closed guvenlik kontrolleri yazilir.
12. Demo temizleme yontemi hazirlanir ve guvenli hedefe karsi test edilir.

Burada yalniz demo kodlari yazilir. Ana veritabanina ve ana medya kokune
dokunulmaz.

### Dorduncu calisma: Demo ortamini kurma

13. Kullanicidan acik olusturma onayi alinir.
14. `guidemate_demo` olusturulur.
15. Mevcut Flyway migration'lari bos demo veritabaninda calistirilir.
16. Ayri demo medya klasoru olusturulur.
17. Aktif hedefin kesinlikle `guidemate_demo` ve demo medya koku oldugu yeniden
    dogrulanir.

### Besinci calisma: Verileri dikey olusturma

18. Roller, kullanicilar ve profiller olusturulur.
19. Avatarlar ve medya kayitlari olusturulur.
20. Turlar, tur gorselleri ve session'lar olusturulur.
21. Rezervasyonlar, kapasite ve yorumlar olusturulur. Mevcut urunde favori
    ozelligi olmadigi icin favori kaydi uretilmez.
22. Odeme, wallet, iade, kazanc, banka hesabi ve para cekme zincirleri
    olusturulur.
23. Sohbet, mesaj, bildirim ve gercek cihazla olusacak kayitlar hazirlanir.
24. Admin inceleme ve diger lifecycle durumlari olusturulur.

Her grup eklendikten sonra iliskiler ve turetilmis degerler dogrulanir; tum veri
tek seferde yazilip hata arama en sona birakilmaz.

### Altinci calisma: Dogrulama

25. 300 ana kullanici ve butun iliskiler sayisal olarak kontrol edilir.
26. Backend hesaplamalari dogrulanir.
27. Endpoint, pagination, filtre, yetki ve OpenAPI kontrolleri yapilir.
28. Onemli test hesaplarinin kisa katalogu hazirlanir.
29. Android normal API sozlesmesiyle demo backend'e baglanir.

### Yedinci calisma: Kullanici testi

30. Turist, rehber ve backend admin akislarinin kullanici testleri yapilir.
31. Iki cihazli mesajlasma ve bildirim test edilir.
32. Rezervasyon, odeme, iade ve wallet test edilir.
33. Bos, hata, sinir ve lifecycle durumlari test edilir.

### Son calisma: Temizlik

34. Kullanicidan ayri silme onayi alinir.
35. Yalniz demo veritabani ve demo medya klasoru silinir.
36. Butun demo-ozel kod ve dosyalar kaldirilir.
37. Git, eski veritabani ve eski medya baslangic durumuyla karsilastirilir.

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
  mevcut akisin uretebildigi `PENDING`, `APPROVED` ve `REJECTED` dagilimlarini
  kapsar. Kodda uretilmeyen `TourChangeRequestStatus.CANCELLED` sirf enum degeri
  var diye sahte kayitla temsil edilmez.
- Rezervasyonlar `PENDING_PAYMENT`, `CONFIRMED`, `COMPLETED`, `CANCELLED`,
  `EXPIRED`; odemeler `PENDING`, `REQUIRES_ACTION`, `VERIFYING`, `SUCCEEDED`,
  `FAILED`, `CANCELLED`, `TIMEOUT` dagilimlarini tutar.
- Iadeler ve hosted odeme ara durumlari gercek Sandbox veya mevcut provider
  akisi uretebildigi olcude kapsanir. Rehber kazanclari `PENDING`, `AVAILABLE`,
  `REVERSED` olarak gercek neden-sonuc iliskileriyle uretilir. Mevcut para cekme
  servisi SIMULATED istegi ayni islemde tamamladigi icin kalici seed yalniz
  `COMPLETED` para cekimleri uretir; `PENDING`, `PROCESSING`, `FAILED`,
  `CANCELLED` ve `IYZICO` payout sahte satirlarla doldurulmaz.
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

## Kesin Demo Veri Tasarimi

### Deterministik kimlik ve zaman

- Ana veri seti tam olarak 250 ACTIVE/rol secmis turist ve 50 ACTIVE/rol secmis
  rehberden olusur. Bu 300 hesap mobil uygulamanin normal giris ve ekran
  akislarini kullanir.
- Turist ve rehber adlari Turkcedir. Ana 300 kullanicinin soyadlari birbirinden
  farklidir; dolayisiyla ayni ad-soyad cifti bulunmaz.
- Kontrollu ACTIVE admin ve yalniz auth hata senaryolarinda kullanilan teknik
  hesaplar 300 ana kullanicinin disindadir; arama, tur, chat ve finans verisine
  katilmaz.
- Seed kimlikleri rastgele her calismada degismez. Kullanici, tur, session,
  rezervasyon ve diger kayit UUID'leri sabit namespace + anlamli seed anahtarindan
  deterministik uretilir. E-posta ve idempotency anahtarlari da ayni katalogdan
  gelir.
- Tarihler tek bir `demo.reference-instant` degerine gore uretilir. Gecmis veri
  onceki 18 aya, gelecek veri sonraki 120 gune yayilir. Dagitik `Instant.now()`
  kullanimi veya her seed calismasinda farkli sonuc yoktur.
- Demo parolasi yalniz Git disindaki demo secret/config degerinden gelir; belgeye,
  loga veya kaynak koda gercek parola yazilmaz.

### Turist dagilimi

Kohortlar birincil test amacini anlatir; ayni turist, kendi neden-sonuc zinciri
gerektiriyorsa birden fazla ozellige ait kayit tasiyabilir.

| Kohort | Kisi | Temel senaryo |
| --- | ---: | --- |
| `NEW_EXPLORER` | 25 | Avatar ve kimlik dolu; rezervasyon, chat ve islem gecmisi olmayan bos durumlar |
| `CHAT_ONLY` | 35 | Satin alma yapmadan bir veya daha fazla rehberle gorusen turistler |
| `UPCOMING_TRAVELER` | 65 | Gelecek CONFIRMED rezervasyonlar, farkli katilimci ve doluluk durumlari |
| `EXPERIENCED_REVIEWER` | 70 | Tamamlanmis geziler; yorum yazilmis ve yorum bekleyen rezervasyonlar |
| `CANCELLATION_REFUND` | 35 | 48 saat oncesi/sonrasi iptal, FULL_REFUND/NO_REFUND ve expired hold senaryolari |
| `FINANCE_POWER_USER` | 20 | Sayfalama olusturacak wallet, odeme, iade ve gezi gecmisi |
| **Toplam** | **250** | |

- Tum 250 turistin kullanici avatari READY durumunda ve ortak user-avatar
  sozlesmesine baglidir. Bos durum kullanicilari yalniz ilgili is kayitlarindan
  yoksundur; kimlik/profil sunumu eksik veya kirik bir kullanici gibi kurulmaz.
- Secili yuksek hacimli turistlerde en az 21 gecmis gezi, 21 bildirim ve 21
  wallet hareketi bulunur; boylece varsayilan 20 kayitlik sayfalama gercekten
  test edilir.
- Pending verification, rol secilmemis ve disabled giris senaryolari ana turist
  sayisina katilmaz. Normal auth akisi pending hesaba turist/rehber rolu
  sectirmedigi icin bu sinir bilerek korunur.

### Rehber dagilimi

| Birincil kohort | Kisi | Temel senaryo |
| --- | ---: | --- |
| `NEW_PROFILE` | 5 | Profili, dilleri ve avatari dolu; henuz turu veya kazanci yok |
| `MODERATION_FOCUSED` | 8 | Pending/rejected tur ve pending/approved/rejected degisiklik talepleri |
| `ACTIVE_OPERATOR` | 19 | Yayindaki turlar, acik/kapali session'lar ve gelecek rezervasyonlar |
| `CANCELLATION_ARCHIVE` | 7 | Rehber iptali, iade zinciri, iptal session ve arsiv tur gecmisi |
| `FINANCE_FOCUSED` | 6 | Aylara yayilan kazanc, banka hesabi ve SIMULATED cekim gecmisi |
| `HIGH_VOLUME` | 5 | Tur, session, yorum, bildirim ve chat sayfalamasini zorlayan hesaplar |
| **Toplam** | **50** | |

Rehber seviyesi bu kohortlardan bagimsiz ikinci bir dagilimdir ve `GuideLevel`
alana yazilmaz:

| Beklenen seviye | Rehber | Yetkili temel veri |
| --- | ---: | --- |
| `APPROVED` | 35 | Yeni/dusuk gecmis veya session, puan ya da yorum esiklerinden en az birini saglamayan gercek sinir senaryolari |
| `SILVER` | 10 | En az 5 tamamlanmis session, 3 yorum ve 3.7 ortalama |
| `SUPER` | 4 | En az 20 tamamlanmis session, 10 yorum ve 4.5 ortalama |
| `LEGENDARY` | 1 | En az 100 tamamlanmis session, 30 yorum ve 4.8 ortalama |
| **Toplam** | **50** | |

- APPROVED grubunda ayri ayri session esigini, puan esigini ve yorum sayisi
  esigini kaciran yakin-sinir ornekleri bulunur. Boylece seviye yalniz mutlu
  yoldan degil tum karar kosullarindan dogrulanir.
- Tum rehberlerin biyografi, uzmanlik basligi, Turkce dahil 4 dil ve READY kullanici avatari
  vardir. Yalniz NEW_PROFILE kohortunda tur/banka/kazanc bos ekranlari bilincli
  olarak korunur.

### Auth destek hesaplari

Ana 300 hesaba ve admin'e ek olarak yalniz test katalogunda gorunen bes teknik
hesap bulunur:

- Iki `PENDING_VERIFICATION` hesap: biri gecerli yeniden gonderim/dogrulama,
  digeri suresi dolmus token davranisi icin kullanilir.
- Bir ACTIVE fakat rolu secilmemis hesap rol secimi ekranini test eder.
- Iki `DISABLED` hesap farkli onceki rol gecmisleriyle login ve confirmation
  engelini test eder; hicbir public tur, finans veya chat verisine katilmaz.
- Confirmation, reset ve refresh tokenlari kalici katalog verisi gibi yazilmaz;
  ilgili auth testi baslatildiginda servis akisi tarafindan olusturulur.
- Google subject ve Google hata senaryolari sahte tokenla kurulmaz; gercek Google
  ID token testi gerektiginde uygun ACTIVE teknik hesap kullanilir.

### Tur, konum ve session katalogu

- Toplam 180 tur bulunur: 130 `APPROVED`, 20 `PENDING_REVIEW`, 15 `REJECTED`
  ve 15 `ARCHIVED`.
- Alti mevcut kategori esit dagilir: `culture`, `food`, `nature`, `art`,
  `entertainment`, `adventure` kategorilerinin her birinde 30 tur vardir.
- Turkiye'den 24 gercek destinasyon; `TR` ulke kodu, `Europe/Istanbul` saat
  dilimi ve deterministik demo place kimligiyle kullanilir. Sultanahmet,
  Ayasofya, Galata, Kapadokya, Efes, Pamukkale, Kaleici, Bodrum, Oludeniz,
  Troya, Cumalikizik, Safranbolu, Selimiye, Mevlana, Anitkabir, Mardin,
  Gobeklitepe, Zeugma, Nemrut, Sumela, Ayder, Ani, Akdamar ve Amasya kapsanir.
- Tur basliklari, aciklamalari, bulusma ve iptal nedenleri, degisiklik/inceleme
  metinleri, yazili yorumlar, rehber unvanlari ve biyografileri, sohbet
  mesajlari ile bildirim onizlemeleri Turkcedir.
- Her tur Turkce dahil 2, 3 veya 4 dil destekler ve bu diller rehber dilinin alt
  kumesidir. `tr`, `en`, `fr`, `es`, `it`, `de`, `pt`, `nl`, `el`, `ja`, `ko`,
  `ar`, `no` kodlari dengeli dagitilir; tek dilli demo turu uretilmez.
- Fiyatlar USD minor unit olarak 1500-35000, sureler 60-480 dakika, kapasiteler
  1-20 araligindadir. Siralama ve filtre testleri icin sinir ve orta degerler
  dengeli kullanilir.
- Toplam 560 session bulunur: 365 `COMPLETED`, 150 `OPEN_FOR_BOOKING`, 25
  `CLOSED` ve 20 `CANCELLED`.
- 150 acik session; bos, kismen dolu, neredeyse dolu, sold-out ve suresi
  dolmamis pending-payment hold nedeniyle kapasitesi azalmis gruplara dagilir.
  Doluluk sayisi elle yazilmaz.
- CANCELLED session'lar mevcut rehber iptal akisi ve `GUIDE` aktoruyle uretilir.
  Kodda kullaniciya acik olmayan `ADMIN` session iptal aktoru sahte kayitla
  eklenmez.
- Toplam 30 tur degisiklik talebi bulunur: 10 `PENDING`, 10 `APPROVED`, 10
  `REJECTED`. Kodun uretmedigi `CANCELLED` durumu eklenmez.

### Rezervasyon, yorum ve kapasite katalogu

- Toplam 1300 rezervasyon hedeflenir: 850 `COMPLETED`, 300 `CONFIRMED`, 20
  suresi dolmamis `PENDING_PAYMENT`, 40 `EXPIRED` ve 90 `CANCELLED`.
- Participant count 1-5 arasinda dagilir; `totalPriceMinor` her zaman session
  birim fiyati x participant count ile uretilir.
- 90 iptalin 35'i turist FULL_REFUND, 20'si turist NO_REFUND, 10'u odeme
  tamamlanmadan turist NOT_APPLICABLE ve 25'i rehber session iptali nedeniyle
  FULL_REFUND zinciridir. Mevcut uygulama akisi uretmedigi icin `ADMIN` veya
  `SYSTEM` aktorlu sahte iptal eklenmez.
- Rezervasyon snapshot'i satin alma anindaki tur basligi, kapak, rehber adi ve
  avatari, konum, saat dilimi, session ve fiyat bilgilerini korur. Sonraki tur
  veya avatar degisikligi tarihsel snapshot'i geriye donuk degistirmez.
- Toplam 420 yorum, yalniz `COMPLETED` ve daha once yorumlanmamis rezervasyonlara
  baglanir. 1-5 puanlar, yalniz puan ve puan+yorum cesitleri bulunur.
- En az bir turun 21'den fazla yorumu vardir. Rehber seviye gruplarinin puan ve
  yorum sayilari kendi esiklerini gercek yorum kayitlariyla saglar veya bilerek
  kacirir.

### Odeme, wallet ve finans katalogu

- Canonical tur, rezervasyon, wallet, earning ve refund tutarlari her zaman USD
  minor unit'tir. Hosted charge para birimi yalniz gercek quote/checkout akisi
  sirasinda `USD`, `TRY`, `EUR`, `GBP`, `NOK` veya `CHF` olabilir.
- Deterministik ana gezi gecmisi wallet ile basarili satin alma uzerinden
  kurulur. Her purchase debit'i ilgili SUCCEEDED payment ve reservation'a,
  her refund credit'i ilgili refund'a, her earning hareketi ilgili earning'e
  baglidir.
- Turist top-up gecmisi icin yalniz izole demo oldugu acik, secret icermeyen ve
  terminal durumda kalan tarihsel provider fixture kimlikleri kullanilabilir.
  Bunlar webhook/payment-event basarisi veya iyzico E2E kaniti sayilmaz ve
  reconciliation aday durumlarinda birakilmaz.
- Kalici seed `PENDING`, `REQUIRES_ACTION`, `VERIFYING` veya `TIMEOUT` hosted
  odeme birakmaz. Bu ara durumlar scheduler/provider tarafindan degisecegi icin
  gercek Sandbox akisi sirasinda test edilir.
- FX quote, provider callback/event, payment page URL, encrypted provider token,
  provider customer ve saved card satirlari sahte degerlerle doldurulmaz. Secili
  turistte gercek iyzico Sandbox odemesi bunlari olusturur.
- 300 ana kullanicinin wallet'i normal servis davranisiyla olusur. Bos, sifir,
  pozitif ve cok hareketli bakiyeler ledger kayitlarinin sonucu olur; bakiye
  kolonu veya seed sabiti yoktur.
- `TOP_UP`, `TOUR_PURCHASE`, `REFUND`, `GUIDE_EARNING`, `WITHDRAWAL` ve
  `EARNING_REVERSAL` hareketlerinin her biri, ilgili is kaydi ve idempotency
  anahtariyla en az bir gercek neden-sonuc zincirinde bulunur.
- Guide earning; basarili rezervasyonda `PENDING`, session tamamlaninca
  `AVAILABLE`, uygun iptal/iade zincirinde `REVERSED` olur. Brut, yuzde 10
  platform komisyonu ve net tutar servis tarafindan hesaplanir.
- Kazanclar son 18 aya dagitilir; secili rehberde bir yil icinde en az 6 farkli
  ay bulunur. Aylik toplam ve tur karti kazanci earning kayitlarindan hesaplanir.
- 45 rehberin en az bir banka hesabi vardir; 10 rehberde ikinci aktif veya
  disabled hesap bulunur. Bes NEW_PROFILE rehber banka bos ekranini korur.
- Kalici cekim gecmisi yalniz mevcut servisin gercekten uretebildigi
  `SIMULATED` + `COMPLETED` kayitlardan olusur. En az 30 tamamlanmis cekim,
  kendi debit ledger kaydiyla birlikte uretilir.

### Chat, bildirim ve dis servis siniri

- Toplam 180 benzersiz turist-rehber conversation ve yaklasik 2400 kalici mesaj
  uretilir. Satin alma chat icin on kosul degildir.
- Mesajlar iki yonlu, farkli uzunluk ve zaman araliklarindadir. Bos conversation,
  tek mesaj, tam okunmus, turistte okunmamis, rehberde okunmamis ve 50 kayitlik
  cursor sayfalamasini asan konusmalar bulunur.
- `clientMessageId` her gonderici icin benzersizdir; backend kalici teslim durumu
  SENT'tir. Android'in PENDING/FAILED yerel durumlari seed edilmez.
- Read state kayitlari mesaja gercekten ait son okunmus kimligi gosterir;
  okunmamis sayisi dogrudan yazilmaz.
- Mevcut servislerin uretebildigi tum semantic notification tipleri neden olan
  tur, rezervasyon, yorum, finans, chat veya security akisi ile olusur. Secili
  hesaplarda 20 kayitlik sayfalama ve okunmus/okunmamis karisimi bulunur.
- Bildirim tercihleri; tumu acik, chat kapali, hatirlatma kapali, finans kapali,
  yorum kapali ve tum kullanici tercihleri kapali senaryolarini kapsar.
  `SECURITY_ALERT` tercih ne olursa olsun engellenmez.
- Tarihsel seed bildirimleri `NOT_REQUESTED` kalabilir. `PENDING`, `SENT` ve
  `FAILED` push durumlari ancak gercek FID/FCM cihaz kaydi ve gercek teslim
  denemesiyle test edilir.
- `device_registrations`, saved cards, hosted callback/webhook ve gercek SMTP
  tokenlari seed edilmez. Bunlar cihaz/Sandbox/E2E adiminda normal endpoint ve
  dis servis akisiyla olusur.

### Backend'in hesaplayacagi deger matrisi

| Ekranda/API'de gorulen deger | Dogrudan yazilan yetkili temel veri | Hesaplayan kaynak |
| --- | --- | --- |
| Kullanici rolu ve erisim durumu | `users`, `roles`, account status ve role-selected | Auth ve security policy |
| Avatar URL/id | READY `media_assets` + `users.avatar_media_id` | Media reference mapper |
| Tur/rehber puani ve yorum sayisi | Completed reservation'a bagli `reviews` | Review aggregate sorgulari |
| Rehber seviyesi | Completed session, completed participant ve review dagilimi | `GuidePerformanceService` + `GuideLevelPolicy` |
| Populer tur/rehber sirasi | Approved tur, gorunur session, reservation ve review | Discovery/ranking sorgulari |
| Aktif/pending/gecmis tur kartlari | Tour approval, session ve change-request durumlari | Guide tour query ve mapper |
| Capacity, booked count ve availability | Session capacity + aktif reservation participantlari + gecerli hold | Reservation capacity sorgulari |
| Rezervasyon toplam tutari | Session unit price + participant count | Booking akisi ve DB constraint |
| Upcoming/past gezi listesi | Reservation ve session lifecycle + purchase snapshot | Reservation query/mapper |
| Wallet bakiye ve kullanilabilir bakiye | Credit/debit ledger + varsa aktif withdrawal rezervasyonu | Wallet balance sorgulari |
| Guide gross/fee/net kazanc | Basarili reservation ve komisyon ayari | `GuideEarningService` |
| Aylik ve session kazanci | PENDING/AVAILABLE earnings; REVERSED haric | Earning aggregate sorgulari |
| Transaction basligi | Ledger reference + reservation snapshot/tour | Wallet projection |
| Refund sonucu | Payment + cancellation policy + refund state | Refund servisleri |
| Chat preview/unread | Message sirasi + read state | Chat query/mapper |
| Notification unread | `notifications.read_at` | Notification repository |
| Reminder tekrar kontrolu | Reservation/session reminder zamani + dedup key | Reminder scheduler/service |

### Medya katalogu ve lisans manifesti

- Gercek kisi kimligi tasimayan, sac ve kiyafet ayrintilariyla kolayca ayirt
  edilen bir kadin ve bir erkek sentetik avatar sablonu kullanilir. Adlarla
  uyumlu sablon secilir; cinsiyetten rol veya uygulama is kurali cikarilmaz.
- Avatarlar PNG, kare kirpilmis, mobil icin uygun boyutta ve 5 MB
  sinirinin altindadir. Her biri kendi kullanicisina ait READY `USER_AVATAR`
  kaydiyla baglanir.
- 180 turun her biri icin tek gecerli `TOUR_COVER` vardir. Degisiklik talepleri
  mevcut kapagi referanslar; sahte, kullanilmayan medya kaydi uretilmez.
- 24 farkli Wikimedia Commons kaynak fotografi 24 Turkiye destinasyonuna
  dagitilir. Kaynaklar 180 tur arasinda deterministik olarak yeniden kullanilir.
- Dosyalar runtime'da internetten alinmaz. Uygulama adiminda bir kez indirilir,
  hash dogrulanir, demo medya kokune kopyalanir ve backend'in normal medya URL
  akisi uzerinden sunulur.
- Kaynak secim onceligi Public Domain/CC0, sonra atif bilgisi tam CC BY veya
  CC BY-SA'dir. Ticari olmayan, turev yasaklayan veya lisansi belirsiz dosya
  kullanilmaz.
- Medya manifesti en az su alanlari tasir:
  `assetKey`, `purpose`, `ownerSeedKey`, `tourSeedKey`, `relativePath`,
  `storageKey`, `sourceKind`, `sourcePageUrl`, `originalFileUrl`, `author`,
  `license`, `licenseUrl`, `attributionText`, `retrievedAt`, `sha256`,
  `contentType`, `sizeBytes`, `width`, `height`, `transformation`.
- Sentetik avatarlar icin `sourceKind=GENERATED`, uretim referansi/prompt surumu
  ve hash saklanir; Wikimedia alanlari null kalabilir. Commons fotograflarinda
  kaynak, eser sahibi ve lisans alanlari zorunludur.
- Manifest Git'e eklenebilir ancak indirilen medya dosyalari demo-ozel kokte
  kalir. Manifest secret, gercek kisi verisi veya provider tokeni icermez.

## Android Envanteri

### Genel yapi

- Android uygulamasi feature-first yapida 540 Kotlin/Java kaynak dosyasi,
  41 `*Screen.kt`, 37 ViewModel ve 14 Retrofit API tanimi icerir.
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
- 250 turist/50 rehber icin deterministik kohortlar, lifecycle kapsami,
  domainler arasi neden-sonuc matrisi ve medya manifest kurali kesinlestirilmistir.
  Tek tek 300 kullanici satiri onay icin sunulmayacak; seed katalogu bu kesin
  dagilimi tekrar edilebilir bicimde uygulayacaktir.

## Guvenli Demo Altyapisi Durumu

- Baslangic Git HEAD, calisma agaci farki, ana veritabani tablo envanteri,
  Flyway gecmisi ve normal medya dosya ozeti Git tarafindan izlenmeyen
  `.demo-safety` alanina kaydedilmistir.
- `guidemate_db`, PostgreSQL custom dump formatinda yedeklenmistir. Yedek
  `pg_restore --list` ve SHA-256 checksum ile dogrulanmistir.
- `application-demo.properties` yalniz `guidemate_demo` ve
  `${user.home}/.guidemate/guidemate-demo-media` hedeflerini kullanir. Ortam
  degiskeniyle ana veritabani veya baska medya yolu verilmeye calisilsa bile
  erken fail-closed guard uygulamayi Flyway/DataSource baslamadan durdurur.
- Demo secret dosyasi Git tarafindan izlenmez; yalniz secret icermeyen ornek
  dosya repoda bulunur.
- `scripts/demo/cleanup-demo.sh` varsayilan olarak dry-run calisir. Gercek
  temizleme yalniz `--execute` ve `DELETE_GUIDEMATE_DEMO_ONLY` onayi birlikte
  verildiginde, localhost `guidemate_demo` ve sabit demo medya kokune karsi
  calisabilir.
- Temizleme aracinin dry-run, yanlis onayi reddetme ve gercek yurutme dali
  gecici medya klasoru + sahte `dropdb` ile test edilmistir. Ana veritabaninda
  hicbir silme islemi denenmemistir.
- Kullanici onayiyla `guidemate_demo` olusturulmus, demo profili fail-closed
  guard altinda baslatilmis ve Flyway V1-V14 migration'larinin tamami bu bos
  veritabanina uygulanmistir. Demo semasi 32 tabloyla dogrulanmistir.
- `${user.home}/.guidemate/guidemate-demo-media` ayri demo medya koku olarak
  kullanilir. Normal medya kokune dokunulmamistir.
- Son izolasyon kontrolunde `guidemate_db` korunmus; kullanici, tur,
  rezervasyon, odeme ve medya sayilari `0` kalmistir. Aktif demo hedefinin
  yalniz `guidemate_demo` ve sabit demo medya koku oldugu dogrulanmistir.
- Baslangic yedeginin SHA-256 checksum'u ve 24 lisansli kaynak gorselin
  checksum manifesti yeniden dogrulanmistir.

## Demo Veri Seti Durumu

- 18-24 arasindaki dikey veri olusturma adimlari tamamlanmistir. Veri seti
  deterministik, tekrar calistirmaya karsi korumali ve `guidemate_demo`
  disinda calismayi reddeden guard altindadir.
- 306 demo-domain kullanicisi vardir: 250 aktif turist, 50 aktif rehber, bir
  admin ve auth lifecycle durumlarini gosteren bes teknik hesap.
- Ana 300 turist/rehber Turkce adlara ve birbirinden farkli soyadlara sahiptir.
  Kullaniciya gorunen seed metinleri Turkcedir.
- 180 tur, 560 oturum, 30 degisiklik istegi, 1300 rezervasyon ve 420 yorum;
  onay, ret, arsiv, acik, kapali, iptal, tamamlanmis, bekleyen odeme ve suresi
  dolmus durumlarini kapsar.
- 300 wallet, 1435 odeme, 65 iade, 2370 ledger hareketi, 1230 rehber kazanci,
  55 banka hesabi ve 30 tamamlanmis SIMULATED para cekme kaydi vardir.
- 180 sohbet, 2400 mesaj, 360 okunma durumu, 300 bildirim tercihi ve tum 23
  semantic bildirim tipini kapsayan 1200 bildirim vardir.
- Iki sentetik avatar sablonuna baglanan 300 ayri kullanici avatar kaydi ve 180
  tur kapagi olmak uzere 480 demo medya kaydinin tamaminda fiziksel dosya
  bulunur. Her tur 2-4 dil destekler. Tur kapaklari 24 lisansli Wikimedia
  Commons kaynagindan turetilmis ve `ATTRIBUTION.tsv` ile belgelenmistir.
- Puan, rehber seviyesi, bakiye, kazanc, doluluk ve sayaclar dogrudan sahte
  sonuc olarak yazilmamistir; bunlari doguran iliskili temel kayitlardan
  hesaplanir. Dogrulama sonucu rehber seviyeleri 35 APPROVED, 10 SILVER,
  4 SUPER ve 1 LEGENDARY olarak olusur.
- Gercek cihaz kaydi, provider musterisi, kayitli kart, provider event'i ve FX
  quote fixture'i uretilmemistir. Bunlar yalniz gercek Firebase/iyzico Sandbox
  akisiyla olusacaktir.
- Temiz PostgreSQL 18 Testcontainers veritabaninda V1-V14 migration, tam seed
  ve invariant dogrulamasi basarilidir. Mevcut `guidemate_demo` da ayrica
  salt okunur yeniden dogrulanmistir.
- Tek seferlik uretim tamamlandigi icin yerel secret dosyasinda
  `DEMO_DATASET_ENABLED=false` durumuna alinmistir. Veriler korunur; normal
  demo baslangicinda seed yeniden calismaz.

## Dogrulama Sonucu (25-29)

- `guidemate_demo` salt okunur sorgularla yeniden kontrol edilmistir: 32 tablo,
  306 demo-domain kullanicisi, 480 medya, 180 tur, 560 session, 1300
  rezervasyon, 420 yorum, 1435 odeme, 2370 ledger hareketi, 180 sohbet, 2400
  mesaj ve 1200 bildirim beklenen degerlerle birebir eslesir.
- Fiyat carpimi, tamamlanmamis rezervasyona yorum, sohbet disi gonderici,
  negatif ledger bakiyesi ve gercek provider fixture'i ihlallerinin tamami
  sifirdir. Rehber seviyeleri temel kayitlardan 35 `APPROVED`, 10 `SILVER`,
  4 `SUPER` ve 1 `LEGENDARY` olarak hesaplanir.
- PostgreSQL 18 Testcontainers uzerinde demo seed, endpoint, filtre, page,
  cursor pagination, sahiplik, rol, auth lifecycle ve OpenAPI kontrollerini
  kapsayan demo entegrasyon paketi 5/5 basarilidir. Tum backend paketi 203/203
  basarili, Flyway V1-V14 temiz PostgreSQL uzerinde gecerlidir.
- Gercek `guidemate_demo` sureci LAN uzerinden acilmistir. OpenAPI 72 path ile,
  filtreli tur aramasi, top guide listesi, JPEG medya erisimi, demo login,
  wallet ve bildirim endpoint'leri HTTP 200 vermistir. Provider callback ve
  webhook endpoint'lerinin `@Hidden` nedeniyle public OpenAPI'da yer almamasi
  bilincli sozlesmedir.
- Android Git tarafindan izlenmeyen `local.properties` icinde aktif LAN
  adresi `http://192.168.68.101:8080/` olarak ayarlanmistir. Android kaynak
  kodu degismeden `:app:assembleDebug` basarili olmustur. LAN adresi ileride
  degisirse yalniz bu yerel deger yeniden guncellenir.
- Son izolasyon kontrolunde `guidemate_db` halen 32 tablo ve sifir kullanici,
  tur, rezervasyon, odeme ve medya kaydiyla korunur. `guidemate_demo` ise 32
  tablo ve tam demo verisiyle ayridir. Baslangic dump SHA-256 degeri korunur;
  24 Wikimedia kaynak gorselinin checksum'lari kilitli manifestle dogrulanir.

## Temsili Test Hesaplari

- Tum demo hesaplarinin parolasi yalniz Git tarafindan izlenmeyen
  `config/application-demo-secrets.properties` icindeki
  `DEMO_DATASET_PASSWORD` degeridir. Parola veya token bu dosyaya yazilmaz.

| Hesap | Amac |
| --- | --- |
| `tourist001@demo.guidemate.test` | Avatarli, rezervasyon/chat/bildirim gecmisi olmayan bos turist durumu |
| `tourist028@demo.guidemate.test` | 60 mesajli sohbet ve cursor pagination |
| `tourist061@demo.guidemate.test` | Yaklasan ve bekleyen odeme dahil rezervasyon lifecycle'i |
| `tourist196@demo.guidemate.test` | Iptal ve suresi dolmus rezervasyon durumlari |
| `tourist233@demo.guidemate.test` | 21 gecmis tur, 12.500 minor unit wallet ve 19 bildirim |
| `guide001@demo.guidemate.test` | Tur, kazanc ve banka hesabi olmayan yeni rehber |
| `guide006@demo.guidemate.test` | Bekleyen tur/degisiklik, kazanc ve iki banka hesabi |
| `guide016@demo.guidemate.test` | `APPROVED` seviye siniri ve yorumlu tamamlanmis turlar |
| `guide039@demo.guidemate.test` | `SILVER` performans seviyesi |
| `guide046@demo.guidemate.test` | `SUPER` performans seviyesi |
| `guide050@demo.guidemate.test` | `LEGENDARY`, 100 tamamlanmis session, 50 yorum ve aylik kazanc |
| `admin@demo.guidemate.test` | Admin inceleme ve yetki akislari |
| `pending.valid@demo.guidemate.test` | Gecerli dogrulama tokenli `PENDING_VERIFICATION` hesap |
| `pending.expired@demo.guidemate.test` | Suresi dolmus dogrulama tokenli hesap |
| `role.selection@demo.guidemate.test` | Aktif fakat rol secimi tamamlanmamis hesap |
| `disabled.tourist@demo.guidemate.test` | Devre disi turist auth hatasi |
| `disabled.guide@demo.guidemate.test` | Devre disi rehber auth hatasi |

## Acik Kararlar

- Ilk yirmi dokuz madde tamamlanmistir. Siradaki calisma 30-33 arasindaki
  turist, rehber, admin, iki cihazli mesaj/bildirim, odeme ve sinir durumlarini
  kapsayan kullanici kabul testleridir.
- Demo calismasi bittiginde yalniz demo veritabani, demo medya koku ve demo icin
  eklenen kodlar ayri silme onayiyla kaldirilir. Ana veritabani, normal medya,
  mevcut kod ve uygulama davranisi korunur.
