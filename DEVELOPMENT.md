# TransferChain AES — geliştirici kılavuzu

**Sürüm:** 1.0.0. Aynı interface üzerinden GCM, CTR veya `ctr-with-hmac`
çalıştırır. Key çağıran tarafından sağlanır; plugin anahtarı Keystore/Keychain'e
kaydetmez. [Kurulum ve kullanım](README.md).

## Kaynak haritası

| Dosya                           | Değiştirme nedeni                                  |
| ------------------------------- | -------------------------------------------------- |
| [www/AES.js](www/AES.js)        | Argüman sırası, binary view, multipart sonuç       |
| [Android](src/android/AES.java) | javax.crypto, native doğrulama, CTR sayaç kontrolü |
| [iOS](src/ios/AES.swift)        | CryptoKit GCM / CommonCrypto CTR                   |
| [plugin.xml](plugin.xml)        | Native feature, sınıf ve JS global kaydı           |

## Kullanım

```js
const encrypted = await CryptoKit.AES.encrypt({ mode: 'GCM', key, data })
let plain
try {
  plain = await CryptoKit.AES.decrypt({
    mode: 'GCM', key, iv: encrypted.iv, data: encrypted.data,
    tag: encrypted.tag
  })
  await consumePlaintext(plain)
} finally {
  plain?.fill(0)
}
```

Örnek deviceready sonrasında çalışır. Girdi ve consumer fonksiyonları çağıran
tarafından sağlanır; sahip olunan secret bufferlar işlem bitince temizlenir.
Ayrıntılar: [API](docs/API.md).

deviceready gerekir. AAD, şifrelenmeyen fakat tag ile doğrulanan ek veridir;
örneğin kayıt kimliği/sürümü bağlanabilir. Decrypt aynı AAD'yi almalıdır. Sonuç
AAD'yi içermez; saklama formatının bunu ayrıca tanımlaması gerekir.

## Parametre ve sonuç sözleşmesi

| Alan           | GCM                                        | CTR                  |
| -------------- | ------------------------------------------ | -------------------- |
| mode           | 'GCM'                                      | 'CTR'                |
| key            | 16, 24 veya 32 byte                        | 16, 24 veya 32 byte  |
| data           | 0–1.048.576 byte                           | 0–1.048.576 byte     |
| iv             | 12 byte                                    | 16 byte              |
| aad            | Opsiyonel; 0–1.048.576 byte                | Kabul edilmez        |
| tag            | Decrypt'te 16 byte; encrypt girdisi olamaz | Kabul edilmez        |
| encrypt sonucu | { mode, iv, data, tag }                    | { mode, iv, data }   |
| decrypt sonucu | Uint8Array plaintext                       | Uint8Array plaintext |

Binary alanlar Uint8Array/ArrayBuffer kabul eder. Encrypt'te IV verilmezse
native taraf yeni rastgele IV üretir. Decrypt'te IV zorunludur. data ciphertext
uzunluğu plaintext ile aynıdır; GCM tag ayrı taşınır. Boş plaintext geçerlidir.

GCM bütünlüğü doğrular; değiştirilmiş data, AAD veya tag plaintext döndürmeden
AUTHENTICATION_FAILED ile reddedilir. CTR bütünlük sağlamaz: değiştirilen
ciphertext'in başarıyla çözülmesi doğrulanmış plaintext anlamına gelmez.

## Bridge ve native işleyişi

### Streaming mod: ctr-with-hmac

GCM/CTR encrypt/decrypt metotları değişmedi. Streaming API doğrudan
CryptoKit.AES.open üzerinden kullanılır:

```js
const file = await CryptoKit.AES.open(async (transaction) => {
  const id = await transaction.create({ operation: 'encrypt', key, keyHmac })

  await transaction.update(id, chunk1)
  await transaction.update(id, chunk2)
  return transaction.finalize(id)
})
```

Aynı arayüz 'decrypt' kabul eder. finalize bir Cordova File nesnesi döndürür; bu
bir FileEntry veya bütün dosyayı RAM'e alan Blob değildir. transaction.abort(id)
oturumu kapatır. Her create oturumu blok bitmeden finalize/abort edilmelidir.
Callback/native hata veya commit hatasında transaction çıktıları geri alınır.
Finalized dosya yalnızca open başarıyla döndükten sonra çağıranın
sorumluluğudur; işi bitince cordova-plugin-file ile silinmelidir. Başarılı
transaction içindeki finalized dosyalar otomatik silinmez; geçici kullanımda
bloktan çıkmadan abort finalized bir oturuma uygulanmaz, transaction rollback
gerekir.

key: 16/24/32 byte. keyHmac: 1–1.048.576 byte, yeni anahtar için 64 rastgele
byte önerilir. Bağımsız anahtar kullanın. Bir update en fazla 1 MiB; bir stream
plaintext toplamı en fazla 1 GiB. En fazla 16 açık transaction/session vardır.
create rastgele IV üretir; dışarıdan IV alınmaz. Wire format Go uyumludur: 0x01
| IV(16) | ciphertext | HMAC-SHA512(IV + ciphertext)(64). Version MAC'e dahil
değildir; yalnızca 0x01 kabul edilir. Boş plaintext geçerlidir.

Encrypt parçaları native cipher/MAC state ile dosyaya yazar. Decrypt 17-byte
başlığı ve son 64-byte tag'i ayırır; ciphertext özel cache dosyasına yazılır.
finalize MAC'i doğrulamadan plaintext üretmez. Doğrulama sonrası ikinci geçiş 16
KiB buffer kullanır. Java Mac/MessageDigest.isEqual; Swift CryptoKit incremental
HMAC ve MessageAuthenticationCode eşitliği (safeCompare), CommonCrypto CTR
kullanır. Swift'te tag'i Data'ya çevirip normal Data == karşılaştırması
eklemeyin.

Native stream action'ları:

| Action            | Argümanlar                                                         | Sonuç                                  |
| ----------------- | ------------------------------------------------------------------ | -------------------------------------- |
| open              | []                                                                 | transactionID                          |
| create            | [{transactionID, operation}, key ArrayBuffer, keyHmac ArrayBuffer] | sessionID                              |
| update            | [sessionID, data ArrayBuffer]                                      | acknowledgement                        |
| finalize          | [sessionID]                                                        | File URL; JS bunu Cordova File'a çözer |
| abort             | [sessionID]                                                        | acknowledgement                        |
| commit / rollback | [transactionID]                                                    | acknowledgement                        |

JS open callback'i commit/rollback'i yönetir. Native sıralı kuyruk stream
state'ini korur; Android Cordova thread pool, iOS private serial queue kullanır.
Anahtar/ara byte buffer'ları temizlenir ve CommonCrypto context release edilir.
Bu testler sağlayıcı veya GC'nin erişilemeyen bütün iç kopyalarının
sıfırlandığını kanıtlamaz; yalnızca referans bırakmak için sıfırlama iddiasında
bulunulmaz.

### Konumsal Cordova argümanları

Cordova service: AES; action: encrypt/decrypt. Argümanlar konumsaldır:

| İndeks | İçerik                                |
| ------ | ------------------------------------- |
| 0      | { mode } metadata                     |
| 1      | key ArrayBuffer                       |
| 2      | data ArrayBuffer                      |
| 3      | iv ArrayBuffer veya encrypt için null |
| 4      | aad ArrayBuffer veya null             |
| 5      | tag ArrayBuffer veya null             |

Bu altı argüman yalnızca mevcut GCM/CTR encrypt/decrypt action'ları içindir.
Binary taşımayı Cordova yönetir.

Encrypt native callback'i mode, iv, data, tag sırasıyla multipart döndürür.
CTR'de son parça null'dır; JS sonuç nesnesine tag alanı eklenmez. Bu sırayı
değiştirmek iki platform ve www köprüsünü birlikte değiştirmeyi gerektirir.

Android AES/GCM/NoPadding ve AES/CTR/NoPadding kullanır. GCM provider'ının
birleşik ciphertext+tag çıktısı bridge için ayrılır; decrypt öncesi
birleştirilir. iOS GCM CryptoKit, CTR CommonCrypto'dur. CTR 128-bit big-endian
sayaç kullanır; işlem içindeki sayaç taşması reddedilir. İşler native background
katmanındadır.

## Güvenlik ve hata yönetimi

- Aynı key ile GCM IV veya CTR sayaç aralığını tekrar kullanmayın. Dışarıdan IV
  sağlandığında çağrılar arası benzersizlik sorumluluğu çağırandadır.
- Sabit IV yalnızca bilinen test vektörleri içindir. Varsayılan otomatik IV'yi
  uygulama kolaylığı için sabit bir değerle değiştirmeyin.
- Native tarafta key boyutu tekrar kontrol edilir; JS'in 16–32 aralık kontrolü
  tek başına 17-byte anahtarı geçerli yapmaz.
- Geçici buffer'lar mümkün olduğunda temizlenir. Çağıranın key/sonuç dizisinin
  ömrünü çağıran yönetir; native provider kopyaları için tam silme garantisi
  yoktur.
- INVALID_ARGUMENT, AUTHENTICATION_FAILED, RESOURCE_LIMIT ve OPERATION_FAILED
  native hata kodlarıdır. Hata payload'ına key eklemeyin.

## Değişiklik ve test akışı

Örneğin tag formatını değiştirirken sadece JSON alanına bakmayın: Android
doFinal biçimi, iOS sealed box, multipart sırası, JS sonuç dönüşümü ve saklanan
veri sürümü birlikte etkilenir. Mevcut 16-byte sözleşmesi korunmalıdır.

[Bridge testleri](tests/js/bridge.test.js),
[Java vektörleri](tests/native/AESTests.java),
[Go referansı](tests/reference/main.go) ve
[fixture](tests/fixtures/aes-ctr-hmac-vectors.json) plugin içinde bulunur. Test
kurulumu: [TESTING](docs/TESTING.md).

NIST GCM/CTR, tamper, counter wrap, üç key boyutu, boş veri, streaming rollback
ve multipart sırası korunmalıdır. Fixture değişikliklerini protokol incelemesi
olmadan kabul etmeyin. Host sonucu cihaz doğrulaması değildir.
