# KiraSoftware Packet Sniffer v1.0

## Teknik Dokümantasyon ve Kullanım Kılavuzu

## GENEL BAKIŞ

Packet Sniffer, Knight Online oyununun ağ trafiğini analiz etmek için geliştirilmiş profesyonel bir paket izleme aracıdır. Windows kernel driver'ı kullanarak yüksek performanslı paket yakalama sağlar.

### Temel Özellikler

- Gerçek zamanlı paket yakalama (kernel-level)
- Otomatik şifreleme çözme (JvCryption, Rijndael)
- Otomatik sıkıştırma çözme (LZF)
- Çoklu dil desteği (TR, EN, ES, DE)
- Detaylı loglama sistemi
- Gelişmiş filtreleme seçenekleri
- SEND/RECV yön belirleme

---

## PORT YAPILANDIRMASI

Knight Online farklı portlar üzerinden iletişim kurar:

| SUNUCU TİPİ | PORT NUMARASI | AÇIKLAMA |
|-------------|---------------|----------|
| Login Server | 15100-15109 | Giriş işlemleri |
| Game Server | 15001 | Oyun içi hareketler |

### Filtreleme Örnekleri

- **Sadece Login paketleri:** `tcp.DstPort >= 15100 and tcp.DstPort <= 15109`
- **Sadece Game paketleri:** `tcp.DstPort == 15001 or tcp.SrcPort == 15001`
- **Tüm trafiği yakalamak:** `tcp`

---

## PAKET YÖNÜ (DIRECTION)

| YÖN | AÇIKLAMA | KULLANIM |
|-----|----------|----------|
| SEND | Client → Server | İstemci sunucuya paket gönderir |
| RECV | Server → Client | Sunucu istemciye paket gönderir |

**Not:** SEND = Gönderilen paket, RECV = Alınan paket

---

## LOGIN SERVER OPCODE LİSTESİ (Port 15100-15109)

Login Server, kullanıcı girişi ve sunucu seçimi işlemlerini yönetir.

### Standart Login Opcodes

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x01 | PKT_LOGIN_VERSION_REQ | Versiyon kontrol isteği |
| 0x02 | PKT_LOGIN_DOWNLOADINFO_REQ | Download bilgi isteği |
| 0x03 | PKT_LOGIN_LAUNCHER_NEWS | Launcher haberleri |
| 0xF2 | PKT_LOGIN_CRYPTION | JV şifreleme anahtarı |
| 0xF3 | PKT_LOGIN_LOGIN_REQ | Login isteği (Private) |
| 0xF4 | PKT_LOGIN_MGAME_LOGIN | MGame login |
| 0xF5 | PKT_LOGIN_SERVERLIST | Server listesi |
| 0xF6 | PKT_LOGIN_NEWS | Haber paketi |
| 0xF7 | PKT_LOGIN_UNKF7 | Bilinmeyen F7 |
| 0xFA | PKT_LOGIN_OTP | OTP doğrulama |
| 0xFD | PKT_LOGIN_OTP_SYNC | OTP senkronizasyon |
| 0xA1 | PKT_LOGIN_GUARD | Guard koruma paketi |

### USKO Özel Opcodes

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x09 | PKT_LOGIN_09 | Handshake ACK |
| 0x14 | PKT_LOGIN_14 | Login bilgileri (şifreli) |
| 0x18 | PKT_LOGIN_18 | Server listesi (şifreli) |
| 0x19 | PKT_LOGIN_UNKNOWN_19 | Pre-encryption handshake |
| 0x1D | PKT_LOGIN_UNKNOWN_1D | Auth devam |
| 0x26 | PKT_LOGIN_26 | Server cevabı |
| 0x2C | PKT_LOGIN_2C | Handshake ACK |
| 0x34 | PKT_LOGIN_UNKNOWN_34 | Handshake acknowledgment |
| 0x35 | PKT_LOGIN_UNKNOWN_35 | Server cevabı |
| 0x4A | PKT_LOGIN_4A | Handshake ACK |
| 0x4C | PKT_LOGIN_4C | Handshake ACK |
| 0x59 | PKT_LOGIN_UNKNOWN_59 | Login isteği |
| 0x63 | PKT_LOGIN_63 | Login (şifreli) |
| 0x66 | PKT_LOGIN_66 | Handshake ACK |
| 0x68 | PKT_LOGIN_68 | Authentication sonucu |
| 0x87 | PKT_LOGIN_UNKNOWN_87 | Login bilgileri |
| 0x8E | PKT_LOGIN_8E | Handshake ACK |
| 0x90 | PKT_LOGIN_UNKNOWN_90 | Client isteği |
| 0x96 | PKT_LOGIN_96 | Handshake cevabı |
| 0x98 | PKT_LOGIN_98 | Handshake ACK |
| 0x99 | PKT_LOGIN_99 | Login (şifreli) |
| 0xB1 | PKT_LOGIN_B1 | Server listesi (şifreli) |
| 0xB4 | PKT_LOGIN_B4 | Handshake ACK |
| 0xB6 | PKT_LOGIN_B6 | Server cevabı |
| 0xBE | PKT_LOGIN_BE | Authentication sonucu |
| 0xC0 | PKT_LOGIN_C0 | Handshake ACK |
| 0xC8 | PKT_LOGIN_UNKNOWN_C8 | Server/ülke kodu |
| 0xCC | PKT_LOGIN_CC | Authentication sonucu |
| 0xD8 | PKT_LOGIN_UNKNOWN_D8 | Server cevabı |
| 0xDB | PKT_LOGIN_UNKNOWN_DB | Authentication sonucu |
| 0xE2 | PKT_LOGIN_E2 | Handshake ACK |
| 0xEF | PKT_LOGIN_EF | Login (şifreli) |

### Login Paket Akışı

1. **Version Check (0x01)** → Server versiyon kontrolü
2. **Cryption (0xF2)** → Şifreleme anahtar değişimi
3. **Login Request (0xF3 veya USKO opcode)** → Giriş isteği
4. **Authentication Result** → Giriş sonucu
5. **Server List (0xF5 veya USKO opcode)** → Sunucu listesi
6. **Select Server** → Sunucu seçimi

---

## GAME SERVER OPCODE LİSTESİ (Port 15001)

Game Server, oyun içi tüm hareketleri ve etkileşimleri yönetir.

### Karakter ve Giriş İşlemleri

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x01 | PKT_GAME_LOGIN | Hesap girişi |
| 0x02 | PKT_GAME_NEW_CHAR | Karakter oluşturma |
| 0x03 | PKT_GAME_DEL_CHAR | Karakter silme |
| 0x04 | PKT_GAME_SEL_CHAR | Karakter seçimi |
| 0x05 | PKT_GAME_SEL_NATION | Millet seçimi |
| 0x0C | PKT_GAME_ALLCHAR_INFO_REQ | Tüm karakter bilgisi |
| 0x0D | PKT_GAME_GAMESTART | Oyun başlangıcı |
| 0x0E | PKT_GAME_MYINFO | Kullanıcı detayları |
| 0x0F | PKT_GAME_LOGOUT | Çıkış isteği |

### Hareket ve Konum

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x06 | PKT_GAME_MOVE | Hareket (1 saniye) |
| 0x09 | PKT_GAME_ROTATE | Dönüş |
| 0x15 | PKT_GAME_REGIONCHANGE | Bölge değişimi |
| 0x16 | PKT_GAME_REQ_USERIN | Kullanıcı listesi isteği |
| 0x1E | PKT_GAME_WARP | Işınlanma |
| 0x27 | PKT_GAME_ZONE_CHANGE | Bölge değişimi |
| 0x46 | PKT_GAME_SERVER_CHANGE | Sunucu değişimi |

### NPC ve Mob Etkileşimi

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x0A | PKT_GAME_NPC_INOUT | NPC bilgi ekleme/silme |
| 0x0B | PKT_GAME_NPC_MOVE | NPC hareketi |
| 0x1C | PKT_GAME_NPC_REGION | NPC bölge değişimi |
| 0x1D | PKT_GAME_REQ_NPCIN | NPC listesi isteği |
| 0x20 | PKT_GAME_NPC_EVENT | NPC tıklama olayı |
| 0x25 | PKT_GAME_TRADE_NPC | NPC ticareti |
| 0x3A | PKT_GAME_REPAIR_NPC | NPC tamir/ticaret |
| 0x56 | PKT_GAME_NPC_SAY | NPC konuşması |

### Savaş ve Skill

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x08 | PKT_GAME_ATTACK | Saldırı |
| 0x22 | PKT_GAME_TARGET_HP | Hedef HP sonucu |
| 0x31 | PKT_GAME_MAGIC_PROCESS | Skill/büyü paketi |
| 0x32 | PKT_GAME_SKILL_POINT_CHANGE | Skill puanı değişimi |
| 0x11 | PKT_GAME_DEAD | Ölüm |
| 0x12 | PKT_GAME_REGENE | Yeniden doğma |

### Envanter ve Eşya

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x1F | PKT_GAME_ITEM_MOVE | Eşya taşıma |
| 0x21 | PKT_GAME_ITEM_TRADE | Eşya takası |
| 0x23 | PKT_GAME_ITEM_DROP | Eşya atma |
| 0x24 | PKT_GAME_BUNDLE_OPEN_REQ | Eşya listesi isteği |
| 0x26 | PKT_GAME_ITEM_GET | Eşya alma |
| 0x2D | PKT_GAME_USERLOOK_CHANGE | Görünüm değişimi |
| 0x38 | PKT_GAME_DURATION | Eşya dayanıklılığı |
| 0x3B | PKT_GAME_ITEM_REPAIR | Eşya tamir |
| 0x3D | PKT_GAME_ITEM_COUNT_CHANGE | Eşya adedi değişimi |
| 0x3F | PKT_GAME_ITEM_REMOVE | Eşya silme |
| 0x45 | PKT_GAME_WAREHOUSE | Depolama |
| 0x5B | PKT_GAME_ITEM_UPGRADE | Eşya yükseltme |
| 0x73 | PKT_GAME_RENTAL | Kiralama |
| 0x74 | PKT_GAME_ITEM_EXPIRATION | Eşya son kullanma |
| 0xA4 | PKT_GAME_CLAN_WAREHOUSE | Klan deposu |
| 0xC7 | PKT_GAME_TEMPORARY_INVENTORY | Geçici envanter |

### Chat ve İletişim

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x10 | PKT_GAME_CHAT | Sohbet |
| 0x19 | PKT_GAME_NATION_CHAT | Millet sohbeti |
| 0x35 | PKT_GAME_CHAT_TARGET | Özel mesaj hedefi |
| 0x49 | PKT_GAME_FRIEND_PROCESS | Arkadaş işlemi |
| 0x55 | PKT_GAME_SELECT_MSG | Mesaj seçimi |
| 0xDB | PKT_GAME_NOTICE_MSG | Duyuru mesajı |

### Parti ve Takım

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x2F | PKT_GAME_PARTY | Parti işlemi |
| 0x4F | PKT_GAME_PARTY_BBS | Parti ilanı |
| 0xE8 | PKT_GAME_PARTY_HP | Parti HP bilgisi |

### Klan ve Lonca

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x3C | PKT_GAME_KNIGHTS_PROCESS | Lonca işlemi |
| 0x3E | PKT_GAME_KNIGHTS_LIST | Lonca listesi |
| 0x63 | PKT_GAME_CLAN_BATTLE | Lonca savaşı |
| 0x91 | PKT_GAME_CLANPOINTS_BATTLE | Lonca puan savaşı |

### Ticaret ve Pazar

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x50 | PKT_GAME_MARKET_BBS | Pazar ilanı |
| 0x68 | PKT_GAME_MERCHANT | Tüccar |
| 0x69 | PKT_GAME_MERCHANT_INOUT | Tüccar aç/kapa |
| 0x6A | PKT_GAME_SHOPPING_MALL | Alışveriş merkezi |

### Oyuncu Durumu

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x07 | PKT_GAME_USER_INOUT | Kullanıcı bilgi ekle/sil |
| 0x17 | PKT_GAME_HP_CHANGE | HP değişimi |
| 0x18 | PKT_GAME_MSP_CHANGE | MP değişimi |
| 0x1A | PKT_GAME_EXP_CHANGE | EXP değişimi |
| 0x1B | PKT_GAME_LEVEL_CHANGE | Seviye değişimi |
| 0x28 | PKT_GAME_STAT_POINT_CHANGE | Stat puanı değişimi |
| 0x29 | PKT_GAME_STATE_CHANGE | Otur/kalk |
| 0x2A | PKT_GAME_LOYALTY_CHANGE | Ulusal puan değişimi |
| 0x54 | PKT_GAME_WEIGHT_CHANGE | Ağırlık değişimi |
| 0x9B | PKT_GAME_SP_CHANGE | SP değişimi |

### Sistem ve Oyun

| HEX | OPCODE ADI | AÇIKLAMA |
|-----|------------|----------|
| 0x13 | PKT_GAME_TIME | Oyun zamanı |
| 0x14 | PKT_GAME_WEATHER | Hava durumu |
| 0x2B | PKT_GAME_VERSION_CHECK | Versiyon kontrolü |
| 0x2C | PKT_GAME_CRYPTION | Şifreleme |
| 0x2E | PKT_GAME_NOTICE | Duyuru |
| 0x36 | PKT_GAME_CONCURRENTUSER | Aktif kullanıcı sayısı |
| 0x37 | PKT_GAME_DATASAVE | Veri kaydetme |
| 0x39 | PKT_GAME_TIMENOTIFY | Zaman bildirimi |
| 0x41 | PKT_GAME_SPEEDHACK_CHECK | Hız kontrolü |
| 0x42 | PKT_GAME_COMPRESS_PACKET | Sıkıştırılmış paket |
| 0x43 | PKT_GAME_SERVER_CHECK | Sunucu kontrolü |
| 0x44 | PKT_GAME_CONTINOUS_PACKET | Bölge verisi |
| 0x47 | PKT_GAME_REPORT_BUG | Hata bildirimi |
| 0x48 | PKT_GAME_HOME | Eve dönüş |
| 0x4A | PKT_GAME_GOLD_CHANGE | Altın değişimi |
| 0x4B | PKT_GAME_WARP_LIST | Işınlanma listesi |
| 0x4C | PKT_GAME_VIRTUAL_SERVER | Sanal sunucu bilgisi |
| 0x4D | PKT_GAME_ZONE_CONCURRENT | Bölge kullanıcı sayısı |
| 0x4E | PKT_GAME_CORPSE | Ceset |
| 0x51 | PKT_GAME_KICKOUT | Atılma |
| 0x52 | PKT_GAME_CLIENT_EVENT | Client olayı |
| 0x53 | PKT_GAME_MAP_EVENT | Harita olayı |
| 0x57 | PKT_GAME_BATTLE_EVENT | Savaş olayı |
| 0x58 | PKT_GAME_AUTHORITY_CHANGE | Yetki değişimi |
| 0x59 | PKT_GAME_EDIT_BOX | Giriş kutusu |
| 0x5E | PKT_GAME_ZONEABILITY | Bölge yeteneği |
| 0x5F | PKT_GAME_EVENT | Oyun olayı |
| 0x60 | PKT_GAME_STEALTH | Gizlilik |
| 0x61 | PKT_GAME_ROOM_PACKETPROCESS | Oda paket işlemi |
| 0x62 | PKT_GAME_ROOM | Oda |
| 0x64 | PKT_GAME_QUEST | Görev |
| 0x66 | PKT_GAME_KISS | Öpme |
| 0x67 | PKT_GAME_RECOMMEND_USER | Kullanıcı önerisi |
| 0x6B | PKT_GAME_SERVER_INDEX | Sunucu indeksi |
| 0x6C | PKT_GAME_EFFECT | Efekt |
| 0x6D | PKT_GAME_SIEGE | Kuşatma |
| 0x6E | PKT_GAME_NAME_CHANGE | İsim değişimi |
| 0x6F | PKT_GAME_WEBPAGE | Web sayfası |
| 0x70 | PKT_GAME_CAPE | Pelerin |
| 0x71 | PKT_GAME_PREMIUM | Premium |
| 0x72 | PKT_GAME_HACKTOOL | Hile aracı tespiti |
| 0x75 | PKT_GAME_CHALLENGE | Meydan okuma |
| 0x76 | PKT_GAME_PET | Evcil hayvan |
| 0x77 | PKT_GAME_CHINA | Çin bölgesi |
| 0x78 | PKT_GAME_KING | Kral |
| 0x79 | PKT_GAME_SKILLDATA | Skill verisi |
| 0x7A | PKT_GAME_PROGRAMCHECK | Program kontrolü |
| 0x7B | PKT_GAME_BIFROST | Bifrost |
| 0x7C | PKT_GAME_REPORT | Rapor |
| 0x7D | PKT_GAME_LOGOSSHOUT | Logos bağırma |
| 0x80 | PKT_GAME_RANK | Sıralama |
| 0x81 | PKT_GAME_STORY | Hikaye |
| 0x82 | PKT_GAME_NATION_TRANSFER | Millet transferi |
| 0x83 | PKT_GAME_ZONE_TERRAIN | Bölge arazisi |
| 0x84 | PKT_GAME_MOVING_TOWER | Hareket eden kule |
| 0x85 | PKT_GAME_BDWINFO | BDW bilgisi |
| 0x86 | PKT_GAME_MINING | Madencilik |
| 0x87 | PKT_GAME_HELMET | Miğfer |
| 0x88 | PKT_GAME_PVP | PVP |
| 0x89 | PKT_GAME_CHANGE_HAIR | Saç değişimi |
| 0x8A | PKT_GAME_KAUL_A | Kaul A |
| 0x8B | PKT_GAME_VIP_STORAGE | VIP depo |
| 0x8C | PKT_GAME_KAUL_C | Kaul C |
| 0x8D | PKT_GAME_GENDER_CHANGE | Cinsiyet değişimi |
| 0x8E | PKT_GAME_PACKET16 | Paket 16 |
| 0x8F | PKT_GAME_PACKET17 | Paket 17 |
| 0x90 | PKT_GAME_DEATH_LIST | Ölüm listesi |
| 0x92 | PKT_GAME_UTC_MOVIE | UTC filmi |
| 0x97 | PKT_GAME_GENIE | Cin |
| 0x98 | PKT_GAME_SURROUNDING_USER | Çevredeki kullanıcı |
| 0x99 | PKT_GAME_ACHIEVE | Başarı |
| 0x9A | PKT_GAME_SEALEXP | Mühürlü EXP |
| 0x9C | PKT_GAME_WHEEL | Çark |
| 0x9F | PKT_GAME_LOADING_LOGIN | Yükleme girişi |
| 0xA0 | PKT_GAME_XIGNCODE3 | XignCode3 |
| 0xA1 | PKT_GAME_GUARD | Guard |
| 0xA2 | PKT_GAME_KSW_GUARD_HOOK | KSW Guard |
| 0xB3 | PKT_GAME_TOWN | Şehir |
| 0xB6 | PKT_GAME_VANGUARD | Vanguard |
| 0xB9 | PKT_GAME_RESKILL | Tekrar öldürme |
| 0xC0 | PKT_GAME_CAPTCHA | Captcha |
| 0xC2 | PKT_GAME_DAILY_RANK | Günlük sıralama |
| 0xC8 | PKT_GAME_KILL_ASSIST | Öldürme yardımı |
| 0xD0 | PKT_GAME_DB_DAILY_OP | DB günlük işlem |
| 0xD1 | PKT_GAME_DB_UPDATE_RANKING | DB sıralama güncelleme |
| 0xD2 | PKT_GAME_DB_LOAD_RANKING | DB sıralama yükleme |
| 0xD3 | PKT_GAME_DB_DONATE_NP | DB NP bağışı |
| 0xD4 | PKT_GAME_RESET_LOYALTY | NP sıfırlama |
| 0xD5 | PKT_GAME_DB_NPOINTS | DB NP puanları |
| 0xE9 | PKT_GAME_F10_SETTINGS | F10 ayarları |
| 0xFA | PKT_GAME_DB_SAVE_USER | DB kullanıcı kaydetme |
| 0xFF | PKT_GAME_TEST_PACKET | Test paketi |

---

## ŞİFRELEME SİSTEMİ

Knight Online birden fazla şifreleme yöntemi kullanır:

### JvCryption
- Knight Online'nin orijinal şifreleme algoritması
- Login Server'da anahtar değişimi için kullanılır
- Dinamik anahtar üretimi

### Rijndael (AES)
- USKO Login Server'da kullanılır
- 256-bit anahtar uzunluğu
- CBC modu

### Sıkıştırma
- LZF algoritması kullanılır
- Opcode 0x42 ile sıkıştırılmış paketler
- Otomatik decompression desteği

---

## LOG DOSYASI SİSTEMİ

Log dosyaları otomatik olarak şu formatta oluşturulur:

```
LoginLog/
├── LoginPacket_2026-04-18-12-30-00.log
├── LoginPacket_2026-04-18-12-35-00.log
└── LoginPacket_2026-04-18-12-40-00.log
```

### Log Dosyası Formatı

```
[2026-04-18 12:30:15.123] ========================================
[2026-04-18 12:30:15.124] [SEND] 192.168.1.100:54321 -> 212.175.66.1:15100
[2026-04-18 12:30:15.125] Size: 256 bytes | Opcode: 0x01 (PKT_LOGIN_VERSION_REQ)
[2026-04-18 12:30:15.126] Encrypted: No | Compressed: No
[2026-04-18 12:30:15.127] ========================================
```

---

## AYAR DOSYASI (PacketSettings.ini)

```ini
[General]
Language=tr              ; Dil: tr, en, es, de
LogEnabled=1             ; 0=kapalı, 1=açık
LogPath=LoginLog/        ; Log dosya yolu
AutoScroll=1             ; 0=kapalı, 1=açık
MaxLogSize=100           ; MB cinsinden max boyut

[Filter]
SourceIP=                ; Kaynak IP (boş=tümü)
DestPort=15100           ; Hedef port
Protocol=tcp             ; tcp veya udp
FilterString=            ; Özel filtre

[Encryption]
AutoDecrypt=1            ; 0=kapalı, 1=açık
ShowRawData=1            ; 0=kapalı, 1=açık
ShowDecrypted=1          ; 0=kapalı, 1=açık

[Compression]
AutoDecompress=1         ; 0=kapalı, 1=açık
ShowCompressed=1         ; 0=kapalı, 1=açık

[Display]
ColorOutput=1            ; 0=kapalı, 1=açık
ShowTimestamp=1          ; 0=kapalı, 1=açık
ShowOpcode=1             ; 0=kapalı, 1=açık

[LoginOpcodes]
Enabled=*                ; Tüm login opcodeleri

[GameOpcodes]
Enabled=*                ; Tüm game opcodeleri
```

---

## KONSOL KOMUTLARI

| KOMUT | AÇIKLAMA | İŞLEV |
|-------|----------|-------|
| Ctrl+C | Programı kapat | Güvenli kapanma |
| F1 | Ayarlar menüsü | Tüm ayarlar |
| F2 | Filtre ayarları | IP/Port filtreleri |
| F5 | Ekranı temizle | Konsolu temizle |
| R | Ayarları yenile | INI dosyasını yeniden yükle |
| S | İstatistik göster | Paket istatistikleri |
| L | Loglamayı aç/kapa | Kayıt sistemi |
| H/? | Yardım | Komut listesi |

---

## SİSTEM GEREKSİNİMLERİ

| BİLEŞEN | MINİMUM | ÖNERİLEN |
|----------|---------|----------|
| İşlemci | Intel Core i3 2.4GHz | Intel Core i5 3.0GHz |
| RAM | 4 GB | 8 GB |
| Disk | 100 MB | 500 MB SSD |
| Ağ | 100 Mbps | 1 Gbps |
| İşletim Sist. | Windows 7/8/10/11 (x64) | Windows 10/11 (x64) |

### Performans

- Capture Rate: 10,000+ paket/saniye
- Processing: <1ms gecikme
- CPU Usage: %5-10 (normal)
- Memory: ~50-100 MB
- Disk I/O: 1-5 MB/s (loglama açıkken)

---

## SIK KARŞILANAN SORUNLAR

### Sorun: "Driver yüklenemedi" hatası

- Yönetici olarak çalıştırdığınızdan emin olun
- Antivirüs programını geçici olarak devre dışı bırakın
- WinDivert64.sys dosyasının varlığını kontrol edin
- Windows Defender'den istisna ekleyin

### Sorun: Paketler görünmüyor

- Knight Online'ın çalıştığından emin olun
- Doğru port numarasını kullandığınızı kontrol edin
- Firewall ayarlarını kontrol edin
- Filtre kurallarını sıfırlayın

### Sorun: Oyun laglanıyor

- Loglamayı kapatın veya azaltın
- Filtreleme kullanın
- Auto-decompression'ı kapatın
---

**KiraSoftWare © 2026** - Tüm Hakları Saklıdır
