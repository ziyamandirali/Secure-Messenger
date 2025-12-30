# Secure Messenger - Çalıştırma Talimatları

Bu proje, Python ve Tkinter kullanılarak geliştirilmiş, steganografi ve DES şifreleme tabanlı güvenli bir mesajlaşma uygulamasıdır.

## Gereksinimler

- Python 3.x
- `Pillow` (Görsel işleme için)
- `pycryptodome` (Şifreleme için)
- `tk` (Arayüz için - genellikle Python ile gelir)

### Kurulum

Gerekli kütüphaneleri yüklemek için terminalde şu komutu çalıştırın:

```bash
pip install Pillow pycryptodome
```

Veya sanal ortam (venv) kullanıyorsanız:

```bash
# Sanal ortamı aktif et (Linux/Mac)
source venv/bin/activate
# Yükle
pip install Pillow pycryptodome
```

---

## 1. Sunucuyu (Server) Başlatmak

Mesajlaşmanın çalışması için önce sunucunun açık olması gerekir.

1.  Proje klasöründe terminal açın.
2.  Aşağıdaki komutu yazın:

```bash
python3 server.py
```

*Sunucu `0.0.0.0:9999` adresinde dinlemeye başlayacaktır. Terminali kapatmayın.*
*(Arka planda çalıştırmak isterseniz: `nohup python3 server.py &`)*

---

## 2. İstemciyi (Client) Başlatmak

Kullanıcı arayüzünü açmak için yeni bir terminal penceresinde:

```bash
python3 gui_client.py
```

Birden fazla kullanıcı ile test etmek için bu komutu farklı terminallerde tekrar çalıştırarak 2. veya 3. istemciyi açabilirsiniz.

---

## Kullanım Adımları

1.  **Kayıt Ol (Register):**
    *   İlk açılışta bir **Kullanıcı Adı** ve **Parola** belirleyin.
    *   bilgisayarınızdan bir **Resim** seçin.
    *   **Register** butonuna basın.
    *   *Sistem, parolanızı bu resmin içine gizleyip sunucuya yükleyecektir.*

2.  **Giriş Yap (Login):**
    *   Kayıt olduktan sonra **Login** butonuna basarak giriş yapın.
    *   *Not: Girdiğiniz parola, mesajların şifresini çözmek için anahtar olarak kullanılır.*

3.  **Mesajlaşma:**
    *   Sol taraftaki listeden çevrimiçi (Yeşil ●) veya çevrimdışı (Kırmızı ●) bir kullanıcı seçin.
    *   Mesajınızı yazıp **Send** butonuna basın.

4.  **Çıkış (Log Out):**
    *   Sağ üstteki **Log Out** butonu ile oturumu kapatabilirsiniz.

## Sorun Giderme

- **"ModuleNotFoundError"**: Kütüphanelerin yüklü olduğundan emin olun (`pip install ...`).
- **"Connection Refused"**: Sunucunun (`server.py`) çalıştığından emin olun.
- **Gri ikon sorunu**: Bu sorun çözülmüştür, artık renkli noktalar kullanılıyor.
