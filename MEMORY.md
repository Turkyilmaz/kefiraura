# MEMORY.md — Long-Term Memory

---

## Murat Hakkında

- **Ad:** Murat Türkyılmaz
- **Firma:** Pure7 (Siber Güvenlik Partner) — www.pure7.com.tr
- **Rol:** InfoSec Takım Lideri
- **Timezone:** Istanbul (UTC+3)
- **İletişim:** Telegram

---

## Pure7 Ürünleri

1. **CrowdStrike Falcon** (EDR/XDR + Identity Protection)
2. **Netskope** (SASE/Cloud Security)

---

## Müşteriler

Detaylar: `customers/customers.md`

| Müşteri | Ürün | Notlar |
|---------|------|--------|
| **TeknoSA** | Endpoint Protection | 2.207 host, Discover aktif |
| **Pizza Lazza** | Endpoint Protection | 1.541 host, Discover lisansı yok |
| **Yurtiçi Kargo** | Endpoint + Identity Protection | 8.407 host, 4.087 kullanıcı |

---

## Script Altyapısı

- Tüm raporlar FalconPy SDK ile çalışıyor
- Rapor formatı: Excel (.xlsx) — Pure7 brand renkleri (Orange + Navy)
- Gönderen mail: `Reports_InfoSec@pure7.com.tr`
- Script'ler: `scripts/<müşteri>/generate_report.py`
- Raporlar: `customers/reports/<müşteri>/`

---

## Önemli Notlar

- Pizza Lazza'da Discover API 403 veriyor (lisans yok) — normal
- Yurtiçi Identity API'de Stealthy/Duplicate/Honeytoken flag'ları risk factor üzerinden tespit ediliyor, tam doğrulama yapılmadı
- Pagination düzeltmesi yapıldı (body= yerine kwargs kullanılıyor)

---

## Bekleyen İşler

- Pizza Lazza: Quarantine on Write, Volume Shadow Copy, Credential Dumping → ON yapılacak
- TeknoSA: Phase 1 policy'lerinde ML Prevention DISABLED → düzeltilecek
- Yurtiçi: Stealthy/Duplicate/Honeytoken flag doğrulaması yapılacak
- Netskope raporları henüz başlanmadı

---

## Müşteri Durumu (Son: 2026-03-23)

| Müşteri | Endpoint | Identity | Kritik Sorun |
|---------|----------|----------|--------------|
| TeknoSA | ✅ | ❌ | ML Prevention DISABLED |
| Pizza Lazza | ✅ | ❌ | Quarantine/Cred Dumping kapalı |
| Yurtiçi Kargo | ✅ | ✅ | 2.694 pwd never expires |
| CarrefourSA | ✅ | ❌ | — |

---

## Kefir Aura Projesi

- **Site:** https://kefiraura.pages.dev
- **Platform:** Cloudflare Pages (ücretsiz)
- **GitHub:** https://github.com/Turkyilmaz/kefiraura
- **Klasör:** `kefiraura/`

### Yapılanlar
- Hugo static site — tüm sayfalar hazır
- Formspree iletişim formu (mjgpbbyo)
- Blog: 4 yazı (kefir, sağlık, 21 gün, ikinci beyin)
- Satış Noktaları: Köylü Peynircilik (10 şube), Emek Yufka & Mantı
- Sertifikalar: 3 PDF belge
- Sosyal medya takvimi + içerik şablonları

### Bekleyenler
- kefiraura.com domain bağlantısı
- Yeni logo (Boyacıyan — #05 önerisi)
- Ürün ve Meltem Hanım fotoğrafları
