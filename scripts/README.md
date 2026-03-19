# CrowdStrike Report Template

## Dosyalar

| Dosya | Açıklama |
|---|---|
| `crowdstrike_report_template.py` | Ana şablon — yeni müşteri için bu kullanılır |
| `teknosa/generate_report.py` | TeknoSA'ya özel, production script |

---

## Yeni Müşteri Eklemek

Şunu söylemen yeterli:

> "[Müşteri Adı] için CrowdStrike raporu kur"
> - Client ID: xxx
> - Secret: xxx
> - Base URL: https://api.eu-1.crowdstrike.com (veya us-1, us-2)
> - Haftalık gönderim: Cuma 15:00 (veya istediğin gün/saat)

Ben de:
1. Template'den `scripts/[musteri_adi]/generate_report.py` oluştururum
2. Credentials ve müşteri adını doldururum
3. Output dizinini ayarlarım (`customers/reports/[musteri_adi]/`)
4. Cron'a eklerim
5. Test raporu çalıştırırım

**5 dakika içinde hazır.**

---

## Template Placeholder'ları

| Placeholder | Açıklama |
|---|---|
| `{{CLIENT_ID}}` | CrowdStrike API Client ID |
| `{{CLIENT_SECRET}}` | CrowdStrike API Secret |
| `{{BASE_URL}}` | API Base URL (eu-1, us-1, us-2) |
| `{{OUTPUT_DIR}}` | Rapor çıktı klasörü |
| `{{CUSTOMER_NAME}}` | Müşteri adı (Cover + başlıklarda görünür) |

---

## Rapor İçeriği (8 Sheet)

1. **Cover** 🟦 — Kapak sayfası (müşteri adı, tarih, Pure7)
2. **Summary** 🟠 — Dashboard (host sayısı, policy durumu, exclusions)
3. **Risk & Actions** 🔴 — Otomatik risk tespiti
4. **All Hosts** 🟦 — Tüm hostlar (2200+ satır)
5. **Host Grupları** 🟠 — Static/Dynamic gruplar
6. **Policy Atamaları** 🟠 — Her gruba atanan policiler
7. **Policy Detayları** 🟠 — Prevention + Sensor Update detayları
8. **Exclusions** ⚫ — ML, IOA, SV exclusionları

---

## Cron Zamanlaması

Her Cuma 15:00 Istanbul (12:00 UTC):
```
0 12 * * 5
```

---

## Rapor Adı Formatı

```
[MusteriAdi]_CrowdStrike_HealthCheck_YYYY-MM-DD.xlsx
```

Örnek: `TeknoSA_CrowdStrike_HealthCheck_2026-03-19.xlsx`
