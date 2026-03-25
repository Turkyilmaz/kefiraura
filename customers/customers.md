# Müşteri Konfigürasyonları

> Pure7 InfoSec — CrowdStrike Müşteri Listesi
> Son güncelleme: 2026-03-23

---

## 1. TeknoSA

**Ürün:** CrowdStrike Falcon Endpoint Protection
**API Region:** EU-1 (`https://api.eu-1.crowdstrike.com`)
**Script:** `scripts/teknosa/generate_report.py`
**Rapor Klasörü:** `customers/reports/teknosa/`

| | |
|---|---|
| Client ID | `c18f8fd7b9ce49d0bf68c5336cd5e7c0` |
| Secret | `JD6dZpQ13rIA5KnU0ukw2q8F9O7BMYvS4sXajbhN` |

**Notlar:**
- 2.207 endpoint
- Falcon Discover aktif (63 unmanaged, 842 high memory)
- Identity Protection: ❌ Yok

---

## 2. Pizza Lazza

**Ürün:** CrowdStrike Falcon Endpoint Protection
**API Region:** EU-1 (`https://api.eu-1.crowdstrike.com`)
**Script:** `scripts/pizzalazza/generate_report.py`
**Rapor Klasörü:** `customers/reports/pizzalazza/`

| | |
|---|---|
| Client ID | `dbec0850f9144386bfb5bdad5861e71f` |
| Secret | `tKz4YPfmQB3r08FRAaS6CvT5ldw9e2GIEgH1Ls7y` |

**Notlar:**
- 1.541 endpoint
- Falcon Discover: ❌ (403 - lisans yok)
- Identity Protection: ❌ Yok

---

## 3. Yurtiçi Kargo

**Ürün 1:** CrowdStrike Falcon Endpoint Protection
**Ürün 2:** CrowdStrike Falcon Identity Protection
**API Region:** EU-1 (`https://api.eu-1.crowdstrike.com`)
**Script (Endpoint):** `scripts/yurtici/generate_report.py`
**Script (Identity):** `scripts/yurtici/generate_identity_report.py`
**Rapor Klasörü:** `customers/reports/yurtici/`

### Endpoint Protection API

| | |
|---|---|
| Client ID | `a6df49f452c144ecaf630aae61b1d571` |
| Secret | `1JWgqADk6idMC4hpctzK7sxfXlTo3S02rE8OQb59` |

**Notlar:**
- 8.407 endpoint (en büyük müşteri)
- Falcon Discover aktif (146 unmanaged, 336 high memory)

### Identity Protection API

| | |
|---|---|
| Client ID | `a6df49f452c144ecaf630aae61b1d571` |
| Secret | `1JWgqADk6idMC4hpctzK7sxfXlTo3S02rE8OQb59` |

**Notlar:**
- 4.087 kullanıcı
- 214 stale, 2.114 inactive
- 2.694 pwd never expires, 465 compromised
- 68 privileged hesap

---

## 4. CarrefourSA

**Ürün:** CrowdStrike Falcon Endpoint Protection
**API Region:** EU-1 (`https://api.eu-1.crowdstrike.com`)
**Script:** `scripts/carrefoursa/generate_report.py`
**Rapor Klasörü:** `customers/reports/carrefoursa/`

| | |
|---|---|
| Client ID | `4c6024b3d8524613b5c37abe055140e5` |
| Secret | `O4E7rwYKC2cBsPletv0X5pU9kfbao6FI31uzNx8H` |

**Notlar:**
- 596 endpoint
- Falcon Discover: ❌ (403 - lisans yok)
- Identity Protection: ❌ Yok

---

## Rapor Takvimi

| Müşteri | Endpoint Raporu | Identity Raporu |
|---------|----------------|-----------------|
| TeknoSA | Her Cuma 15:00 (Istanbul) | — |
| Pizza Lazza | Her Cuma 15:00 (Istanbul) | — |
| Yurtiçi Kargo | Her Cuma 15:00 (Istanbul) | Her Cuma 15:00 (Istanbul) |
| CarrefourSA | Her Cuma 15:00 (Istanbul) | — |

## Gönderen Mail
`Reports_InfoSec@pure7.com.tr` (Pure7 InfoSec Reports)
