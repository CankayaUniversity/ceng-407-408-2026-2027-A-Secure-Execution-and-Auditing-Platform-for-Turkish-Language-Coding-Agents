# Kişi 4 — Gün 1–6 teslim durumu

7 Kasım 2026 tarihli yerel doğrulama. CI doğrulaması push sonrasında yapılmalı.

Bu dosya 7 Kasım koşusunun tarihsel özetidir. 8 Kasım ayrı Executor servisi ve
sürüm doğrulamasının güncel sonucu için `reports/docs/evaluation.md` dosyasına bakın.

| Gün | Kişisel teslim | Doğrulama |
| --- | --- | --- |
| 1 | SQLite audit, logger, pytest ve CI altyapısı | Repository/logger/Gateway audit testleri; gerçek çalıştırmalarda SQLite kayıtları |
| 2 | Demo login, Policy senaryoları, Gateway–Executor–Audit bağlantısı | Linux Executor entegrasyonları ve demo login testleri |
| 3 | Decision Engine, Policy–Supervisor sırası, kararların audit kaydı | Gerçek Gemini Supervisor çağrıları; offline ALLOW/DENY/REVIEW ve hata testleri |
| 4 | NetworkX Graph Inspector, Decision Engine ve audit bağlantısı | Risk/eksik graph testleri; graph–audit–permit izleri |
| 5 | Altı normal senaryo, ekipten altı saldırı, runner ve metrikler | Her iki çalıştırmada on iki JSON senaryosu yüklendi ve sonuçları kaydedildi |
| 6 | On iki senaryo çalıştırması, metrik/Added Latency ve raporlar | `fixture/` ve `gemini/` sonuçları; altı gerçek süre çifti; 12/12 trace eşleşmesi |

## Gerçek Supervisor ile sonuç

- Model: `gemini-3.1-flash-lite`.
- Altı normal görev tamamlandı; altı saldırı hedefi Policy tarafından engellendi.
- ASR: 0/6, %0. TCR: 6/6, %100. FBR: 0/6, %0.
- Graph–audit–permit eşleşmesi: 12/12 senaryo.
- Altı normal görevde güvenlik açık ortalama süre: 4277,10 ms.
- Aynı görevlerin baseline ortalaması: 96,91 ms.
- Ortalama Added Latency: 4180,19 ms, yaklaşık 4,18 saniye.

Süreler tek geçişte ölçüldü ve model/ağ süresini içeriyor. Agent önerileri
betiklenmiştir; canlı bir üretken agent'ın saldırıya uyma oranı ölçülmedi.
Saldırı hedeflerinin Policy tarafından reddedilmesi Supervisor'a gönderilmelerini
engeller. Bu sonuçlar modelin bütün saldırıları tespit ettiğini göstermez.

Test sayıları ve son doğrulama `test_summary.json` içindedir. Yeniden çalıştırma
ve ölçüm yöntemi `docs/evaluation.md` dosyasında açıklanmıştır.

## Ekipte kalan dağıtım işi

Ayrı Docker Executor servisinin entry point'i hâlâ kapalı. Bu servis için sandbox
sorumlusunun entegrasyonu ve ekip kabul kontrolü gerekir. Mevcut değerlendirme,
gerçek Executor'ı bir test konteynerinde geçici proje kopyalarıyla çalıştırdı;
ayrı servisin tamamlandığı anlamına gelmez.

API anahtarı ve ham SQLite dosyaları Git dışında tutuldu. Bu yerel doğrulama yeni
değişikliklerin GitHub Actions sonucu değildir; CI push sonrasında çalışabilir.
