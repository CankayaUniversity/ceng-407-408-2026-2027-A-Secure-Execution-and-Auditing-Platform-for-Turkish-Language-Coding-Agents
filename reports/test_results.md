# Sürüm test doğrulaması

8 Kasım 2026. Kaynak: `8f44b66` + yerel release hazırlığı.

| Kontrol | Gözlenen sonuç | Kapsam |
| --- | --- | --- |
| Kaynak commit CI | Başarılı | `8f44b66`, GitHub run `42425753518` |
| Önceki Linux regresyonu | 701 test + 204 alt test geçti | 7 Kasım değerlendirme sürümü |
| Önceki demo login | 8 test geçti | 7 Kasım |
| Yerel provider/agent/registry | 125 test geçti | 8 Kasım Windows, gerçek API çağrısı olmadan |
| Yeni tam Linux regresyonu | 707 test + 204 alt test geçti | Python 3.11.18, 0 başarısız/hata/atlanan |
| Güncel demo login | 8 test geçti | Python 3.11.18 Linux |
| Temiz klon | Başarılı | GitHub `prototype_v1`, commit `8f44b66`, kişisel `.env` yok |
| Temiz Compose demo | Başarılı | Temiz `8f44b66` klonu, ayrı servisler, imza, sınırlar ve restart kalıcılığı |
| Gerçek Gemini + ayrı Executor | Başarılı | `gemini-3.1-flash-lite`, Graph Inspector, permit, audit ve ayrı servis |
| Nihai metrik kontrolü | Başarılı | İki koşuda 12'şer sonuç yeniden hesaplandı; kayıtlı metrikler birebir aynı, toplam 24/24 trace özeti eşleşiyor |

Yerel birim/regresyon testleri ile gerçek servis demosu ayrı doğrulamalardır.
Windows çıktı kodlaması uyarısı, alt süreçte açık UTF-8 kullanımıyla giderildi;
temiz demo tekrarı ve gerçek Gemini koşusu uyarısız tamamlandı. CI kaynak
commit'e aittir; push edilmemiş release değişiklikleri için CI çalışmış sayılmaz.
