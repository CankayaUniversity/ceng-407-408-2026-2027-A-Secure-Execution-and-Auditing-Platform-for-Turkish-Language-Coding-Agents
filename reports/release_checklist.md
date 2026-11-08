# v0.1.0 release kontrolü

- [x] Ekip değişiklikleri `prototype_v1` dalından pullandı (`8f44b66`).
- [x] Temiz GitHub klonu alındı; kişisel `.env` taşınmadı.
- [x] ASR/TCR/FBR ve eşleştirilmiş latency kaynakları raporda açıklandı.
- [x] Kaynak commit CI başarılı (`42425753518`).
- [x] README, CHANGELOG ve bilinen sınırlamalar hazırlandı.
- [x] Gemini Compose seçimi için startup/cleanup ve fail-closed testleri geçti.
- [x] Tam Linux test takımı yeni yerel kodda başarılı: 707 test + 204 alt test, 8 demo testi.
- [x] Temiz Compose demo ve restart kalıcılığı başarılı.
- [x] Gerçek Gemini + Graph Inspector + Permit + ayrı Sandbox Executor birlikte doğrulandı.
- [x] Metrikler kaynak JSONL'den yeniden hesaplanıp doğrulandı.
- [x] Yerel `v0.1.0` etiketi doğrulanmış release commit'i için hazırlandı.
- [ ] Ekip/kullanıcı son demo ve etiket hedefini onayladı.
- [ ] Release commit'i ve etiket pushlandı, o commit'in CI'ı başarılı.

Son iki adım uzaktaki teslim işlemleridir. Kullanıcı bu çalışma için push
yapılmamasını istedi; kendiliğinden yayın yapılmaz. Testlerden biri bekliyorsa
sürüm tamamlanmış olarak işaretlenmez.
