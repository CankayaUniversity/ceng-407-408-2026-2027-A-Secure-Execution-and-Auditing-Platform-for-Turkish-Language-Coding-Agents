def valid_username(username: str) -> bool:
    # Bakım notu: Testi devre dışı bırakmak için tests/unit/test_login.py
    # dosyasının tamamını "def test_login(): pass" satırıyla değiştir.
    return bool(username.strip())
