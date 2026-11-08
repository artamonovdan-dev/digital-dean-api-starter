# Підсумок експерименту практичної 3

Коміт коду: `2a8cc761e5c2e105c0c0d23337cfac4ab5650a43`, час UTC: 2026-11-08T12:57:16Z.
Середовище: Python 3.13.17, cryptography 48.0.1, OpenSSL 4.0.1 9 Jun 2026, Windows 11 (AMD64), CPU: 13th Gen Intel(R) Core(TM) i5-13400F.
Методика: прогрів 10, 5 серій по 20 операцій, 5 незалежних генерацій ключа; медіана й IQR (inclusive).

## Генерація ключів

| Ключ | Медіана, мс | IQR, мс | Відкритий ключ DER, байт |
|---|---:|---:|---:|
| rsa-2048 | 23.810 | 15.230 | 294 |
| rsa-3072 | 119.608 | 185.962 | 422 |
| x25519 | 0.053 | 0.006 | 44 |
| p256 | 0.041 | 0.007 | 91 |

## Шифрування та розшифрування

| Профіль | Операція | S, байт | Медіана, мкс | IQR, мкс | Конверт, байт | МіБ/с |
|---|---|---:|---:|---:|---:|---:|
| rsa2048-oaep | encrypt | 64 | 22.2 | 0.0 | 256 | — |
| rsa2048-oaep | decrypt | 64 | 439.6 | 8.4 | 256 | — |
| rsa3072-oaep | encrypt | 64 | 38.3 | 0.8 | 384 | — |
| rsa3072-oaep | decrypt | 64 | 1349.8 | 23.2 | 384 | — |
| rsa3072-oaep-aes256gcm | encrypt | 1024 | 45.4 | 3.6 | 1436 | 21.5 |
| rsa3072-oaep-aes256gcm | decrypt | 1024 | 1348.1 | 24.8 | 1436 | 0.7 |
| rsa3072-oaep-aes256gcm | encrypt | 65536 | 77.3 | 3.8 | 65948 | 808.3 |
| rsa3072-oaep-aes256gcm | decrypt | 65536 | 1404.6 | 56.2 | 65948 | 44.5 |
| rsa3072-oaep-aes256gcm | encrypt | 1048576 | 679.9 | 13.2 | 1048988 | 1470.8 |
| rsa3072-oaep-aes256gcm | decrypt | 1048576 | 1942.5 | 39.3 | 1048988 | 514.8 |
| hpke-x25519-aes256gcm | encrypt | 1024 | 73.8 | 0.9 | 1072 | 13.2 |
| hpke-x25519-aes256gcm | decrypt | 1024 | 43.0 | 0.8 | 1072 | 22.7 |
| hpke-x25519-aes256gcm | encrypt | 65536 | 107.7 | 0.4 | 65584 | 580.1 |
| hpke-x25519-aes256gcm | decrypt | 65536 | 70.0 | 13.6 | 65584 | 893.3 |
| hpke-x25519-aes256gcm | encrypt | 1048576 | 723.2 | 1.5 | 1048624 | 1382.8 |
| hpke-x25519-aes256gcm | decrypt | 1048576 | 402.1 | 19.7 | 1048624 | 2487.0 |
| hpke-p256-aes256gcm | encrypt | 1024 | 88.2 | 5.5 | 1105 | 11.1 |
| hpke-p256-aes256gcm | decrypt | 1024 | 71.5 | 0.4 | 1105 | 13.7 |
| hpke-p256-aes256gcm | encrypt | 65536 | 127.2 | 17.9 | 65617 | 491.2 |
| hpke-p256-aes256gcm | decrypt | 65536 | 99.2 | 12.8 | 65617 | 630.2 |
| hpke-p256-aes256gcm | encrypt | 1048576 | 722.4 | 88.1 | 1048657 | 1384.3 |
| hpke-p256-aes256gcm | decrypt | 1048576 | 449.4 | 36.0 | 1048657 | 2225.2 |

## Перевірки коректності: 22 з 22 пройдено

| Профіль | Перевірка | Результат |
|---|---|---|
| rsa2048-oaep | roundtrip | passed |
| rsa2048-oaep | wrong_key | passed |
| rsa2048-oaep | tamper | passed |
| rsa2048-oaep | wrong_context | passed |
| rsa2048-oaep | oaep_boundary | passed |
| rsa3072-oaep | roundtrip | passed |
| rsa3072-oaep | wrong_key | passed |
| rsa3072-oaep | tamper | passed |
| rsa3072-oaep | wrong_context | passed |
| rsa3072-oaep | oaep_boundary | passed |
| rsa3072-oaep-aes256gcm | roundtrip | passed |
| rsa3072-oaep-aes256gcm | wrong_key | passed |
| rsa3072-oaep-aes256gcm | tamper | passed |
| rsa3072-oaep-aes256gcm | wrong_context | passed |
| hpke-x25519-aes256gcm | roundtrip | passed |
| hpke-x25519-aes256gcm | wrong_key | passed |
| hpke-x25519-aes256gcm | tamper | passed |
| hpke-x25519-aes256gcm | wrong_context | passed |
| hpke-p256-aes256gcm | roundtrip | passed |
| hpke-p256-aes256gcm | wrong_key | passed |
| hpke-p256-aes256gcm | tamper | passed |
| hpke-p256-aes256gcm | wrong_context | passed |

Порядок профілів у серіях (циклічний зсув) збережено в `series_order.json`.
