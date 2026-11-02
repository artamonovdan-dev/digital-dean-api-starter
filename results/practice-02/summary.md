# Підсумок вимірювань (run_id 20261102T092438Z-9b147db1)

Медіана середніх часів п'яти серій, міжквартильний розмах (IQR) і пропускна здатність за байтами початкового повідомлення.

| Алгоритм | Бібліотека | Розмір, байт | Операція | Медіана, мкс | IQR, мкс | МіБ/с |
|---|---|---:|---|---:|---:|---:|
| AES-128-GCM | cryptography | 1024 | encrypt | 2.40 | 0.10 | 407.6 |
| AES-128-GCM | cryptography | 1024 | decrypt | 2.48 | 0.02 | 393.1 |
| AES-128-GCM | cryptography | 65536 | encrypt | 11.66 | 0.36 | 5362.0 |
| AES-128-GCM | cryptography | 65536 | decrypt | 11.87 | 0.93 | 5264.5 |
| AES-128-GCM | cryptography | 1048576 | encrypt | 642.33 | 419.03 | 1556.8 |
| AES-128-GCM | cryptography | 1048576 | decrypt | 618.26 | 33.14 | 1617.4 |
| AES-128-GCM | pycryptodome | 1024 | encrypt | 27.98 | 0.47 | 34.9 |
| AES-128-GCM | pycryptodome | 1024 | decrypt | 38.47 | 2.96 | 25.4 |
| AES-128-GCM | pycryptodome | 65536 | encrypt | 47.45 | 2.88 | 1317.1 |
| AES-128-GCM | pycryptodome | 65536 | decrypt | 57.25 | 3.35 | 1091.7 |
| AES-128-GCM | pycryptodome | 1048576 | encrypt | 756.17 | 674.20 | 1322.5 |
| AES-128-GCM | pycryptodome | 1048576 | decrypt | 777.22 | 52.35 | 1286.6 |
| AES-256-GCM | cryptography | 1024 | encrypt | 2.46 | 0.10 | 397.8 |
| AES-256-GCM | cryptography | 1024 | decrypt | 2.51 | 0.04 | 388.4 |
| AES-256-GCM | cryptography | 65536 | encrypt | 12.92 | 0.11 | 4836.3 |
| AES-256-GCM | cryptography | 65536 | decrypt | 13.45 | 0.15 | 4648.2 |
| AES-256-GCM | cryptography | 1048576 | encrypt | 660.31 | 32.81 | 1514.4 |
| AES-256-GCM | cryptography | 1048576 | decrypt | 646.75 | 49.05 | 1546.2 |
| AES-256-GCM | pycryptodome | 1024 | encrypt | 28.01 | 0.13 | 34.9 |
| AES-256-GCM | pycryptodome | 1024 | decrypt | 36.23 | 1.90 | 27.0 |
| AES-256-GCM | pycryptodome | 65536 | encrypt | 48.15 | 0.43 | 1298.1 |
| AES-256-GCM | pycryptodome | 65536 | decrypt | 57.17 | 0.29 | 1093.3 |
| AES-256-GCM | pycryptodome | 1048576 | encrypt | 808.58 | 152.03 | 1236.7 |
| AES-256-GCM | pycryptodome | 1048576 | decrypt | 791.83 | 18.09 | 1262.9 |
| ChaCha20-Poly1305 | cryptography | 1024 | encrypt | 3.11 | 0.07 | 314.3 |
| ChaCha20-Poly1305 | cryptography | 1024 | decrypt | 3.44 | 0.70 | 284.0 |
| ChaCha20-Poly1305 | cryptography | 65536 | encrypt | 28.61 | 0.09 | 2184.2 |
| ChaCha20-Poly1305 | cryptography | 65536 | decrypt | 29.70 | 0.30 | 2104.2 |
| ChaCha20-Poly1305 | cryptography | 1048576 | encrypt | 934.04 | 956.97 | 1070.6 |
| ChaCha20-Poly1305 | cryptography | 1048576 | decrypt | 913.91 | 57.25 | 1094.2 |
| ChaCha20-Poly1305 | pycryptodome | 1024 | encrypt | 14.60 | 0.46 | 66.9 |
| ChaCha20-Poly1305 | pycryptodome | 1024 | decrypt | 20.09 | 1.65 | 48.6 |
| ChaCha20-Poly1305 | pycryptodome | 65536 | encrypt | 172.17 | 3.12 | 363.0 |
| ChaCha20-Poly1305 | pycryptodome | 65536 | decrypt | 179.88 | 1.40 | 347.5 |
| ChaCha20-Poly1305 | pycryptodome | 1048576 | encrypt | 3137.05 | 2661.64 | 318.8 |
| ChaCha20-Poly1305 | pycryptodome | 1048576 | decrypt | 3078.64 | 79.62 | 324.8 |

## Середовище

- Процесор: 13th Gen Intel(R) Core(TM) i5-13400F
- ОС: Windows-11-10.0.26200-SP0, архітектура AMD64
- Python 3.13.17
- cryptography 48.0.1, OpenSSL 4.0.1 9 Jun 2026
- PyCryptodome 3.24.0, AES-NI: True, CLMUL: True
- Таймер: QueryPerformanceCounter(), роздільність 1e-07 с
- Коміт перед дослідом: 0e17648b2aa4b522f470fa3f1b2140359013d536
