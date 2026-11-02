# Digital Dean API — практичні роботи 1 і 2

Навчальний API інформаційної системи «Цифровий деканат» (FastAPI + Pydantic 2).
Лише синтетичні дані; сховище в пам'яті — дані зникають після перезапуску.

**Індивідуальний варіант: 1 — enrollment_year — рік вступу (ціле число, межі з конфігурації закладу)**

## Запуск

```bash
python -m venv .venv
# Windows:   .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m uvicorn app.main:app --reload
```

Документація: http://127.0.0.1:8000/docs, специфікація: http://127.0.0.1:8000/openapi.json

## Контракт

| Метод | Шлях | Успіх | Помилки | Призначення |
|---|---|---|---|---|
| GET | /health | 200 | — | Готовність застосунку |
| POST | /api/v1/students | 201 | 409, 422 | Створити запис |
| GET | /api/v1/students | 200 | 422 | Список; фільтр `?enrollment_year=` |
| GET | /api/v1/students/{student_id} | 200 | 404, 422 | Запис за UUID |
| PATCH | /api/v1/students/{student_id} | 200 | 404, 409, 422 | Часткова зміна дозволених полів |

Помилки 404/409 мають структуроване тіло `{"detail": {"code": "...", "message": "..."}}`
(`student_not_found`, `email_conflict`). 422 — стандартна відповідь валідації FastAPI.

## Поля запису

| Поле | Тип | Обмеження | Власник |
|---|---|---|---|
| id | UUID | генерується сервером | Сервер |
| full_name | рядок | 5–120 символів після вилучення крайніх пробілів | Клієнт |
| email | e-mail | синтаксично коректна, унікальна без урахування регістру | Клієнт |
| group_code | рядок | `^[A-ZА-ЩЬЮЯҐЄІЇ0-9]{1,10}-[0-9]{2}$`, напр. `КН-31` | Клієнт |
| enrollment_year | див. нижче | див. нижче | Клієнт |

## Індивідуальний варіант

Поле `enrollment_year` — рік вступу, **ціле число** (рядок `"2024"`, дробове число чи `true` відхиляються, бо використано `Strict()`).
Межі **не зашиті в код**: їх читає `app/config.py` зі змінних середовища закладу:

| Змінна | Значення за замовчуванням | Пояснення |
|---|---|---|
| `DEAN_ENROLLMENT_YEAR_MIN` | 2018 | найраніший рік вступу, з яким студент ще може навчатися (бакалаврат 4 р. + магістратура 2 р. + можлива академвідпустка) |
| `DEAN_ENROLLMENT_YEAR_MAX` | 2026 | поточний рік вступної кампанії |

Тести беруть межі з тієї ж конфігурації, тому залишаються правильними при іншому налаштуванні.

## Захисні рішення та межі

- `extra="forbid"`: невідомі поля (`is_admin`, `id` у PATCH) відхиляються з 422 — захист від масового присвоєння. Це **не** авторизація.
- PATCH використовує `model_dump(exclude_unset=True)`; порожнє тіло та `null` відхиляються.
- Унікальність e-mail перевіряється і при оновленні (поточний запис виключено з порівняння).
- Клієнт не отримує трасування стека чи внутрішню структуру сховища.
- Немає автентифікації, авторизації, HTTPS, постійного сховища — це теми наступних робіт.

---

# Практична робота 2 — симетричне шифрування службових приміток

**Індивідуальний варіант роботи 2: 1 — категорія примітки** (`category`: `general`, `academic`, `administrative`).

## Встановлення, запуск, тести, вимірювання

```bash
python -m pip install -e ".[dev]"          # додає cryptography==48.0.1 і pycryptodome==3.24.0
python -m pytest                           # усі тести робіт 1 і 2
python -m uvicorn app.main:app --reload --host 127.0.0.1   # один процес, без --workers
python -m benchmarks.crypto_benchmark --output-dir results/practice-02
python -m benchmarks.plot_results --input results/practice-02/report.json
```

`--reload` і будь-який перезапуск створюють новий ключ і порожнє сховище приміток.

## Нові операції (префікс /api/v1)

| Метод | Шлях | Успіх | Помилки | Результат |
|---|---|---|---|---|
| POST | /students/{student_id}/secure-notes | 201 | 404, 422, 503 | id, student_id, algorithm, category; без text, ключа й конверта |
| GET | /students/{student_id}/secure-notes/{note_id} | 200 | 404, 422, 500 | id, student_id, algorithm, category, перевірений text |
| GET | /lab/crypto/benchmark-results | 200 | 404, 500 | Валідований `results/practice-02/report.json` |

- Тіло POST: `{"text": "...", "category": "academic"}`; `category` необов'язкове (типово `general`).
- 422: порожній текст або лише пробіли, понад 4096 байтів UTF-8, невідоме поле (`key`, `nonce`, `algorithm`…), невідома категорія, неправильний UUID.
- 404: невідомий студент, невідома примітка або примітка іншого студента.
- 500 `{"detail": "Protected note unavailable"}`: пошкоджений чи підмінений серверний конверт, невідомий ключ, інша версія формату.
- 503 `{"detail": "Protected note unavailable"}`: вичерпано навчальну межу використання ключа (1 000 000 записів); старі примітки читаються далі.
- Звіт: 404 / 500 `{"detail": "Benchmark results unavailable"}`; шлях задає конфігурація, не клієнт.

## Внутрішній зашифрований запис

`version=1, student_id, note_id, algorithm=AES-256-GCM, backend=cryptography, key_id, nonce (12 Б), ciphertext, tag (16 Б), category`.
Поля `text` і `key` не зберігаються. Асоційовані дані (канонічний JSON): `version, student_id, note_id, algorithm, key_id, category`.

## Компоненти

| Файл | Відповідальність |
|---|---|
| `app/security/profiles.py` | профілі AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305; перевірка довжин |
| `app/security/adapters.py` | `seal_bytes` / `open_bytes` для cryptography і PyCryptodome, `CiphertextError` |
| `app/security/context.py` | канонічні асоційовані дані (з category) |
| `app/security/nonce.py` | `NonceSequence`: 12-байтовий лічильник під `Lock`, межа використання |
| `app/security/keys.py` | один ключ AES-256 і один лічильник на процес (`get_process_key`) |
| `app/repositories/secure_note_repository.py` | сховище конвертів у пам'яті |
| `app/api/secure_notes.py`, `app/api/crypto_lab.py` | маршрути |
| `benchmarks/crypto_benchmark.py`, `benchmarks/plot_results.py` | вимірювання, графіки, таблиця |

## Межі

Сховище й ключ існують лише в пам'яті одного процесу. Немає автентифікації користувача, авторизації та HTTPS.
Шифрування поля не захищає від захоплення процесу і не контролює повторну видачу старого конверта.
