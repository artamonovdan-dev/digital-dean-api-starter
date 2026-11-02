"""Асоційовані дані пов’язують повідомлення з очікуваним ресурсом."""

import json

CONTEXT_VERSION = 1
DEFAULT_CATEGORY = "general"


def note_aad(student_id, note_id, algorithm, key_id, category=DEFAULT_CATEGORY) -> bytes:
    """Канонічна серіалізація контексту примітки.

    Однакова для запису й читання: відсортовані ключі, без пробілів, UTF-8.
    Індивідуальний варіант 1: category входить до контексту, тому зміна
    збереженої категорії спричиняє відхилення перевірки тега.
    Контекст не шифрується, тож чутливий текст сюди не потрапляє.
    """
    context = {
        "version": CONTEXT_VERSION,
        "student_id": str(student_id),
        "note_id": str(note_id),
        "algorithm": algorithm,
        "key_id": str(key_id),
        "category": category,
    }
    return json.dumps(
        context, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
