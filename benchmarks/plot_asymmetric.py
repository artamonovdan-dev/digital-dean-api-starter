"""Графіки й таблиця з власного results/practice-03/report.json (без сторонніх бібліотек).

Запуск після експерименту:
    python -m benchmarks.plot_asymmetric

Створює в results/practice-03:
- hybrid_time.svg — медіанний час encrypt/decrypt гібридних профілів за розмірами (лог. шкали);
- direct_rsa_time.svg — медіанний час encrypt/decrypt прямого RSA-OAEP на 64 байтах;
- keygen_time.svg — медіанний час генерації пари ключів (лог. шкала);
- summary.md — таблиці медіан, IQR, розмірів конверта, пропускної здатності та перевірок.
Риска на графіках — IQR п'яти серій (Q1–Q3 навколо медіани не відновлюється з агрегату,
тому показано медіана ± IQR/2 як оцінка розкиду).
"""
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "results" / "practice-03"
COLORS = ("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b")
SIZE_LABEL = {64: "64 Б", 1024: "1 КіБ", 65536: "64 КіБ", 1048576: "1 МіБ"}


def _ms(ns: float) -> float:
    return ns / 1e6


def _header(width: int, height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="Arial, sans-serif" font-size="13">',
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text x="20" y="28" font-size="16" font-weight="bold">{title}</text>',
    ]


def _log_ticks(low: float, high: float) -> list[float]:
    return [10.0 ** p for p in range(math.floor(math.log10(low)), math.ceil(math.log10(high)) + 1)]


def _fmt(value: float) -> str:
    return f"{value:g}"


def hybrid_chart(results: list[dict]) -> str:
    rows = [r for r in results if r["group"] == "hybrid"]
    sizes = sorted({r["payload_bytes"] for r in rows})
    series = sorted({(r["profile"], r["operation"]) for r in rows})
    width, height, left, right, top, bottom = 960, 540, 80, 330, 50, 60
    pw, ph = width - left - right, height - top - bottom
    values = [_ms(r["median_ns"]) for r in rows]
    ticks = _log_ticks(min(values) * 0.8, max(values) * 1.25)
    low, high = math.log10(ticks[0]), math.log10(ticks[-1])

    def x(size):
        return left + pw * sizes.index(size) / (len(sizes) - 1)

    def y(ms):
        return top + ph * (1 - (math.log10(ms) - low) / (high - low))

    out = _header(width, height, "Гібридні профілі: медіанний час операції, мс (лог. шкала)")
    for t in ticks:
        out.append(f'<line x1="{left}" x2="{left + pw}" y1="{y(t):.1f}" y2="{y(t):.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{_fmt(t)}</text>')
    for s in sizes:
        out.append(f'<text x="{x(s):.1f}" y="{top + ph + 22}" text-anchor="middle">{SIZE_LABEL.get(s, s)}</text>')
    out.append(f'<text x="{left + pw / 2}" y="{height - 12}" text-anchor="middle">Розмір повідомлення</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" fill="none" stroke="#333"/>')
    profiles = sorted({p for p, _ in series})
    for index, (profile, operation) in enumerate(series):
        color = COLORS[profiles.index(profile) % len(COLORS)]
        dash = "" if operation == "encrypt" else "6,4"
        points = {r["payload_bytes"]: r for r in rows if r["profile"] == profile and r["operation"] == operation}
        line = " ".join(f"{x(s):.1f},{y(_ms(points[s]['median_ns'])):.1f}" for s in sizes)
        out.append(f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2" stroke-dasharray="{dash}"/>')
        for s in sizes:
            r = points[s]
            med, half = _ms(r["median_ns"]), _ms(r["iqr_ns"]) / 2
            out.append(f'<line x1="{x(s):.1f}" x2="{x(s):.1f}" y1="{y(med + half):.1f}" y2="{y(max(med - half, ticks[0])):.1f}" stroke="{color}"/>')
            out.append(f'<circle cx="{x(s):.1f}" cy="{y(med):.1f}" r="3.5" fill="{color}"/>')
        ly = top + 18 + index * 24
        out.append(f'<line x1="{left + pw + 15}" x2="{left + pw + 45}" y1="{ly}" y2="{ly}" stroke="{color}" stroke-width="2" stroke-dasharray="{dash}"/>')
        out.append(f'<text x="{left + pw + 52}" y="{ly + 4}">{profile} / {operation}</text>')
    out.append(f'<text x="{left + pw + 15}" y="{top + 18 + len(series) * 24 + 8}" font-size="11" fill="#555">джерело: report.json; риска: медіана ± IQR/2</text>')
    out.append("</svg>")
    return "\n".join(out)


def bar_chart(labels: list[str], medians_ms: list[float], iqr_ms: list[float], title: str,
              axis: str, log: bool) -> str:
    width, height, left, top, bottom = 820, 460, 90, 50, 110
    pw, ph = width - left - 30, height - top - bottom
    if log:
        ticks = _log_ticks(min(medians_ms) * 0.5, max(m + i for m, i in zip(medians_ms, iqr_ms)) * 1.2)
        low, high = math.log10(ticks[0]), math.log10(ticks[-1])

        def y(v):
            return top + ph * (1 - (math.log10(max(v, ticks[0])) - low) / (high - low))
        base = top + ph
    else:
        peak = max(m + i for m, i in zip(medians_ms, iqr_ms)) * 1.15
        step = 10 ** math.floor(math.log10(peak / 5))
        step *= next(k for k in (1, 2, 5, 10) if peak / 5 <= k * step)
        ticks = [step * i for i in range(int(peak / step) + 2)]

        def y(v):
            return top + ph * (1 - v / ticks[-1])
        base = y(0)
    out = _header(width, height, title)
    for t in ticks:
        out.append(f'<line x1="{left}" x2="{left + pw}" y1="{y(t):.1f}" y2="{y(t):.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{_fmt(round(t, 6))}</text>')
    out.append(f'<text transform="translate(22,{top + ph / 2}) rotate(-90)" text-anchor="middle">{axis}</text>')
    slot = pw / len(labels)
    for i, (label, med, iqr) in enumerate(zip(labels, medians_ms, iqr_ms)):
        color = COLORS[i % len(COLORS)]
        cx = left + slot * (i + 0.5)
        out.append(f'<rect x="{cx - slot * 0.3:.1f}" y="{y(med):.1f}" width="{slot * 0.6:.1f}" height="{base - y(med):.1f}" fill="{color}"/>')
        out.append(f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{y(med + iqr / 2):.1f}" y2="{y(max(med - iqr / 2, 1e-12)):.1f}" stroke="black"/>')
        out.append(f'<text x="{cx:.1f}" y="{y(med) - 6:.1f}" text-anchor="middle" font-size="11">{med:.3g}</text>')
        for j, part in enumerate(label.split("|")):
            out.append(f'<text x="{cx:.1f}" y="{top + ph + 20 + j * 16}" text-anchor="middle" font-size="12">{part}</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" fill="none" stroke="#333"/>')
    out.append(f'<text x="{left}" y="{height - 10}" font-size="11" fill="#555">джерело: report.json; риска: медіана ± IQR/2</text>')
    out.append("</svg>")
    return "\n".join(out)


def summary(report: dict) -> str:
    exp, env = report["experiment"], report["environment"]
    lines = [
        "# Підсумок експерименту практичної 3", "",
        f"Коміт коду: `{exp['source_commit']}`, час UTC: {exp['created_at_utc']}.",
        f"Середовище: Python {env['python']}, cryptography {env['cryptography']}, {env['openssl']}, "
        f"{env['os']}, CPU: {env['cpu']}.",
        f"Методика: прогрів {exp['warmup']}, {exp['series']} серій по {exp['operations_per_series']} "
        f"операцій, {exp['keygen_runs']} незалежних генерацій ключа; медіана й IQR (inclusive).", "",
        "## Генерація ключів", "",
        "| Ключ | Медіана, мс | IQR, мс | Відкритий ключ DER, байт |", "|---|---:|---:|---:|",
    ]
    for k in report["key_generation"]:
        lines.append(f"| {k['key_profile']} | {_ms(k['median_ns']):.3f} | {_ms(k['iqr_ns']):.3f} | {k['public_key_der_bytes']} |")
    lines += ["", "## Шифрування та розшифрування", "",
              "| Профіль | Операція | S, байт | Медіана, мкс | IQR, мкс | Конверт, байт | МіБ/с |",
              "|---|---|---:|---:|---:|---:|---:|"]
    for r in report["results"]:
        mib = "—" if r["throughput_mib_s"] is None else f"{r['throughput_mib_s']:.1f}"
        lines.append(f"| {r['profile']} | {r['operation']} | {r['payload_bytes']} | {r['median_ns'] / 1000:.1f} | "
                     f"{r['iqr_ns'] / 1000:.1f} | {r['ciphertext_bytes']} | {mib} |")
    passed = sum(c["passed"] for c in report["checks"])
    lines += ["", f"## Перевірки коректності: {passed} з {len(report['checks'])} пройдено", "",
              "| Профіль | Перевірка | Результат |", "|---|---|---|"]
    for c in report["checks"]:
        lines.append(f"| {c['profile']} | {c['name']} | {'passed' if c['passed'] else 'FAILED'} |")
    order_file = FOLDER / "series_order.json"
    lines += ["", "Порядок профілів у серіях (циклічний зсув) збережено в `series_order.json`."
              if order_file.exists() else ""]
    return "\n".join(lines) + "\n"


def main(folder: Path = FOLDER) -> None:
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    results = report["results"]
    (folder / "hybrid_time.svg").write_text(hybrid_chart(results), encoding="utf-8")
    direct = [r for r in results if r["group"] == "direct"]
    (folder / "direct_rsa_time.svg").write_text(bar_chart(
        [f"{r['profile']}|{r['operation']}" for r in direct],
        [_ms(r["median_ns"]) for r in direct], [_ms(r["iqr_ns"]) for r in direct],
        "Пряме RSA-OAEP, 64 байти: медіанний час операції, мс", "мс", log=False,
    ), encoding="utf-8")
    keys = report["key_generation"]
    (folder / "keygen_time.svg").write_text(bar_chart(
        [k["key_profile"] for k in keys], [_ms(k["median_ns"]) for k in keys], [_ms(k["iqr_ns"]) for k in keys],
        "Генерація пари ключів: медіана 5 незалежних запусків, мс (лог. шкала)", "мс", log=True,
    ), encoding="utf-8")
    (folder / "summary.md").write_text(summary(report), encoding="utf-8")
    print(f"Charts and summary.md written to {folder}")


if __name__ == "__main__":
    main()
