"""Графіки й таблиці з власного results/practice-04/report.json (без сторонніх бібліотек).

Запуск після експерименту:
    python -m benchmarks.plot_hash

Створює в results/practice-04:
- throughput.svg — пропускна здатність, МіБ/с (медіана 5 серій), лог. шкали;
  суцільна лінія — whole, пунктир — chunked;
- avalanche.svg — середня частка змінених бітів хешу (точка) і діапазон min–max
  за 100 змінами одного біта;
- summary.md — таблиці медіани, IQR, МіБ/с, лавинного ефекту та перевірок.
Недоступні профілі не малюються й не замінюються нулями.
"""
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "results" / "practice-04"
COLORS = {"sha256": "#1f77b4", "sha512": "#ff7f0e", "sha3-256": "#2ca02c", "blake2b-256": "#d62728",
          "blake2s-256": "#9467bd", "md5": "#8c564b", "sha1": "#7f7f7f"}
SIZE_LABEL = {64: "64 Б", 1024: "1 КіБ", 65536: "64 КіБ", 1048576: "1 МіБ"}


def _head(width, height, title):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'font-family="Arial, sans-serif" font-size="13">',
            f'<rect width="{width}" height="{height}" fill="white"/>',
            f'<text x="20" y="28" font-size="16" font-weight="bold">{title}</text>']


def throughput_chart(results: list[dict]) -> str:
    sizes = sorted({r["payload_bytes"] for r in results})
    algorithms = [a for a in COLORS if any(r["algorithm"] == a for r in results)]
    width, height, left, right, top, bottom = 960, 540, 80, 250, 50, 60
    pw, ph = width - left - right, height - top - bottom
    values = [r["throughput_mib_s"] for r in results]
    low = math.floor(math.log10(min(values)))
    high = math.ceil(math.log10(max(values)))

    def x(size):
        return left + pw * sizes.index(size) / (len(sizes) - 1)

    def y(value):
        return top + ph * (1 - (math.log10(value) - low) / (high - low))

    out = _head(width, height, "Пропускна здатність хешування, МіБ/с (медіана 5 серій, лог. шкала)")
    for p in range(low, high + 1):
        out.append(f'<line x1="{left}" x2="{left + pw}" y1="{y(10**p):.1f}" y2="{y(10**p):.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 8}" y="{y(10**p) + 4:.1f}" text-anchor="end">{10**p:g}</text>')
    for s in sizes:
        out.append(f'<text x="{x(s):.1f}" y="{top + ph + 22}" text-anchor="middle">{SIZE_LABEL[s]}</text>')
    out.append(f'<text x="{left + pw / 2}" y="{height - 12}" text-anchor="middle">Розмір повідомлення</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" fill="none" stroke="#333"/>')
    for i, algorithm in enumerate(algorithms):
        color = COLORS[algorithm]
        for mode, dash in (("whole", ""), ("chunked", "5,4")):
            rows = {r["payload_bytes"]: r for r in results if r["algorithm"] == algorithm and r["mode"] == mode}
            line = " ".join(f"{x(s):.1f},{y(rows[s]['throughput_mib_s']):.1f}" for s in sizes)
            out.append(f'<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2" stroke-dasharray="{dash}"/>')
            for s in sizes:
                out.append(f'<circle cx="{x(s):.1f}" cy="{y(rows[s]["throughput_mib_s"]):.1f}" r="3" fill="{color}"/>')
        ly = top + 18 + i * 24
        out.append(f'<line x1="{left + pw + 15}" x2="{left + pw + 45}" y1="{ly}" y2="{ly}" stroke="{color}" stroke-width="3"/>')
        out.append(f'<text x="{left + pw + 52}" y="{ly + 4}">{algorithm}</text>')
    ly = top + 18 + len(algorithms) * 24 + 10
    out.append(f'<text x="{left + pw + 15}" y="{ly}" font-size="11" fill="#555">суцільна — whole</text>')
    out.append(f'<text x="{left + pw + 15}" y="{ly + 16}" font-size="11" fill="#555">пунктир — chunked</text>')
    out.append(f'<text x="{left + pw + 15}" y="{ly + 32}" font-size="11" fill="#555">джерело: report.json</text>')
    out.append("</svg>")
    return "\n".join(out)


def avalanche_chart(avalanche: list[dict]) -> str:
    width, height, left, top, bottom = 860, 460, 80, 50, 80
    pw, ph = width - left - 30, height - top - bottom

    def y(fraction):
        return top + ph * (1 - fraction)

    out = _head(width, height, "Лавинний ефект: частка змінених бітів хешу (100 змін одного біта)")
    for i in range(6):
        f = i / 5
        out.append(f'<line x1="{left}" x2="{left + pw}" y1="{y(f):.1f}" y2="{y(f):.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 8}" y="{y(f) + 4:.1f}" text-anchor="end">{f:.1f}</text>')
    out.append(f'<line x1="{left}" x2="{left + pw}" y1="{y(0.5):.1f}" y2="{y(0.5):.1f}" stroke="#999" stroke-dasharray="4,4"/>')
    slot = pw / len(avalanche)
    for i, a in enumerate(avalanche):
        color = COLORS[a["algorithm"]]
        cx = left + slot * (i + 0.5)
        lo, hi = a["min_flipped_bits"] / a["digest_bits"], a["max_flipped_bits"] / a["digest_bits"]
        out.append(f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{y(hi):.1f}" y2="{y(lo):.1f}" stroke="{color}" stroke-width="3"/>')
        out.append(f'<line x1="{cx - 10:.1f}" x2="{cx + 10:.1f}" y1="{y(hi):.1f}" y2="{y(hi):.1f}" stroke="{color}" stroke-width="2"/>')
        out.append(f'<line x1="{cx - 10:.1f}" x2="{cx + 10:.1f}" y1="{y(lo):.1f}" y2="{y(lo):.1f}" stroke="{color}" stroke-width="2"/>')
        out.append(f'<circle cx="{cx:.1f}" cy="{y(a["mean_fraction"]):.1f}" r="6" fill="{color}"/>')
        out.append(f'<text x="{cx + 10:.1f}" y="{y(a["mean_fraction"]) - 8:.1f}" font-size="11">{a["mean_fraction"]:.3f}</text>')
        out.append(f'<text x="{cx:.1f}" y="{top + ph + 20}" text-anchor="middle">{a["algorithm"]}</text>')
        out.append(f'<text x="{cx:.1f}" y="{top + ph + 36}" text-anchor="middle" font-size="11" fill="#555">{a["digest_bits"]} біт</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" fill="none" stroke="#333"/>')
    out.append(f'<text x="{left}" y="{height - 10}" font-size="11" fill="#555">точка — середня частка; риска — min–max; '
               f'пунктир 0.5 — орієнтир, не поріг безпеки; джерело: report.json</text>')
    out.append("</svg>")
    return "\n".join(out)


def summary(report: dict) -> str:
    env = report["environment"]
    lines = [
        "# Підсумок експерименту практичної 4", "",
        f"source_commit `{report['source_commit']}`, created_at {report['created_at']}.",
        f"Середовище: Python {env['python']}, {env['openssl_ssl']}, {env['os']}, {env['architecture']}, CPU: {env['cpu']}.",
        "", "## Статуси профілів", "", "| Профіль | Доступний | Реалізація |", "|---|---|---|",
    ]
    for a in report["algorithms"]:
        lines.append(f"| {a['algorithm']} | {'так' if a['available'] else 'ні (' + a['reason'] + ')'} | {a['implementation'] or '—'} |")
    lines += ["", "## Швидкодія", "",
              "| Профіль | Спосіб | S, байт | Повторів | Медіана, нс | IQR, нс | МіБ/с |", "|---|---|---:|---:|---:|---:|---:|"]
    for r in report["results"]:
        lines.append(f"| {r['algorithm']} | {r['mode']} | {r['payload_bytes']} | {r['repeats']} | "
                     f"{r['median_ns']:.0f} | {r['iqr_ns']:.0f} | {r['throughput_mib_s']:.1f} |")
    lines += ["", "## Лавинний ефект (1024 байти, 100 змін одного біта)", "",
              "| Профіль | Біт хешу | Мін | Макс | Середнє | Середня частка |", "|---|---:|---:|---:|---:|---:|"]
    for a in report["avalanche"]:
        lines.append(f"| {a['algorithm']} | {a['digest_bits']} | {a['min_flipped_bits']} | {a['max_flipped_bits']} | "
                     f"{a['mean_flipped_bits']:.2f} | {a['mean_fraction']:.4f} |")
    passed = sum(c["passed"] for c in report["checks"])
    lines += ["", f"## Перевірки коректності: {passed} з {len(report['checks'])} пройдено", ""]
    failed = [c for c in report["checks"] if not c["passed"]]
    lines.append("Усі перевірки пройдено." if not failed else
                 "Невдалі: " + ", ".join(f"{c['algorithm']}/{c['name']}" for c in failed))
    return "\n".join(lines) + "\n"


def main(folder: Path = FOLDER) -> None:
    report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    (folder / "throughput.svg").write_text(throughput_chart(report["results"]), encoding="utf-8")
    (folder / "avalanche.svg").write_text(avalanche_chart(report["avalanche"]), encoding="utf-8")
    (folder / "summary.md").write_text(summary(report), encoding="utf-8")
    print(f"Charts and summary.md written to {folder}")


if __name__ == "__main__":
    main()
