"""Графіки та таблиця з власного report.json (без сторонніх бібліотек).

Запуск після вимірювань:
    python -m benchmarks.plot_results --input results/practice-02/report.json

Створює поруч із report.json:
- encrypt_throughput.svg, decrypt_throughput.svg — медіана МіБ/с від розміру,
  вертикальні риски показують розкид п'яти серій (мінімум–максимум);
- summary.md — таблиця медіан, IQR і швидкості для всіх 36 рядків.
"""

import argparse
import json
import math
from pathlib import Path

COLORS = ("#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b")
DASH = {"cryptography": "", "pycryptodome": "6,4"}
SIZE_LABELS = {1024: "1 КіБ", 65536: "64 КіБ", 1048576: "1024 КіБ"}
OP_TITLES = {
    "encrypt": "Шифрування",
    "decrypt": "Перевірене розшифрування",
}


def _throughput(size: int, mean_ns: float) -> float:
    return size * 1e9 / (2**20 * mean_ns)


def _nice_ceiling(value: float) -> float:
    """Найближча зверху «кругла» межа осі: 1, 2 або 5 × 10^k."""
    power = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 5, 10):
        if value <= step * power:
            return step * power
    return 10 * power


def make_svg(rows: list[dict], operation: str) -> str:
    rows = [r for r in rows if r["operation"] == operation]
    sizes = sorted({r["size_bytes"] for r in rows})
    combos = sorted({(r["algorithm"], r["backend"]) for r in rows})
    width, height, left, right, top, bottom = 900, 520, 80, 250, 50, 60
    plot_w, plot_h = width - left - right, height - top - bottom
    y_max = _nice_ceiling(max(_throughput(r["size_bytes"], min(r["series_mean_ns"])) for r in rows) * 1.05)

    def x(size):
        return left + plot_w * sizes.index(size) / (len(sizes) - 1)

    def y(value):
        return top + plot_h * (1 - value / y_max)

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'font-family="Arial, sans-serif" font-size="13">',
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text x="{left}" y="28" font-size="16" font-weight="bold">'
        f'{OP_TITLES[operation]}: пропускна здатність, МіБ/с (медіана 5 серій)</text>',
    ]
    for i in range(6):
        value = y_max * i / 5
        out.append(f'<line x1="{left}" x2="{left + plot_w}" y1="{y(value):.1f}" y2="{y(value):.1f}" stroke="#ddd"/>')
        out.append(f'<text x="{left - 8}" y="{y(value) + 4:.1f}" text-anchor="end">{value:.0f}</text>')
    for size in sizes:
        out.append(f'<text x="{x(size):.1f}" y="{top + plot_h + 22}" text-anchor="middle">{SIZE_LABELS.get(size, size)}</text>')
    out.append(f'<text x="{left + plot_w / 2}" y="{height - 12}" text-anchor="middle">Розмір повідомлення</text>')
    out.append(f'<text transform="translate(20,{top + plot_h / 2}) rotate(-90)" text-anchor="middle">МіБ/с</text>')
    out.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" fill="none" stroke="#333"/>')

    for index, (algorithm, backend) in enumerate(combos):
        color = COLORS[index % len(COLORS)]
        series = {r["size_bytes"]: r for r in rows if r["algorithm"] == algorithm and r["backend"] == backend}
        points = " ".join(f"{x(s):.1f},{y(series[s]['throughput_mib_s']):.1f}" for s in sizes)
        out.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" stroke-dasharray="{DASH[backend]}"/>')
        for s in sizes:
            r = series[s]
            low = _throughput(s, max(r["series_mean_ns"]))
            high = _throughput(s, min(r["series_mean_ns"]))
            out.append(f'<line x1="{x(s):.1f}" x2="{x(s):.1f}" y1="{y(low):.1f}" y2="{y(high):.1f}" stroke="{color}" stroke-width="2"/>')
            out.append(f'<circle cx="{x(s):.1f}" cy="{y(r["throughput_mib_s"]):.1f}" r="4" fill="{color}"/>')
        ly = top + 20 + index * 24
        out.append(f'<line x1="{left + plot_w + 15}" x2="{left + plot_w + 45}" y1="{ly}" y2="{ly}" stroke="{color}" stroke-width="2" stroke-dasharray="{DASH[backend]}"/>')
        out.append(f'<text x="{left + plot_w + 52}" y="{ly + 4}">{algorithm} / {backend}</text>')
    out.append(f'<text x="{left + plot_w + 15}" y="{top + 20 + len(combos) * 24 + 10}" font-size="11" fill="#555">риска: розкид 5 серій (min–max)</text>')
    out.append("</svg>")
    return "\n".join(out)


def make_table(report: dict) -> str:
    lines = [
        f"# Підсумок вимірювань (run_id {report['run_id']})",
        "",
        "Медіана середніх часів п'яти серій, міжквартильний розмах (IQR) і пропускна здатність "
        "за байтами початкового повідомлення.",
        "",
        "| Алгоритм | Бібліотека | Розмір, байт | Операція | Медіана, мкс | IQR, мкс | МіБ/с |",
        "|---|---|---:|---|---:|---:|---:|",
    ]
    for r in report["results"]:
        lines.append(
            f"| {r['algorithm']} | {r['backend']} | {r['size_bytes']} | {r['operation']} | "
            f"{r['median_ns'] / 1000:.2f} | {r['iqr_ns'] / 1000:.2f} | {r['throughput_mib_s']:.1f} |"
        )
    env = report["environment"]
    lines += [
        "",
        "## Середовище",
        "",
        f"- Процесор: {env.get('cpu_model')}",
        f"- ОС: {env.get('os')}, архітектура {env.get('architecture')}",
        f"- Python {env.get('python')}",
        f"- cryptography {env['cryptography'].get('version')}, {env['cryptography'].get('openssl')}",
        f"- PyCryptodome {env['pycryptodome'].get('version')}, AES-NI: {env['pycryptodome'].get('aes_ni')}, CLMUL: {env['pycryptodome'].get('clmul')}",
        f"- Таймер: {env['timer'].get('implementation')}, роздільність {env['timer'].get('resolution_s')} с",
        f"- Коміт перед дослідом: {report.get('code_state', {}).get('git_commit')}",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 charts")
    parser.add_argument("--input", type=Path, default=Path("results/practice-02/report.json"))
    args = parser.parse_args()
    report = json.loads(args.input.read_text(encoding="utf-8"))
    folder = args.input.parent
    for operation in ("encrypt", "decrypt"):
        (folder / f"{operation}_throughput.svg").write_text(make_svg(report["results"], operation), encoding="utf-8")
    (folder / "summary.md").write_text(make_table(report), encoding="utf-8")
    print(f"Charts and summary.md written to {folder}")


if __name__ == "__main__":
    main()
