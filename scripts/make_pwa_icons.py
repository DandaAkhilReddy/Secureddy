"""Generate the PWA icons (brass shield monogram on the dark brand background).

Run from the repository root:  python scripts/make_pwa_icons.py
Writes src/reddysec/web/static/icons/*.png. The PNGs are committed, so the
app never needs Pillow fonts at runtime; re-run only when the mark changes.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "src" / "reddysec" / "web" / "static" / "icons"
BG = (14, 19, 24, 255)  # --bg
BRASS = (201, 163, 92, 255)  # --accent
BRASS_LIGHT = (220, 184, 110, 255)  # --accent-strong
FONTS = (
    "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
)
SS = 4  # supersampling for smooth edges


def _bezier(p0, p1, p2, p3, n=48):
    pts = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def shield(cx: float, top: float, w: float, h: float) -> list[tuple[float, float]]:
    """A heater shield: flat shoulders, straight sides, curved to a point."""
    hw = w / 2
    shoulder = top + h * 0.12
    side_end = top + h * 0.42
    bottom = top + h
    pts = [(cx, top), (cx + hw, shoulder), (cx + hw, side_end)]
    pts += _bezier((cx + hw, side_end), (cx + hw, top + h * 0.72), (cx + hw * 0.45, top + h * 0.9), (cx, bottom))[1:]
    pts += _bezier((cx, bottom), (cx - hw * 0.45, top + h * 0.9), (cx - hw, top + h * 0.72), (cx - hw, side_end))[1:]
    pts += [(cx - hw, shoulder)]
    return pts


def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def draw_icon(size: int, *, scale: float, rounded: bool = False) -> Image.Image:
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if rounded:
        d.rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.22), fill=BG)
    else:
        d.rectangle((0, 0, S, S), fill=BG)
    w = S * 0.62 * scale
    h = S * 0.72 * scale
    top = (S - h) / 2
    d.polygon(shield(S / 2, top, w, h), fill=BRASS)
    inset = S * 0.045 * scale
    d.polygon(shield(S / 2, top + inset * 1.2, w - 2 * inset, h - 2.1 * inset), fill=BG)
    f = font(int(h * 0.56))
    box = d.textbbox((0, 0), "S", font=f)
    tw, th = box[2] - box[0], box[3] - box[1]
    d.text((S / 2 - tw / 2 - box[0], top + h * 0.44 - th / 2 - box[1]), "S", font=f, fill=BRASS_LIGHT)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    draw_icon(192, scale=1.0).save(OUT / "icon-192.png", optimize=True)
    draw_icon(512, scale=1.0).save(OUT / "icon-512.png", optimize=True)
    # Maskable: the mark stays inside the central 80% safe zone.
    draw_icon(512, scale=0.72).save(OUT / "icon-maskable-512.png", optimize=True)
    draw_icon(180, scale=0.9).convert("RGB").save(OUT / "apple-touch-icon.png", optimize=True)
    draw_icon(64, scale=1.12, rounded=True).save(OUT / "favicon-64.png", optimize=True)
    draw_icon(32, scale=1.15, rounded=True).save(OUT / "favicon-32.png", optimize=True)
    print("wrote", sorted(p.name for p in OUT.glob("*.png")))


if __name__ == "__main__":
    main()
