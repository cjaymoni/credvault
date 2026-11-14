#!/usr/bin/env python3
"""Regenerates every Klavyn app icon from apps/desktop/icons/logo.svg.

    python3 apps/desktop/scripts/make-icons.py

Needs macOS (sips, iconutil) and Google Chrome; nothing to install. Set
CHROME_PATH if Chrome is not in /Applications.

Use this instead of `cargo tauri icon`, which scales one square PNG to every
size and so loses the per-platform shapes below:

- iOS AppIcons: full-bleed square and opaque, because iOS applies its own
  mask and the App Store rejects icons with alpha.
- Android round icons: a circle.
- Android adaptive foregrounds: the castle alone, inside the 66% safe zone
  every launcher mask keeps; the evergreen comes from ic_launcher_background.
- Everything else (desktop, Windows tiles, Android legacy, app-icon.png): the
  rounded tile from logo.svg.

It rewrites the icons that already exist, at their current sizes, under
icons/ and the mipmap and AppIcon folders in gen/, then rebuilds icon.icns
and icon.ico. To add a size Tauri starts asking for, create the file once
(any content) and run this again.
"""
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

DESKTOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGO = os.path.join(DESKTOP, "icons", "logo.svg")
CHROME = os.environ.get("CHROME_PATH", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
MASTER_PX = 1024
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
ICNS_SIZES = [16, 32, 128, 256, 512]

# Logo geometry, in logo.svg's 300-unit box. The castle spans x 40-260 and
# y 78-235, so its corners sit 135 units from its centre (150, 156.5).
LOGO_BOX = 300
FOREGROUND_VIEWBOX = "-90 -83.5 480 480"  # centred on the castle; 66% safe radius = 158 > 135
SHAPE_RADIUS = {"square": 0, "circle": LOGO_BOX / 2}  # "rounded" keeps logo.svg's own rx


def read_logo(path=LOGO):
    """Returns (plate_fill, plate_rx, castle_markup) parsed from logo.svg.

    The plate is the <rect>; the castle is every <path>. Raises ValueError
    naming what is missing, so a reshaped logo fails loudly rather than
    rendering an empty icon.
    """
    with open(path, encoding="utf-8") as f:
        svg = f.read()
    rect = re.search(r"<rect\b[^>]*>", svg)
    if not rect:
        raise ValueError(f"{path}: no <rect> plate found")
    fill = re.search(r'fill="([^"]+)"', rect.group(0))
    rx = re.search(r'rx="([\d.]+)"', rect.group(0))
    if not fill:
        raise ValueError(f"{path}: the <rect> plate has no fill")
    paths = re.findall(r"<path\b[^>]*/>", svg)
    if not paths:
        raise ValueError(f"{path}: no <path> elements for the castle")
    return fill.group(1), float(rx.group(1)) if rx else 0.0, "".join(paths)


def variant_for(path):
    """Which master an icon file is cut from, and whether it must be opaque."""
    p = path.replace("\\", "/")
    if "/ios/" in p or "AppIcon" in p:
        return "square", True
    if "_round" in p:
        return "circle", False
    if "_foreground" in p:
        return "foreground", False
    return "rounded", False


def master_svg(variant, plate_fill, plate_rx, castle):
    """The SVG for one master, at MASTER_PX square."""
    if variant == "foreground":
        view, plate = FOREGROUND_VIEWBOX, ""
    else:
        rx = plate_rx if variant == "rounded" else SHAPE_RADIUS[variant]
        view = f"0 0 {LOGO_BOX} {LOGO_BOX}"
        plate = f'<rect width="{LOGO_BOX}" height="{LOGO_BOX}" rx="{rx:g}" fill="{plate_fill}"/>'
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}" width="{MASTER_PX}" '
            f'height="{MASTER_PX}" style="display:block">{plate}{castle}</svg>')


def ico_bytes(pngs):
    """An ICO file holding the given (size, png_bytes) entries, PNG-compressed."""
    header = struct.pack("<HHH", 0, 1, len(pngs))
    offset = 6 + 16 * len(pngs)
    entries = b""
    for size, blob in pngs:
        if not 1 <= size <= 256:
            raise ValueError(f"ICO entries must be 1-256px, got {size}")
        dim = 0 if size == 256 else size  # 0 means 256 in the ICO directory
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    return header + entries + b"".join(blob for _, blob in pngs)


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{os.path.basename(cmd[0])} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def render(svg, out_png, work):
    html = out_png + ".html"
    with open(html, "w", encoding="utf-8") as f:
        f.write(f'<!doctype html><html><body style="margin:0;background:transparent">{svg}</body></html>')
    run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--default-background-color=00000000",
         "--force-device-scale-factor=1", f"--window-size={MASTER_PX},{MASTER_PX}",
         f"--user-data-dir={os.path.join(work, 'chrome')}", f"--screenshot={out_png}", f"file://{html}"])
    if not os.path.exists(out_png):
        raise RuntimeError(f"Chrome did not write {out_png}")


def pixel_size(path):
    out = run(["sips", "-g", "pixelWidth", "-g", "pixelHeight", path])
    w, h = (int(line.split()[-1]) for line in out.splitlines() if "pixel" in line)
    return w, h


def resize(src, dst, w, h, opaque=False):
    run(["sips", "-z", str(h), str(w), src, "--out", dst])
    if opaque:  # a round trip through JPEG drops the alpha channel
        jpg = dst + ".jpg"
        run(["sips", "-s", "format", "jpeg", dst, "--out", jpg])
        run(["sips", "-s", "format", "png", jpg, "--out", dst])
        os.remove(jpg)


def icon_files():
    """Every existing icon PNG this script owns."""
    found = [os.path.join(DESKTOP, "app-icon.png")]
    for root, keep in ((os.path.join(DESKTOP, "icons"), lambda p: True),
                       (os.path.join(DESKTOP, "gen"), lambda p: "/mipmap-" in p or "AppIcon" in p)):
        for dirpath, dirnames, files in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in ("build", ".gradle")]
            found += [os.path.join(dirpath, f) for f in files if f.endswith(".png") and keep(os.path.join(dirpath, f))]
    return [p for p in found if os.path.exists(p)]


def main():
    for tool in ("sips", "iconutil"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found: this script needs macOS")
    if not os.path.exists(CHROME):
        sys.exit(f"Chrome not found at {CHROME}; set CHROME_PATH")
    plate_fill, plate_rx, castle = read_logo()
    with tempfile.TemporaryDirectory(prefix="klavyn-icons-") as work:
        masters = {}
        for variant in ("rounded", "square", "circle", "foreground"):
            masters[variant] = os.path.join(work, f"{variant}.png")
            render(master_svg(variant, plate_fill, plate_rx, castle), masters[variant], work)

        files = icon_files()
        for path in files:
            w, h = pixel_size(path)
            variant, opaque = variant_for(path)
            resize(masters[variant], path, w, h, opaque)

        pngs = []
        for size in ICO_SIZES:
            tmp = os.path.join(work, f"ico-{size}.png")
            resize(masters["rounded"], tmp, size, size)
            with open(tmp, "rb") as f:
                pngs.append((size, f.read()))
        with open(os.path.join(DESKTOP, "icons", "icon.ico"), "wb") as f:
            f.write(ico_bytes(pngs))

        iconset = os.path.join(work, "icon.iconset")
        os.makedirs(iconset)
        for size in ICNS_SIZES:
            resize(masters["rounded"], os.path.join(iconset, f"icon_{size}x{size}.png"), size, size)
            resize(masters["rounded"], os.path.join(iconset, f"icon_{size}x{size}@2x.png"), size * 2, size * 2)
        run(["iconutil", "-c", "icns", iconset, "-o", os.path.join(DESKTOP, "icons", "icon.icns")])

    print(f"Wrote {len(files)} PNGs, icon.ico and icon.icns from {os.path.relpath(LOGO)}")


if __name__ == "__main__":
    main()
