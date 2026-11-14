"""Tests for make-icons.py's pure parts: no Chrome or macOS tools needed.

    python3 -m unittest discover -s apps/desktop/scripts -p "test_*.py"
"""
import importlib.util
import os
import struct
import tempfile
import unittest

_spec = importlib.util.spec_from_file_location(
    "make_icons", os.path.join(os.path.dirname(__file__), "make-icons.py"))
make_icons = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_icons)


def _svg(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".svg", delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


class VariantFor(unittest.TestCase):
    def test_ios_icons_are_opaque_squares(self):
        self.assertEqual(make_icons.variant_for("icons/ios/AppIcon-60x60@3x.png"), ("square", True))
        self.assertEqual(
            make_icons.variant_for("gen/apple/Assets.xcassets/AppIcon.appiconset/AppIcon-512@2x.png"),
            ("square", True))

    def test_android_shapes(self):
        self.assertEqual(make_icons.variant_for("icons/android/mipmap-hdpi/ic_launcher_round.png"), ("circle", False))
        self.assertEqual(make_icons.variant_for("icons/android/mipmap-hdpi/ic_launcher_foreground.png"),
                         ("foreground", False))
        self.assertEqual(make_icons.variant_for("icons/android/mipmap-hdpi/ic_launcher.png"), ("rounded", False))

    def test_desktop_and_windows_icons_use_the_rounded_tile(self):
        for path in ("icons/icon.png", "icons/32x32.png", "icons/Square150x150Logo.png", "app-icon.png"):
            self.assertEqual(make_icons.variant_for(path), ("rounded", False), path)

    def test_windows_separators(self):
        self.assertEqual(make_icons.variant_for(r"icons\ios\AppIcon-20x20@1x.png"), ("square", True))


class ReadLogo(unittest.TestCase):
    def test_reads_the_real_logo(self):
        fill, rx, castle = make_icons.read_logo()
        self.assertEqual(fill.lower(), "#123f3a")
        self.assertEqual(rx, 68)
        self.assertEqual(castle.count("<path"), 3)
        self.assertNotIn("<rect", castle)

    def test_missing_rx_means_square_plate(self):
        path = _svg('<svg><rect width="300" height="300" fill="#000"/><path d="M0 0h1v1Z"/></svg>')
        self.assertEqual(make_icons.read_logo(path)[1], 0.0)

    def test_rejects_a_logo_without_a_plate(self):
        path = _svg('<svg><path d="M0 0h1v1Z"/></svg>')
        with self.assertRaisesRegex(ValueError, "no <rect> plate"):
            make_icons.read_logo(path)

    def test_rejects_a_logo_without_paths(self):
        path = _svg('<svg><rect width="300" height="300" fill="#000"/></svg>')
        with self.assertRaisesRegex(ValueError, "no <path> elements"):
            make_icons.read_logo(path)


class MasterSvg(unittest.TestCase):
    def test_shapes_change_only_the_plate_radius(self):
        self.assertIn('rx="68"', make_icons.master_svg("rounded", "#123f3a", 68, ""))
        self.assertIn('rx="0"', make_icons.master_svg("square", "#123f3a", 68, ""))
        self.assertIn('rx="150"', make_icons.master_svg("circle", "#123f3a", 68, ""))

    def test_foreground_has_no_plate_and_a_wider_view(self):
        svg = make_icons.master_svg("foreground", "#123f3a", 68, "<path/>")
        self.assertNotIn("<rect", svg)
        self.assertIn(f'viewBox="{make_icons.FOREGROUND_VIEWBOX}"', svg)

    def test_foreground_castle_fits_the_android_safe_zone(self):
        x, y, w, _ = (float(v) for v in make_icons.FOREGROUND_VIEWBOX.split())
        cx, cy = x + w / 2, y + w / 2
        safe_radius = w * 0.66 / 2
        for corner in ((40, 78), (260, 78), (40, 235), (260, 235)):
            self.assertLessEqual(((corner[0] - cx) ** 2 + (corner[1] - cy) ** 2) ** 0.5, safe_radius, corner)


class IcoBytes(unittest.TestCase):
    def test_directory_points_at_each_png(self):
        blobs = [(16, b"a" * 10), (256, b"b" * 20)]
        data = make_icons.ico_bytes(blobs)
        self.assertEqual(struct.unpack("<HHH", data[:6]), (0, 1, 2))
        first = struct.unpack("<BBBBHHII", data[6:22])
        second = struct.unpack("<BBBBHHII", data[22:38])
        self.assertEqual((first[0], first[6], first[7]), (16, 10, 38))
        self.assertEqual((second[0], second[6], second[7]), (0, 20, 48))  # 0 encodes 256px
        self.assertEqual(data[38:48], b"a" * 10)
        self.assertEqual(data[48:], b"b" * 20)

    def test_rejects_sizes_ico_cannot_hold(self):
        with self.assertRaises(ValueError):
            make_icons.ico_bytes([(512, b"x")])


if __name__ == "__main__":
    unittest.main()
