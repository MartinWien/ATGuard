"""Generate ATGuard's original vector-style app icon at Windows icon sizes."""
from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parent.parent
out = root / "assets"
out.mkdir(exist_ok=True)
im = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
d = ImageDraw.Draw(im)
d.rounded_rectangle((28, 28, 996, 996), radius=218, fill="#111a12", outline="#30472a", width=12)
shield = [(512, 172), (770, 278), (770, 505), (746, 604), (691, 698), (610, 779), (512, 846), (414, 779), (333, 698), (278, 604), (254, 505), (254, 278), (512, 172)]
d.polygon(shield, fill="#20331d")
d.line(shield, fill="#a9e889", width=24, joint="curve")
d.line([(389, 500), (478, 589), (641, 410)], fill="#b5f195", width=38, joint="curve")
for x, y in [(389, 500), (478, 589), (641, 410)]:
    d.ellipse((x-19, y-19, x+19, y+19), fill="#b5f195")
im.resize((256, 256), Image.Resampling.LANCZOS).save(out / "icon.png")
im.save(out / "icon.ico", sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
print("Created assets/icon.png and assets/icon.ico")
