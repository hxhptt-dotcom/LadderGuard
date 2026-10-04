# 生成 LadderGuard 的 .ico 图标：圆角方块底 + 白色梯子，纯手写像素，无第三方依赖
import struct, sys

def rounded_mask(w, h, r):
    def inside(x, y):
        if x < r and y < r: return (x-r)**2 + (y-r)**2 <= r*r
        if x >= w-r and y < r: return (x-(w-1-r))**2 + (y-r)**2 <= r*r
        if x < r and y >= h-r: return (x-r)**2 + (y-(h-1-r))**2 <= r*r
        if x >= w-r and y >= h-r: return (x-(w-1-r))**2 + (y-(h-1-r))**2 <= r*r
        return True
    return inside

def draw(size, bg, fg):
    w = h = size
    px = [[None]*w for _ in range(h)]
    inside = rounded_mask(w, h, max(2, size//6))
    for y in range(h):
        for x in range(w):
            if inside(x, y):
                px[y][x] = bg
    sc = size / 32.0
    def rect(x0, y0, x1, y1):
        for y in range(int(y0*sc), int(y1*sc)):
            for x in range(int(x0*sc), int(x1*sc)):
                if 0 <= x < w and 0 <= y < h and px[y][x] is not None:
                    px[y][x] = fg
    # 梯子：两条竖轨 + 四级横档
    rect(9, 6, 12, 26)
    rect(20, 6, 23, 26)
    for yy in (8, 13, 18, 23):
        rect(9, yy, 23, yy + 2)
    # 转 BGRA 自底向上
    xor = b""
    for y in range(h-1, -1, -1):
        for x in range(w):
            r, g, b = px[y][x] if px[y][x] else (0, 0, 0)
            a = 255 if px[y][x] else 0
            xor += struct.pack("<BBBB", b, g, r, a)
    mask_row = ((w + 31) // 32) * 4
    andd = b"\x00" * (mask_row * h)
    bmp = struct.pack("<IiiHHIIiiII", 40, w, h*2, 1, 32, 0, w*h*4, 0, 0, 0, 0) + xor + andd
    return bmp

def make_ico(path, bg, fg):
    imgs = []
    for size in (16, 32, 48):
        imgs.append((size, draw(size, bg, fg)))
    out = struct.pack("<HHH", 0, 1, len(imgs))
    offset = 6 + 16 * len(imgs)
    entries = b""
    for size, bmp in imgs:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(bmp), offset)
        offset += len(bmp)
    with open(path, "wb") as f:
        f.write(out + entries + b"".join(b for _, b in imgs))
    print(path, "OK")

make_ico("icon_green.ico", (22, 163, 74), (255, 255, 255))
make_ico("icon_red.ico", (220, 38, 38), (255, 255, 255))
