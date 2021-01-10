from math import ceil, floor

denum = 8
bases = [1 + n / denum for n in range(1, denum)]


targets = [
    (4, 64),
    (6, 1_000_000),
]

for bits, target in targets:
    for base in bases:
        scale_0 = floor(target / base ** (2**bits - 1))
        scales = {
            int(scale_0 * 1.5),
            int(scale_0 * 1.375),
            int(scale_0 * 1.25),
            int(scale_0 * 1.125),
            int(scale_0 * 1.0),
        }
        for scale in scales:
            if scale < 1:
                continue
            if scale > 100:
                scale = round(scale / 100) * 100
            offset = 1 - base ** 0 * scale
            vals = [floor(offset + scale * base**n) for n in range(2**bits)]
            if len(vals) != len(set(vals)):
                continue
            str_vals = " ".join(str(v).rjust(4) for v in vals[:12])
            str_vals += " " + " ".join(str(v).rjust(7) for v in vals[-bits:])
            print(f"base=1 + {int(base*denum-denum)}/{denum}  scale={scale:9.3f}  offset={offset:9.2f} vals={str_vals}")
    print()
