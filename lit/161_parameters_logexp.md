## Parameter Range and Encoding

The remaining parameters `-m` and `-t` must be encoded in the
brainkey. Memory availability is widely variable and the number
of iterations is the most straight forward way for users to trade
off protection vs the time they are willing to wait when they
access their wallet.

For `-m` we don't want to support PC hardware starting with the
x64 generation of multi-core CPUs. We would like to use a
substantial portion of the available memory of systems starting
from 2GB.

We chose an encoding where we cover a range that is large in
magnitude rather than precision, which means that key derivation
will use a lower value for `-m` than might exhaust a systems
memory and a higher value for `-t` than would correspond exactly
to how long the user chose as their preference to wait.

The general principle of encoding is to chose a base ``b`` for
each parameter such that an integer ``v`` can be encoded in 3bits
as ``n``. We have ``n`` during decoding and our function `` d(n:
int) -> float `` produces ``v`` for a given base ``b``:

```math
d(n, b) = v
\space\space | \space
v > 1,
v \in \Reals
```

The function ``d`` should satisfy the following constraints.

```math
\begin{align}
d(0, b) &= 1 \\
d(1, b) &> 1 \\
d(n, b) &\approx b^n \\
⌈ d(n, b) ⌉
&\ne
⌈ d(n+1, b) ⌉ \\
\end{align}
```

To satisfy $`(4)`$ we can scale $`b^n`$ by a
factor $`s`$ and then pull the curve down with an
offset $`o`$ so we satisfy $`(1)`$. We first
derive $`s`$ from our constraints and then we have
$`o = 1 - s`$.

```math
\begin{align}
g(0)     &= g(1) - 1       \\
g(0)     &= s b^0          \\
g(0)     &= s              \\
g(1)     &= s b            \\
g(0) + 1 &= g(1)           \\
   s + 1 &= s b            \\
       1 &= s b - s        \\
       1 &= s (b - 1)      \\
       s &= 1 / (b - 1)    \\
\end{align}
```

```python
# def: param_coeffs
# dep: common.typing
def param_coeffs(b: float) -> Tuple[int, int]:
    assert b > 1
    s = 1 / (b - 1)
    o = 1 - s

    v0 = b ** 0 * s + o
    v1 = b ** 1 * s + o
    assert v0 == 1
    assert 1.5 < v1 < 2.5
    return (s, o)
```


## `param_exp` and `param_log`

In the context of the ``kdf`` module, for a given base, we will use
`param_exp` to convert ``n -> v`` and `param_log` to convert ``v -> n``,
where `v` is the value for a parameter `-m` or `-t`.

```math
\begin{align}
\mathit{param\_exp}(n, b) &= ⌊ o + s × b^n ⌉
\newline
\mathit{param\_log}(v, b) &= ⌊ \log_{b} ( \frac{v - o}{s} ) ⌉
\end{align}
```

```python
# def: impl_log_and_exp
# dep: param_coeffs
from math import log

def param_exp(n: int, b: float) -> int:
    s, o = param_coeffs(b)
    v = round(b ** n * s + o)
    return v

def param_log(v: int, b: float) -> int:
    s, o = param_coeffs(b)
    n = log((v - o) / s) / log(b)
    return min(max(round(n), 0), 2**63)
```


### Evaluate `param_exp` and  `param_log`

```python
# exec
# dep: common.imports, constant*, impl_log_and_exp
import terminaltables as tt

for b in [V0_KDF_M_BASE, V0_KDF_T_BASE]:
    s, o = param_coeffs(b)

    data = [["n"], ["log(exp(n))"], ["exp(n)"]]
    for n0 in [0, 1, 2, 3, 4, 5, 6, 7]:
        v = param_exp(n0, b)
        n1 = param_log(v, b)
        assert n0 == n1
        data[0].append(n0)
        data[1].append(n1)
        data[2].append(v)
    table = tt.AsciiTable(data)
    table.inner_heading_row_border = False
    print(table.table)
```

```python
# out
+-------------+---+---+---+---+---+----+----+----+
| n           | 0 | 1 | 2 | 3 | 4 | 5  | 6  | 7  |
| log(exp(n)) | 0 | 1 | 2 | 3 | 4 | 5  | 6  | 7  |
| exp(n)      | 1 | 2 | 4 | 6 | 9 | 14 | 22 | 33 |
+-------------+---+---+---+---+---+----+----+----+
+-------------+---+---+---+----+----+-----+------+------+
| n           | 0 | 1 | 2 | 3  | 4  | 5   | 6    | 7    |
| log(exp(n)) | 0 | 1 | 2 | 3  | 4  | 5   | 6    | 7    |
| exp(n)      | 1 | 2 | 6 | 22 | 86 | 342 | 1366 | 5462 |
+-------------+---+---+---+----+----+-----+------+------+
# exit: 0
```

With different choices for $`b`$ we can now trade
off precision vs magnitude. With a base of 11/10
we can have a magnitude of 4000x of our lowest
value, where each increment is roughly 1/10 larger
than the previous.


```python
# exec
# dep: impl_log_and_exp
for b in [11/10, 9/8, 6/5, 5/4, 1.5, 2.0, 3.0, 4.0]:
    s, o = param_coeffs(b)
    vals = [round(b**n * s + o) for n in range(8)]
    print(f"{b=:.3f} {s=:6.3f} {o=:6.3f} {vals=}")
```

```python
# out
b=1.100 s=10.000 o=-9.000 vals=[1, 2, 3, 4, 6, 7, 9, 10]
b=1.125 s= 8.000 o=-7.000 vals=[1, 2, 3, 4, 6, 7, 9, 11]
b=1.200 s= 5.000 o=-4.000 vals=[1, 2, 3, 5, 6, 8, 11, 14]
b=1.250 s= 4.000 o=-3.000 vals=[1, 2, 3, 5, 7, 9, 12, 16]
b=1.500 s= 2.000 o=-1.000 vals=[1, 2, 4, 6, 9, 14, 22, 33]
b=2.000 s= 1.000 o= 0.000 vals=[1, 2, 4, 8, 16, 32, 64, 128]
b=3.000 s= 0.500 o= 0.500 vals=[1, 2, 5, 14, 41, 122, 365, 1094]
b=4.000 s= 0.333 o= 0.667 vals=[1, 2, 6, 22, 86, 342, 1366, 5462]
# exit: 0
```
