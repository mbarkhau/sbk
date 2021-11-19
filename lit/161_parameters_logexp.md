## Parameter Range and Encoding

For the remaining parameters `-m` and `-t`, we do want to encode them
in the salt, as memory availability is widely variable and the number
of iterations is the most straight forward way for users to trade off
protection vs how long they are willing to wait when they access their
wallet.

For `-m` we don't want to support low end hardware, as we expect to
run on PC hardware starting with the x64 generation of multi-core
CPUs. We would like to use a substantial portion of the available
memory of systems starting from 1GB.

We chose an encoding where we cover a range that is large in magnitude
rather than precision, which means that key derivation will use a
lower value for `-m` than might exhaust a systems memory and a higher
value for `-t` than would correspond exactly to how long the user
chose as their preference to wait.

The general principle of encoding is to chose a base `b` for each
parameter such that integer `n` encoded in 6bits covers our desired
range for each parameter. We have `n` during decoding and our
function `d(n: int) -> float`:

```math
d(n) = p
\space\space | \space
p > 1,
p \in \Reals
```

Which should satisfy

```math
\begin{align}
d(0) &= 1 \\
d(1) &> 1 \\
d(n) &\approx b^n \\
⌈ d(n) ⌉
&\ne
⌈ d(n+1) ⌉ \\
\end{align}
```

To satisfy $`(4)`$ we can scale $`b^n`$ by a factor $`s`$ and then
pull the curve down with an offset $`o`$ so we satisfy $`(1)`$. We
first derive $`s`$ from our constraints and then we have $`o = 1 - s`$.

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
    s = int(1 / (b - 1))
    o = int(1 - s)

    v0 = b ** 0 * s + o
    v1 = b ** 1 * s + o
    assert v0 == 1
    assert 1.5 < v1 < 2.5
    return (s, o)
```


## `param_exp` and `param_log`

In the context of the `kdf` module, for a given base, we will use
`param_exp` to convert `n -> v` and `param_log` to convert `v -> n`, where
`v` is the value for a parameter `-m` or `-t`.

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
# dep: impl_log_and_exp
import terminaltables as tt

for b in [1+1/10, 1+1/8]:
    s, o = param_coeffs(b)
    print(f"{b=:.3f} {s=:.3f} {o=:.3f}")

    data = [["n"], ["log(exp(n))"], ["exp(n)"]]
    for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 61, 62, 63]:
        e = param_exp(n, b)
        l = param_log(e, b)
        data[0].append(n)
        data[1].append(l)
        data[2].append(e)
    table = tt.AsciiTable(data)
    table.inner_heading_row_border = False
    print(table.table)
```

```python
# out
b=1.100 s=9.000 o=-8.000
+-------------+---+---+---+---+---+---+---+----+----+------+------+------+
| n           | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7  | 8  | 61   | 62   | 63   |
| log(exp(n)) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7  | 8  | 61   | 62   | 63   |
| exp(n)      | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 10 | 11 | 3006 | 3308 | 3639 |
+-------------+---+---+---+---+---+---+---+----+----+------+------+------+
b=1.125 s=8.000 o=-7.000
+-------------+---+---+---+---+---+---+---+----+----+-------+-------+-------+
| n           | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7  | 8  | 61    | 62    | 63    |
| log(exp(n)) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7  | 8  | 61    | 62    | 63    |
| exp(n)      | 1 | 2 | 3 | 4 | 6 | 7 | 9 | 11 | 14 | 10546 | 11866 | 13350 |
+-------------+---+---+---+---+---+---+---+----+----+-------+-------+-------+
# exit: 0
```

With different choices for $`b`$ we can now trade off precision vs
magnitude. With a base of 11/10 we can have a magnitude of 4000x of
our lowest value, where each increment is roughly 1/10 larger than
the previous.


```python
# exec
# dep: impl_log_and_exp
for b in [17/16, 11/10, 9/8, 6/5, 5/4]:
    s, o = param_coeffs(b)
    maxval = round(b**63 * s + o)
    print(f"{b=:.3f} {s=:<2} {o=:<3} {maxval=}")
```

```python
# out
b=1.062 s=16 o=-15 maxval=714
b=1.100 s=9  o=-8  maxval=3639
b=1.125 s=8  o=-7  maxval=13350
b=1.200 s=5  o=-4  maxval=486839
b=1.250 s=4  o=-3  maxval=5097891
# exit: 0
```
