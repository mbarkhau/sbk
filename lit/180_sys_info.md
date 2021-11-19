# System Information

The appropriate kdf parameters depend on the hardware available on the
system where sbk is running. To provide the best protection the
against a brute force attack, We want to use a substantial portion of
the available system memory.

To this end, the `sbk.sys_info` implements parsing and evaluation of
the usable memory of the users system.


## Module: `sbk.sys_info`

```python
# file: src/sbk/sys_info.py
# include: common.boilerplate
# dep: common.imports, imports, common.constants, constants*, impl*, main
```

```bash
# run: bash scripts/lint.sh src/sbk/sys_info.py
# exit: 0
```

```python
# def: imports
from . import kdf
from . import parameters
```


### Module Main and Selftest

We start with a selftest function to illustrate and exercise teh
system information we will be gathering.

```python
# def: main
def main() -> int:
    # xinclude: common.debug_logging
    print("lang: ", detect_lang())
    print("Mem Info:", memory_info())
    print("Memory Info (uncached):", _init_sys_info())
    print("Memory Info (cached)  :", load_sys_info())
    return 0

if __name__ == '__main__':
    main()
```

```bash
# run: python -m sbk.sys_info
# timeout: 90
lang:  en
Mem Info: (15886, 12557)
Memory Info (uncached): SystemInfo(total_mb=15886, usable_mb=9417)
Memory Info (cached)  : SystemInfo(total_mb=15886, usable_mb=9417)
# exit: 0
```


## Language Detection

SBK currently only supports English. It is unlikely we will support
region specific languages such as `en_US`, `en_GB`, `en_AU`, only
`en`. In the future we want to enable translation when available and
this detection is just in preparation for that.

Furthermore, if non-phonetic scripts are ever to be supported, the
whole concept of edit distance to match words of a language specific
wordlist will have to be reconsidered.

```python
# def: constants_lang
DEFAULT_LANG = ct.LangCode('en')
SUPPORTED_LANGUAGES = {'en'}

# PR welcome
# SUPPORTED_LANGUAGES |= {'es', 'pt', 'ru', 'fr', de', 'it', 'tr'}
#
# non-phonetic systems may be a design issue for wordlists
# SUPPORTED_LANGUAGES |= {'ar', 'ko', 'cn', 'jp'}

KB_LAYOUT_TO_LANG = {'us': 'en'}
```

```python
# def: impl_detect_lang
def detect_lang() -> ct.LangCode:
    try:
        localectl_output = sp.check_output("localectl").decode("utf-8")
        lang = _parse_lang(localectl_output)
        kb_lang = _parse_keyboard_lang(localectl_output)
        return lang or kb_lang or DEFAULT_LANG
    except Exception:
        logger.warning("Fallback to default lang: en", exc_info=True)
        return ct.LangCode('en')
```

```python
# def: impl_parse_lang
def _parse_lang(localectl_output: str) -> Optional[ct.LangCode]:
    lang_match = re.search(r"LANG=([a-z]+)", localectl_output)
    if lang_match:
        lang = lang_match.group(1)
        logger.debug(f"lang: {lang}")
        if lang in SUPPORTED_LANGUAGES:
            return ct.LangCode(lang)
    return None
```

```python
# def: impl_parse_keyboard_lang
def _parse_keyboard_lang(localectl_output: str) -> Optional[ct.LangCode]:
    keyboard_match = re.search(r"X11 Layout: ([a-z]+)", localectl_output)
    if keyboard_match:
        layout = keyboard_match.group(1)
        logger.debug(f"keyboard: {layout}")
        if layout in KB_LAYOUT_TO_LANG:
            return ct.LangCode(KB_LAYOUT_TO_LANG[layout])
    return None
```


## Memory Detection

```python
# def: constants
# Fallback value for systems on which total memory cannot be detected
FALLBACK_MEM_MB = int(os.getenv("SBK_FALLBACK_MEM_MB", "1024"))

# cache so we don't have to check usable memory every time
SYSINFO_CACHE_FPATH = SBK_APP_DIR / "sys_info_measurements.json"
```

```python
# def: impl_type_sysinfo
class SystemInfo(NamedTuple):
    total_mb : ct.MebiBytes
    usable_mb: ct.MebiBytes
```

While `/proc/meminfo` is Linux specific, this is the only OS we really
care about anyway.

```python
# def: impl_parse_meminfo
def _parse_meminfo(meminfo_text: str) -> Tuple[ct.MebiBytes, ct.MebiBytes]:
    total_mb = FALLBACK_MEM_MB
    avail_mb = FALLBACK_MEM_MB

    for line in meminfo_text.splitlines():
        if line.startswith("Mem"):
            key, num, unit = line.strip().split()
            if key == "MemTotal:":
                assert unit == "kB"
                total_mb = int(num) // 1024
            elif key == "MemAvailable:":
                assert unit == "kB"
                avail_mb = int(num) // 1024
    return (total_mb, avail_mb)


def memory_info() -> Tuple[ct.MebiBytes, ct.MebiBytes]:
    meminfo_path = pl.Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            with meminfo_path.open(mode="r", encoding="utf-8") as fobj:
                return _parse_meminfo(fobj.read())
        except Exception:
            logger.warning("Error while evaluating system memory", exc_info=True)
    return (FALLBACK_MEM_MB, FALLBACK_MEM_MB)
```

We could use a binary search approach to determine how much memory we
can use, but there is a tradeoff with usability here. We don't want
the memory check take too long, so we start with what the system tells
us we can use and then only reduce that if there are are any issues.

```python
# def: impl_init_sys_info
def _init_sys_info() -> SystemInfo:
    total_mb, avail_mb = memory_info()

    check_mb = avail_mb
    while check_mb > 100:
        logger.debug(f"testing check_mb={check_mb}")
        if _is_usable_kdf_m(check_mb):
            break
        else:
            check_mb = int(check_mb * 0.75)     # try a bit less

    usable_mb = max(check_mb, 100)
    nfo = SystemInfo(total_mb, usable_mb)
    _dump_sys_info(nfo)
    return nfo
```

Our measurement function invokes a subprocess, as the argon2-cffi will
kill the process it's running on if too high a value is specified for
memory. I am not aware of a more elegant way to determine the maxiumum
memory we can use.

```python
# def: impl_measure
def _is_usable_kdf_m(memory_mb: ct.MebiBytes) -> bool:
    retcode = sp.call([sys.executable, "-m", "sbk.kdf", str(memory_mb)])
    return retcode == 0
```


## SysInfo Caching

It can take a few seconds to measure how much memory we can use for
the kdf, but that information won't change from one run to the next.
It's worthwhile to cache this information for later use.

The primary public function `load_sys_info` encapsulates the high
level caching logic, both within the current process (using
`_SYS_INFO_KW`) and on disk.

```python
# def: impl_load_sys_info
def load_sys_info(use_cache: bool = True) -> SystemInfo:
    if use_cache:
        cache_path = SYSINFO_CACHE_FPATH
        if not _SYS_INFO_KW and cache_path.exists():
            try:
                with cache_path.open(mode="rb") as fobj:
                    _SYS_INFO_KW.update(json.load(fobj))
            except Exception as ex:
                logger.warning(f"Error reading cache file {cache_path}: {ex}")

        if _SYS_INFO_KW:
            return SystemInfo(
                total_mb=_SYS_INFO_KW['total_mb'],
                usable_mb=_SYS_INFO_KW['usable_mb'],
            )

    return _init_sys_info()
```

The serialization logic writes a file in `SBK_APP_DIR` which may be
loaded the next time sbk is run. The cache file is always updated
whenever the memory info is evaluated (which typically should only
happen once).

```python
# def: impl_sys_info_dump_cache
_SYS_INFO_KW: Dict[str, int] = {}

def _dump_sys_info(sys_info: SystemInfo) -> None:
    _SYS_INFO_KW.update({
        'total_mb' : sys_info.total_mb,
        'usable_mb': sys_info.usable_mb,
    })

    cache_path = SYSINFO_CACHE_FPATH
    try:
        cache_path.parent.mkdir(exist_ok=True, parents=True)
    except Exception as ex:
        logger.warning(f"Unable to create cache dir {cache_path.parent}: {ex}")
        return

    try:
        with cache_path.open(mode="w", encoding="utf-8") as fobj:
            json.dump(_SYS_INFO_KW, fobj, indent=4)
    except Exception as ex:
        logger.warning(f"Error writing cache file {cache_path}: {ex}")
```
