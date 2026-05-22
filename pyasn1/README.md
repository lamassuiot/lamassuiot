# pyasn1 tooling

This directory contains a small Python entrypoint, [main.py](main.py), plus generated ASN.1 Python code under [myasn1](myasn1).

## Why `pycrate_asn1rt` is missing

The generated file [myasn1/cmp_comp.py](myasn1/cmp_comp.py) was produced by `pycrate_asn1c` and imports the `pycrate_asn1rt` runtime package:

```python
from pycrate_asn1rt.utils import *
```

If you run:

```bash
python3 pyasn1/main.py cmp.ir
```

without installing `pycrate`, Python raises:

```text
ModuleNotFoundError: No module named 'pycrate_asn1rt'
```

## Local setup

Create and activate a virtual environment, then install `pycrate`:

```bash
cd pyasn1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pycrate
```

After that, run the script from the repository root with the virtualenv interpreter:

```bash
./pyasn1/.venv/bin/python pyasn1/main.py cmp.ir
```

Or, if you are already inside `pyasn1` with the virtualenv activated:

```bash
python main.py ../cmp.ir
```

The script requires an explicit input file path. It accepts either DER or PEM input.

To include DER hex annotations in the output:

```bash
./pyasn1/.venv/bin/python pyasn1/main.py --hex cmp.ir
```

## Notes

- The browser demo in [index.html](index.html) also installs `pycrate` before loading the generated CMP module.
- The repo-local Claude settings reference a dedicated Python environment for this tooling as well.
- If you regenerate [myasn1/cmp_comp.py](myasn1/cmp_comp.py), keep `pycrate` installed because the generated code depends on its runtime modules.