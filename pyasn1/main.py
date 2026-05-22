import sys
import base64
import io
import contextlib
import argparse


@contextlib.contextmanager
def _suppress_stdout():
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = old


with _suppress_stdout():
    from myasn1.cmp_comp import PKIXCMP_2023

PKIMessage = PKIXCMP_2023.PKIMessage


# ---------------------------------------------------------------------------
# PEM helpers
# ---------------------------------------------------------------------------

def load_pem_der(path: str) -> bytes:
    with open(path, 'rb') as f:
        data = f.read()
    if data.lstrip().startswith(b'-----'):
        lines = data.decode('ascii').splitlines()
        b64 = ''.join(line for line in lines if not line.startswith('-----'))
        return base64.b64decode(b64)
    return data


# ---------------------------------------------------------------------------
# Hex-annotated renderer
# ---------------------------------------------------------------------------

def _fmt_hex(data: bytes) -> str:
    h = data.hex().upper()
    return ' '.join(h[i:i+2] for i in range(0, len(h), 2))


def _try_hex(obj) -> str:
    try:
        return _fmt_hex(obj.to_der())
    except Exception:
        return '??'


def _render_obj(obj, val) -> str:
    """Return a (possibly multi-line) string for *obj* with value *val*.
    The hex DER encoding is appended as an ASN.1 comment on the first line."""
    obj._val = val
    hex_str = _try_hex(obj)
    cls = type(obj).__name__

    if cls in ('SEQ', 'SET'):
        return _render_seq(obj, val, hex_str)
    elif cls == 'CHOICE':
        return _render_choice(obj, val, hex_str)
    elif cls in ('SEQ_OF', 'SET_OF'):
        return _render_seqof(obj, val, hex_str)
    else:
        # Primitive (INT, OID, BIT_STR, OCT_STR, UTF8String, …)
        return f'{obj._to_asn1()}  -- hex: {hex_str} --'


def _render_seq(obj, val, hex_str) -> str:
    if not val:
        return f'{{ }}  -- hex: {hex_str} --'
    parts = []
    for ident in obj._cont:
        if ident not in val:
            continue
        child = obj._cont[ident]
        _par = child._parent
        child._parent = obj
        rendered = _render_obj(child, val[ident])
        child._parent = _par
        # indent continuation lines by 2 spaces
        indented = rendered.replace('\n', '\n  ')
        parts.append(f'  {ident} {indented},\n')
    if parts:
        parts[-1] = parts[-1][:-2]  # drop trailing ',\n' on the last field
    return f'{{  -- hex: {hex_str} --\n' + ''.join(parts) + '\n}'


def _render_choice(obj, val, hex_str) -> str:
    ident, inner_val = val
    if ident not in obj._cont:
        # raw / unknown alternative
        raw = inner_val.hex().upper() if isinstance(inner_val, (bytes, bytearray)) else str(inner_val)
        return f"{ident} : '{raw}'H  -- hex: {hex_str} --"
    child = obj._cont[ident]
    _par = child._parent
    child._parent = obj
    rendered = _render_obj(child, inner_val)
    child._parent = _par
    # CHOICE in DER has no wrapper tag: its hex == the selected alternative's hex.
    # The child already carries its own hex comment on the first line, so we just prefix.
    return f'{ident} : {rendered}'


def _render_seqof(obj, val, hex_str) -> str:
    if not val:
        return f'{{ }}  -- hex: {hex_str} --'
    parts = []
    _par = obj._cont._parent
    obj._cont._parent = obj
    for item_val in val:
        rendered = _render_obj(obj._cont, item_val)
        indented = rendered.replace('\n', '\n  ')
        parts.append(f'  {indented},\n')
    obj._cont._parent = _par
    if parts:
        parts[-1] = parts[-1][:-2]
    return f'{{  -- hex: {hex_str} --\n' + ''.join(parts) + '\n}'


def to_asn1_hex(obj) -> str:
    """Top-level entry point: render *obj* (already decoded) with hex annotations."""
    return _render_obj(obj, obj._val)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Decode a CMP DER or PEM file using the generated PKIXCMP module.'
    )
    parser.add_argument('input', help='Path to the DER or PEM file to decode')
    parser.add_argument(
        '--hex',
        action='store_true',
        help='Include DER hex annotations in the rendered ASN.1 output',
    )
    return parser.parse_args()

def main():
    args = parse_args()

    der = load_pem_der(args.input)

    with _suppress_stdout():
        PKIMessage.from_der(der)

    if args.hex:
        print(to_asn1_hex(PKIMessage))
    else:
        print(PKIMessage.to_asn1())


if __name__ == '__main__':
    main()
