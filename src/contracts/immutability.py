"""Utilitas pembekuan rekursif untuk kontrak data kanonis."""
from types import MappingProxyType
from typing import Any, Mapping


def freeze_value(val: Any) -> Any:
    """Ubah struktur data mutable bersarang menjadi tipe immutable secara rekursif.

    Konversi:
    - Mapping / dict -> MappingProxyType, semua value dibekukan rekursif.
    - list / tuple -> tuple, semua elemen dibekukan rekursif.
    - set / frozenset -> frozenset, semua elemen dibekukan rekursif.
    - Primitif dan objek yang sudah immutable dikembalikan apa adanya.

    Parameters
    ----------
    val : Any
        Nilai input yang akan dibekukan.

    Returns
    -------
    Any
        Representasi input yang immutable sampai ke dalam.
    """
    if isinstance(val, Mapping):
        return MappingProxyType({k: freeze_value(v) for k, v in val.items()})
    elif isinstance(val, (list, tuple)):
        return tuple(freeze_value(item) for item in val)
    elif isinstance(val, (set, frozenset)):
        return frozenset(freeze_value(item) for item in val)
    return val
