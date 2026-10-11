import pytest

from osint_tool.target import InvalidTarget, normalize_domain


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Ejemplo.COM", "ejemplo.com"),
        ("https://ejemplo.com/ruta?x=1", "ejemplo.com"),
        ("sub.ejemplo.com.", "sub.ejemplo.com"),
        ("https://user:pw@Ejemplo.com:8443/a?b=1#c", "ejemplo.com"),
        ("ejemplo.com:8080", "ejemplo.com"),
    ],
)
def test_normalize(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-bad.com", "a b.com", "192.0.2.1"])
def test_invalid(raw):
    with pytest.raises(InvalidTarget):
        normalize_domain(raw)
