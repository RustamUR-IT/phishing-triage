from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def sample_bytes():
    return lambda name: (SAMPLES / name).read_bytes()


@pytest.fixture
def parse():
    def _parse(text: str | bytes):
        raw = text.encode() if isinstance(text, str) else text
        return BytesParser(policy=policy.default).parsebytes(raw)

    return _parse
