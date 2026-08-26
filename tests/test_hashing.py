import hashlib
import os

from netforensicai.core.evidence import HASH_CHUNK_SIZE, sha256_of_file


def test_sha256_matches_stdlib_for_small_file(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"hello world")

    assert sha256_of_file(file_path) == hashlib.sha256(b"hello world").hexdigest()


def test_sha256_matches_stdlib_across_multiple_chunks(tmp_path):
    data = os.urandom(HASH_CHUNK_SIZE + 12345)
    file_path = tmp_path / "big.bin"
    file_path.write_bytes(data)

    assert sha256_of_file(file_path) == hashlib.sha256(data).hexdigest()


def test_sha256_of_empty_file(tmp_path):
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")

    assert sha256_of_file(file_path) == hashlib.sha256(b"").hexdigest()


def test_sha256_changes_if_content_changes(tmp_path):
    file_path = tmp_path / "mutable.txt"
    file_path.write_bytes(b"version one")
    first = sha256_of_file(file_path)

    file_path.write_bytes(b"version two")
    second = sha256_of_file(file_path)

    assert first != second
