import pytest
from backend.app.analyzers.pcap_reader import read_pcap_file


def test_pcap_reader_missing_file():
    with pytest.raises(FileNotFoundError):
        read_pcap_file("data/pcaps/nonexistent.pcap")


def test_pcap_reader_synthetic_fixture():
    packets, metadata, warnings = read_pcap_file("data/pcaps/synthetic/SYNTH-TEST-001.pcap")
    assert len(packets) == 11
    assert metadata["file_name"] == "SYNTH-TEST-001.pcap"
    assert metadata["file_size_bytes"] > 0
    assert metadata["packet_count"] == 11
    assert isinstance(warnings, list)
