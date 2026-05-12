"""Tests for project_98 core — Network ML Anomaly Detector."""

from __future__ import annotations

import json
from pathlib import Path

from project_98.core import (
    NetworkFlow,
    analyze_flows,
    detect_ddos,
    detect_port_scan,
    detect_volume_anomalies,
    load_flows,
    parse_csv,
    parse_jsonl,
)


def _flow(src="10.0.0.1", dst="10.0.0.2", sport=1024, dport=80,
          proto="tcp", byt=1000, pkts=10, dur=100, flags="", ts="") -> NetworkFlow:
    return NetworkFlow(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                       protocol=proto, bytes_total=byt, packets=pkts,
                       duration_ms=dur, flags=flags, timestamp=ts)


# ── NetworkFlow properties ────────────────────────────────────────────────────

class TestNetworkFlow:
    def test_bytes_per_packet(self) -> None:
        f = _flow(byt=1000, pkts=10)
        assert f.bytes_per_packet == 100.0

    def test_packets_per_second(self) -> None:
        f = _flow(pkts=100, dur=1000)
        assert abs(f.packets_per_second - 100.0) < 0.01

    def test_is_private_src(self) -> None:
        assert _flow(src="10.0.0.1").is_external_src is False
        assert _flow(src="8.8.8.8").is_external_src is True

    def test_is_private_dst(self) -> None:
        assert _flow(dst="192.168.1.1").is_external_dst is False
        assert _flow(dst="1.2.3.4").is_external_dst is True


# ── Parsers ───────────────────────────────────────────────────────────────────

class TestParseCSV:
    def test_parses_basic(self) -> None:
        csv = "src_ip,dst_ip,src_port,dst_port,protocol,bytes_total,packets,duration_ms\n"
        csv += "10.0.0.1,10.0.0.2,1024,80,tcp,1000,10,100\n"
        flows = parse_csv(csv)
        assert len(flows) == 1
        assert flows[0].src_ip == "10.0.0.1"

    def test_skips_invalid_rows(self) -> None:
        csv = "src_ip,dst_ip,src_port,dst_port,protocol,bytes_total,packets,duration_ms\n"
        csv += "bad,row,x,y,z,a,b,c\n"
        flows = parse_csv(csv)
        assert len(flows) == 0


class TestParseJSONL:
    def test_parses_basic(self) -> None:
        line = json.dumps({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 1024, "dst_port": 80, "protocol": "tcp",
            "bytes_total": 1000, "packets": 10, "duration_ms": 100,
        })
        flows = parse_jsonl(line)
        assert len(flows) == 1
        assert flows[0].dst_port == 80

    def test_ignores_blank_lines(self) -> None:
        assert parse_jsonl("") == []
        assert parse_jsonl("\n\n") == []


# ── Volume anomaly detection ──────────────────────────────────────────────────

class TestVolumeAnomalies:
    def _baseline(self, n: int = 50) -> list[NetworkFlow]:
        return [_flow(byt=1000 + i * 10) for i in range(n)]

    def test_normal_flows_no_anomaly(self) -> None:
        flows = self._baseline()
        anomalies = detect_volume_anomalies(flows, z_threshold=3.0)
        assert len(anomalies) == 0

    def test_giant_flow_detected(self) -> None:
        flows = [*self._baseline(), _flow(byt=500000)]
        anomalies = detect_volume_anomalies(flows, z_threshold=3.0)
        assert len(anomalies) >= 1
        assert anomalies[-1].anomaly_type == "VOLUME_ANOMALY"

    def test_anomaly_severity_high(self) -> None:
        flows = [*self._baseline(), _flow(byt=1000000)]
        anomalies = detect_volume_anomalies(flows, z_threshold=2.0)
        assert any(a.severity == "HIGH" for a in anomalies)


# ── Port scan detection ───────────────────────────────────────────────────────

class TestPortScan:
    def test_port_scan_detected(self) -> None:
        flows = [_flow(src="10.1.1.1", dport=p) for p in range(1, 30)]
        anomalies = detect_port_scan(flows, min_unique_ports=15)
        assert any(a.anomaly_type == "PORT_SCAN" for a in anomalies)
        assert any(a.src_ip == "10.1.1.1" for a in anomalies)

    def test_below_threshold_no_alert(self) -> None:
        flows = [_flow(src="10.1.1.1", dport=p) for p in range(1, 5)]
        anomalies = detect_port_scan(flows, min_unique_ports=15)
        assert len(anomalies) == 0

    def test_severity_critical(self) -> None:
        flows = [_flow(src="10.1.1.1", dport=p) for p in range(1, 30)]
        anomalies = detect_port_scan(flows, min_unique_ports=15)
        assert any(a.severity == "CRITICAL" for a in anomalies)


# ── DDoS detection ────────────────────────────────────────────────────────────

class TestDDoS:
    def test_ddos_detected(self) -> None:
        flows = [_flow(src=f"10.0.{i}.{i}", dst="10.0.0.1", dport=80) for i in range(25)]
        anomalies = detect_ddos(flows, min_unique_sources=20)
        assert any(a.anomaly_type == "DDOS" for a in anomalies)

    def test_below_threshold_no_alert(self) -> None:
        flows = [_flow(src=f"10.0.0.{i}", dst="10.0.0.1", dport=80) for i in range(5)]
        anomalies = detect_ddos(flows, min_unique_sources=20)
        assert len(anomalies) == 0


# ── analyze_flows ─────────────────────────────────────────────────────────────

class TestAnalyzeFlows:
    def test_empty_flows(self) -> None:
        report = analyze_flows([])
        assert report.flows_analyzed == 0
        assert len(report.anomalies) == 0

    def test_port_scan_in_full_report(self) -> None:
        flows = [_flow(src="10.1.1.1", dport=p) for p in range(1, 30)]
        report = analyze_flows(flows, port_scan_threshold=15)
        assert any(a.anomaly_type == "PORT_SCAN" for a in report.anomalies)

    def test_to_dict_structure(self) -> None:
        flows = [_flow(src="10.1.1.1", dport=p) for p in range(1, 30)]
        report = analyze_flows(flows, port_scan_threshold=15)
        d = report.to_dict()
        assert "anomalies" in d
        assert "total_anomalies" in d
        assert "by_type" in d


# ── load_flows ────────────────────────────────────────────────────────────────

class TestLoadFlows:
    def test_load_csv(self, tmp_path: Path) -> None:
        f = tmp_path / "flows.csv"
        f.write_text("src_ip,dst_ip,src_port,dst_port,protocol,bytes_total,packets,duration_ms\n"
                     "10.0.0.1,10.0.0.2,1024,80,tcp,1000,10,100\n")
        flows = load_flows(f)
        assert len(flows) == 1

    def test_load_jsonl(self, tmp_path: Path) -> None:
        f = tmp_path / "flows.jsonl"
        f.write_text(json.dumps({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                                 "src_port": 1024, "dst_port": 443, "protocol": "tcp",
                                 "bytes_total": 500, "packets": 5, "duration_ms": 50}) + "\n")
        flows = load_flows(f)
        assert len(flows) == 1
