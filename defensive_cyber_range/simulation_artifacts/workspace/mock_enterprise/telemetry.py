'''Observability & Telemetry Collector for the Mock Enterprise.

Provides OpenTelemetry-aligned trace spans, structured Loki-compatible JSON logs,
and Prometheus-formatted counter/gauge metrics export.
'''

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import uuid
from typing import Any


@dataclass
class TelemetryEvent:
    timestamp: str
    trace_id: str
    span_id: str
    service: str
    event_type: str
    endpoint: str
    actor: str
    status_code: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)


class TelemetryCollector:
    '''Collects structured logs, trace spans, and Prometheus metrics inside the cyber range.'''

    def __init__(self, service_name: str = "acme-enterprise-portal"):
        self.service_name = service_name
        self.events: list[TelemetryEvent] = []
        self.counters: dict[str, int] = {
            "http_requests_total": 0,
            "security_findings_detected_total": 0,
            "security_alerts_triggered_total": 0,
            "patches_deployed_total": 0,
            "patches_rolled_back_total": 0,
        }

    def record_request(
        self,
        endpoint: str,
        actor: str = "anonymous",
        status: int = 200,
        metadata: dict[str, Any] | None = None,
    ) -> TelemetryEvent:
        self.counters["http_requests_total"] += 1
        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            trace_id=uuid.uuid4().hex,
            span_id=uuid.uuid4().hex[:16],
            service=self.service_name,
            event_type="http_request",
            endpoint=endpoint,
            actor=actor,
            status_code=status,
            metadata=metadata or {},
        )
        self.events.append(event)
        return event

    def record_security_event(
        self,
        event_type: str,
        endpoint: str,
        metadata: dict[str, Any],
    ) -> TelemetryEvent:
        if event_type == "finding_detected":
            self.counters["security_findings_detected_total"] += 1
        elif event_type == "alert_triggered":
            self.counters["security_alerts_triggered_total"] += 1
        elif event_type == "patch_deployed":
            self.counters["patches_deployed_total"] += 1
        elif event_type == "patch_rollback":
            self.counters["patches_rolled_back_total"] += 1

        event = TelemetryEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            trace_id=uuid.uuid4().hex,
            span_id=uuid.uuid4().hex[:16],
            service=self.service_name,
            event_type=event_type,
            endpoint=endpoint,
            actor="cyber_range_swarm",
            status_code=200,
            metadata=metadata,
        )
        self.events.append(event)
        return event

    def export_prometheus_metrics(self) -> str:
        lines = []
        for metric_name, value in sorted(self.counters.items()):
            lines.append(f"# TYPE {metric_name} counter")
            lines.append(f'{metric_name}{{service="{self.service_name}"}} {value}')
        return "\n".join(lines) + "\n"
