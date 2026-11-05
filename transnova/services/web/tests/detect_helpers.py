"""Shared helpers for detection tests."""

from fastapi.testclient import TestClient

from web_decoy.app import create_app
from web_decoy.detection.behavior import BehaviorEngine
from web_decoy.detection.signatures import detect_signatures
from .conftest import read_events


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def app_with_clock(settings, clock):
    app = create_app(settings)
    app.state.detectors = [detect_signatures, BehaviorEngine(clock=clock).detect]
    return app


def client_for(app, ip="203.0.113.10"):
    return TestClient(app, client=(ip, 40000), follow_redirects=False)


def dets(event):
    return event["raw_evidence_redacted"]["detections"]


def rules(event):
    return {d["rule"] for d in dets(event)}


def by_rule(event, rule):
    return next(d for d in dets(event) if d["rule"] == rule)


def last(settings):
    return read_events(settings)[-1]


def all_rules(settings):
    return [rules(e) for e in read_events(settings)]
