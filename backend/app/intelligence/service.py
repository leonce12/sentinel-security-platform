"""Threat intelligence service: local dataset first, optional external lookups, with caching."""

import ipaddress
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError
from app.intelligence.providers import LookupResult, VirusTotalProvider
from app.models import ThreatIndicator, ThreatLookup, User
from app.services import app_settings, audit

LOCAL_LIMITATIONS = ("Local dataset entries are only as accurate as their source and date. A match is context "
                     "for investigation, not proof of malicious activity.")

_provider_override = None  # tests inject a provider here


def get_external_provider() -> VirusTotalProvider:
    if _provider_override is not None:
        return _provider_override
    settings = get_settings()
    return VirusTotalProvider(settings.virustotal_api_key, timeout=settings.external_timeout_seconds)


def set_provider_override(provider) -> None:
    global _provider_override
    _provider_override = provider


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise AppError("Enter a valid IPv4 or IPv6 address", 422, "validation_error") from exc


def is_public(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return address.is_global


def local_lookup(db: Session, ip: str) -> LookupResult:
    matches = db.query(ThreatIndicator).filter(ThreatIndicator.indicator == ip).all()
    if not matches:
        return LookupResult("local", "no_information", details={"reason": "Not in the local dataset"},
                            limitations=LOCAL_LIMITATIONS)
    worst = max(matches, key=lambda m: (m.verdict == "malicious", m.confidence))
    return LookupResult("local", worst.verdict, worst.confidence,
                        details={"entries": [{"source": m.source, "verdict": m.verdict, "confidence": m.confidence,
                                              "description": m.description, "added_at": m.added_at.isoformat(),
                                              "synthetic": m.is_synthetic} for m in matches]},
                        limitations=LOCAL_LIMITATIONS)


def lookup(db: Session, raw_ip: str, actor: User, use_external: bool = True) -> list[ThreatLookup]:
    """Check one IP against every available source. Returns one stored lookup per provider."""
    ip = validate_ip(raw_ip)
    now = datetime.now(UTC)
    results: list[ThreatLookup] = []

    local = local_lookup(db, ip)
    results.append(_store(db, ip, local, actor, expires=None))

    external_enabled = app_settings.get(db, "external_intel_enabled")
    provider = get_external_provider()
    if not use_external:
        pass
    elif not external_enabled:
        results.append(_unstored("virustotal", ip, "unavailable",
                                 {"reason": "External lookups are disabled in Settings"}))
    elif not provider.configured:
        results.append(_unstored("virustotal", ip, "unavailable", {"reason": "No VirusTotal API key configured"}))
    elif not is_public(ip):
        results.append(_unstored("virustotal", ip, "no_information",
                                 {"reason": "Private or reserved address; not sent to external services"}))
    else:
        cache_hours = app_settings.get(db, "intel_cache_hours")
        cached = (db.query(ThreatLookup)
                  .filter(ThreatLookup.indicator == ip, ThreatLookup.provider == provider.name,
                          ThreatLookup.expires_at.is_not(None), ThreatLookup.expires_at > now)
                  .order_by(ThreatLookup.looked_up_at.desc()).first())
        if cached:
            cached.details = {**cached.details, "cached": True}
            results.append(cached)
        else:
            result = provider.lookup(ip)
            expires = now + timedelta(hours=cache_hours) if result.cacheable else None
            results.append(_store(db, ip, result, actor, expires=expires))
    audit.record(db, "intel.lookup", actor=actor, object_type="indicator", object_id=ip,
                 details={"verdicts": {r.provider: r.verdict for r in results}})
    db.commit()
    return results


def _store(db: Session, ip: str, result: LookupResult, actor: User | None, expires) -> ThreatLookup:
    row = ThreatLookup(indicator=ip, provider=result.provider, verdict=result.verdict, confidence=result.confidence,
                       details=result.details, limitations=result.limitations, expires_at=expires,
                       requested_by_id=actor.id if actor else None)
    db.add(row)
    db.flush()
    return row


def _unstored(provider: str, ip: str, verdict: str, details: dict) -> ThreatLookup:
    return ThreatLookup(id=0, indicator=ip, provider=provider, verdict=verdict, confidence=None, details=details,
                        limitations="", looked_up_at=datetime.now(UTC), expires_at=None)


def reputation_map(db: Session) -> dict[str, dict]:
    """ip -> strongest negative verdict, from the local dataset and unexpired external lookups.

    Used by the detection engine and risk scoring. Only malicious and suspicious verdicts are
    included: absence from the map means "no negative information", never "safe".
    """
    now = datetime.now(UTC)
    rank = {"malicious": 2, "suspicious": 1}
    out: dict[str, dict] = {}

    def offer(ip, verdict, source, confidence):
        if verdict not in rank:
            return
        current = out.get(ip)
        if current is None or rank[verdict] > rank[current["verdict"]]:
            out[ip] = {"verdict": verdict, "source": source, "confidence": confidence}

    for row in db.query(ThreatIndicator).filter(ThreatIndicator.indicator_type == "ip"):
        offer(row.indicator, row.verdict, f"local dataset ({row.source})", row.confidence)
    for row in db.query(ThreatLookup).filter(ThreatLookup.provider != "local", ThreatLookup.expires_at > now):
        offer(row.indicator, row.verdict, row.provider, row.confidence)
    return out
