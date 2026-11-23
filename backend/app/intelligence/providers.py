"""Threat intelligence providers.

Verdicts are deliberately conservative:
  malicious      a source reports the indicator as malicious
  suspicious     a source reports it as suspicious
  no_detections  a source knows the indicator and reports no detections. This is NOT
                 a statement that the IP is safe.
  no_information the source has no data about the indicator
  unavailable    the source could not be queried (offline, rate limited, not configured)
"""

from dataclasses import dataclass, field

import httpx

VERDICTS = ("malicious", "suspicious", "no_detections", "no_information", "unavailable")


@dataclass
class LookupResult:
    provider: str
    verdict: str
    confidence: float | None = None
    details: dict = field(default_factory=dict)
    limitations: str = ""
    cacheable: bool = True


class VirusTotalProvider:
    """VirusTotal v3 IP address report. Only the IP address itself is sent."""

    name = "virustotal"
    url = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    limitations = ("Counts reflect how many security vendors flag the address. Vendors disagree, lists go stale "
                   "and shared or cloud addresses change owners. Treat as context only.")

    def __init__(self, api_key: str | None, timeout: float = 10.0, transport: httpx.BaseTransport | None = None):
        self.api_key = api_key
        self.timeout = timeout
        self.transport = transport  # injected in tests so no real network call is made

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def lookup(self, ip: str) -> LookupResult:
        if not self.configured:
            return LookupResult(self.name, "unavailable", details={"reason": "No API key configured"},
                                limitations="External lookups are not configured.", cacheable=False)
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.get(self.url.format(ip=ip), headers={"x-apikey": self.api_key})
        except httpx.HTTPError as exc:
            return LookupResult(self.name, "unavailable", details={"reason": f"Service unreachable ({type(exc).__name__})"},
                                limitations=self.limitations, cacheable=False)
        if response.status_code == 404:
            return LookupResult(self.name, "no_information", details={"reason": "Not found in VirusTotal"},
                                limitations=self.limitations)
        if response.status_code == 429:
            return LookupResult(self.name, "unavailable", details={"reason": "Rate limit reached; try again later"},
                                limitations=self.limitations, cacheable=False)
        if response.status_code in (401, 403):
            return LookupResult(self.name, "unavailable", details={"reason": "API key rejected"},
                                limitations=self.limitations, cacheable=False)
        if response.status_code != 200:
            return LookupResult(self.name, "unavailable", details={"reason": f"Unexpected status {response.status_code}"},
                                limitations=self.limitations, cacheable=False)
        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
        except (ValueError, KeyError, TypeError):
            return LookupResult(self.name, "unavailable", details={"reason": "Unexpected response format"},
                                limitations=self.limitations, cacheable=False)
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int)) or None
        if malicious >= 3:
            verdict = "malicious"
        elif malicious > 0 or suspicious > 0:
            verdict = "suspicious"
        else:
            verdict = "no_detections"
        confidence = round(min(1.0, (malicious + 0.5 * suspicious) / 10), 2) if verdict != "no_detections" else None
        return LookupResult(
            self.name, verdict, confidence,
            details={"analysis_stats": stats, "engines_total": total,
                     "country": attributes.get("country"), "as_owner": attributes.get("as_owner"),
                     "reputation": attributes.get("reputation")},
            limitations=self.limitations,
        )
