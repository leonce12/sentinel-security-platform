from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.utils import paginate
from app.core.errors import Conflict
from app.database.session import get_db
from app.intelligence import service
from app.models import ThreatIndicator, ThreatLookup, User
from app.schemas.common import Page
from app.schemas.domain import IndicatorCreate, IndicatorOut, IntelLookupRequest, LookupOut
from app.security.deps import require
from app.security.permissions import Perm
from app.services import app_settings, audit

router = APIRouter(prefix="/intel", tags=["threat intelligence"])


@router.get("/status")
def status(_: User = Depends(require(Perm.INTEL_LOOKUP)), db: Session = Depends(get_db)):
    provider = service.get_external_provider()
    return {
        "local_indicators": db.query(ThreatIndicator).count(),
        "external_enabled": bool(app_settings.get(db, "external_intel_enabled")),
        "virustotal_configured": provider.configured,
        "cache_hours": app_settings.get(db, "intel_cache_hours"),
        "privacy_note": "When external lookups are enabled, only the single public IP address being checked is sent to "
                        "VirusTotal. Log contents, usernames and private addresses are never sent.",
    }


@router.post("/lookup", response_model=list[LookupOut])
def lookup(body: IntelLookupRequest, user: User = Depends(require(Perm.INTEL_LOOKUP)), db: Session = Depends(get_db)):
    return service.lookup(db, body.indicator, user)


@router.get("/lookups", response_model=Page[LookupOut])
def history(indicator: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
            _: User = Depends(require(Perm.INTEL_LOOKUP)), db: Session = Depends(get_db)):
    query = db.query(ThreatLookup)
    if indicator:
        query = query.filter(ThreatLookup.indicator == indicator.strip())
    return paginate(query.order_by(ThreatLookup.looked_up_at.desc()), page, page_size)


@router.get("/indicators", response_model=Page[IndicatorOut])
def indicators(q: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
               _: User = Depends(require(Perm.INTEL_LOOKUP)), db: Session = Depends(get_db)):
    query = db.query(ThreatIndicator)
    if q:
        query = query.filter(ThreatIndicator.indicator.ilike(f"%{q.strip()}%"))
    return paginate(query.order_by(ThreatIndicator.added_at.desc()), page, page_size)


@router.post("/indicators", response_model=IndicatorOut, status_code=201)
def add_indicator(body: IndicatorCreate, user: User = Depends(require(Perm.INTEL_MANAGE)), db: Session = Depends(get_db)):
    ip = service.validate_ip(body.indicator)
    if db.query(ThreatIndicator).filter_by(indicator=ip, source=body.source).first():
        raise Conflict("This indicator already exists for that source")
    row = ThreatIndicator(indicator=ip, verdict=body.verdict, confidence=body.confidence, source=body.source,
                          description=body.description)
    db.add(row)
    db.flush()
    audit.record(db, "intel.indicator_add", actor=user, object_type="indicator", object_id=ip,
                 details={"verdict": body.verdict, "source": body.source})
    db.commit()
    return row
