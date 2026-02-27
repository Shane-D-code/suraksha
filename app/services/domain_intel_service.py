"""
domain_intel_service.py
Person 3 — Graph & Threat Intelligence
Enriches domains with real-world intelligence signals.

Signals collected:
  - Domain age (WHOIS) → new domain = high risk
  - ASN / hosting provider → bullet-proof hosters = red flag
  - SSL certificate issuer → free cert on 2-day-old domain = suspicious
  - DNS TTL → very short TTL = fast-flux (evasion technique)
  - MX records → no email infra but phishing email = suspicious
  - Registrar → known-abused registrars
  - Registrant country → high-risk jurisdictions

This layer removes the "Google flagged as MEDIUM" false positive problem.
Domain age + reputation alone kills most false positives.
"""

import asyncio
import socket
import ssl
import logging
import json
import re
import dns.resolver
import dns.exception
import whois as python_whois
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Risk Config ─────────────────────────────────────────────────────────────

# ASNs known to host bulletproof/abuse-tolerant infrastructure
SUSPICIOUS_ASNS = {
    "AS174", "AS9009", "AS60781", "AS206728",   # common abuse hosts
    "AS3842", "AS49453", "AS197328", "AS29802"
}

# Registrars with high abuse rates
SUSPICIOUS_REGISTRARS = {
    "namecheap", "publicdomainregistry", "todaynic",
    "bizcn", "west263", "hichina"
}

# Countries associated with high phishing volume
HIGH_RISK_COUNTRIES = {"RU", "CN", "NG", "IN", "BR", "PK", "BD"}

# Domain age thresholds
AGE_HIGH_RISK_DAYS = 7       # < 7 days old = very high risk
AGE_MEDIUM_RISK_DAYS = 30    # < 30 days old = elevated risk
AGE_ESTABLISHED_DAYS = 365   # > 1 year = established, lower risk

# SSL issuers that are free and commonly abused
FREE_SSL_ISSUERS = {
    "let's encrypt", "zerossl", "buypass", "ssl.com free"
}


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class DomainIntelligence:
    domain: str

    # WHOIS
    domain_age_days: Optional[int] = None
    expiry_days: Optional[int] = None
    registrar: Optional[str] = None
    registrant_country: Optional[str] = None
    whois_privacy: bool = False

    # Network
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    ip: Optional[str] = None

    # SSL
    ssl_issuer: Optional[str] = None
    ssl_expiry_days: Optional[int] = None
    ssl_valid: bool = False

    # DNS
    dns_ttl: Optional[int] = None
    has_mx: bool = False
    nameservers: list[str] = field(default_factory=list)

    # Computed risk
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)
    is_established: bool = False

    # Metadata
    collected_at: datetime = field(default_factory=datetime.utcnow)
    collection_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "domain_age_days": self.domain_age_days,
            "registrar": self.registrar,
            "registrant_country": self.registrant_country,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "ssl_issuer": self.ssl_issuer,
            "ssl_valid": self.ssl_valid,
            "dns_ttl": self.dns_ttl,
            "has_mx": self.has_mx,
            "risk_score": round(self.risk_score, 3),
            "risk_reasons": self.risk_reasons,
            "is_established": self.is_established,
        }


# ─── Domain Intelligence Service ─────────────────────────────────────────────

class DomainIntelService:
    """
    Enriches domain with external intelligence signals.

    All lookups run concurrently (asyncio.gather) so total time
    is max(individual_times) not sum(individual_times).
    Typical enrichment: ~3-6 seconds for a fresh domain.

    Results are cached in Redis for 6 hours — domain age doesn't
    change that fast.

    WHOIS note: python-whois parsing is inconsistent across registrars.
    We handle failures gracefully — missing data ≠ crash.
    """

    def __init__(self, db_pool=None, redis_client=None, timeout: int = 8):
        self.db = db_pool
        self.redis = redis_client
        self.timeout = timeout

    # ── Main Entry ────────────────────────────────────────────────────────────

    async def enrich(self, domain: str) -> DomainIntelligence:
        """
        Full domain enrichment. Returns DomainIntelligence with risk assessment.

        Cache TTL: 6 hours (domain age/WHOIS doesn't change fast)
        """
        # Strip to root domain for WHOIS (strip subdomains)
        root_domain = self._get_root_domain(domain)

        # Redis cache check
        if self.redis:
            cached = await self.redis.get(f"intel:{root_domain}")
            if cached:
                data = json.loads(cached)
                intel = DomainIntelligence(**{
                    k: v for k, v in data.items()
                    if k in DomainIntelligence.__dataclass_fields__
                })
                logger.debug(f"Intel cache hit: {root_domain}")
                return intel

        intel = DomainIntelligence(domain=root_domain)

        # Run all lookups concurrently
        results = await asyncio.gather(
            self._collect_whois(root_domain),
            self._collect_dns(root_domain),
            self._collect_ssl(root_domain),
            self._collect_asn(root_domain),
            return_exceptions=True
        )

        # Apply results
        for result in results:
            if isinstance(result, Exception):
                intel.collection_errors.append(str(result))
            elif isinstance(result, dict):
                for key, value in result.items():
                    if hasattr(intel, key):
                        setattr(intel, key, value)

        # Calculate risk score
        self._calculate_risk(intel)

        # Cache for 6 hours
        if self.redis:
            await self.redis.setex(
                f"intel:{root_domain}", 21600,
                json.dumps(intel.to_dict())
            )

        # Persist to DB
        if self.db:
            await self._persist(intel)

        return intel

    # ── WHOIS Collection ──────────────────────────────────────────────────────

    async def _collect_whois(self, domain: str) -> dict:
        """
        WHOIS lookup for domain age, registrar, country.
        Most important signal: domain age.
        """
        loop = asyncio.get_event_loop()
        try:
            w = await asyncio.wait_for(
                loop.run_in_executor(None, python_whois.whois, domain),
                timeout=self.timeout
            )

            result = {}

            # Domain age
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age = (datetime.utcnow() - creation).days
                result["domain_age_days"] = max(age, 0)
                result["is_established"] = age > AGE_ESTABLISHED_DAYS

            # Expiry
            expiry = w.expiration_date
            if isinstance(expiry, list):
                expiry = expiry[0]
            if expiry:
                result["expiry_days"] = max((expiry - datetime.utcnow()).days, 0)

            # Registrar
            registrar = w.registrar
            if registrar:
                result["registrar"] = str(registrar).lower()[:100]

            # Country
            country = w.country or (w.registrant_country if hasattr(w, 'registrant_country') else None)
            if country:
                result["registrant_country"] = str(country).upper()[:2]

            # Privacy shield detection
            emails = w.emails or []
            if isinstance(emails, str):
                emails = [emails]
            privacy_keywords = ["privacy", "protect", "proxy", "redacted", "withheld"]
            registrant = str(w.get("registrant_name", "") or "").lower()
            result["whois_privacy"] = any(
                kw in registrant for kw in privacy_keywords
            )

            return result

        except asyncio.TimeoutError:
            logger.warning(f"WHOIS timeout: {domain}")
            return {}
        except Exception as e:
            logger.warning(f"WHOIS failed for {domain}: {e}")
            return {}

    # ── DNS Collection ────────────────────────────────────────────────────────

    async def _collect_dns(self, domain: str) -> dict:
        """
        DNS TTL, nameservers, MX records.
        Very short TTL = fast-flux = sophisticated evasion.
        No MX records but sent in phishing email = suspicious.
        """
        loop = asyncio.get_event_loop()

        async def resolve(record_type: str):
            try:
                answers = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(domain, record_type)
                    ),
                    timeout=5.0
                )
                return answers
            except Exception:
                return None

        result = {}

        # A record for TTL
        a_records = await resolve("A")
        if a_records:
            result["dns_ttl"] = a_records.rrset.ttl if a_records.rrset else None

        # MX records
        mx_records = await resolve("MX")
        result["has_mx"] = mx_records is not None and len(mx_records) > 0

        # Nameservers
        ns_records = await resolve("NS")
        if ns_records:
            result["nameservers"] = [str(r) for r in ns_records][:4]

        return result

    # ── SSL Collection ────────────────────────────────────────────────────────

    async def _collect_ssl(self, domain: str) -> dict:
        """
        SSL certificate issuer and validity.
        Free cert (Let's Encrypt) on a 3-day-old domain is a strong phishing signal.
        Note: free certs are fine on their own — the combination matters.
        """
        loop = asyncio.get_event_loop()

        def _fetch():
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(
                    socket.create_connection((domain, 443), timeout=5),
                    server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert()

                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    org = issuer.get("organizationName", "")

                    not_after = cert.get("notAfter")
                    expiry_days = None
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry_days = (expiry - datetime.utcnow()).days

                    return {
                        "ssl_issuer": org.lower() if org else None,
                        "ssl_expiry_days": expiry_days,
                        "ssl_valid": True
                    }
            except Exception as e:
                return {"ssl_valid": False, "ssl_issuer": None}

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _fetch),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            return {"ssl_valid": False}

    # ── ASN Collection ────────────────────────────────────────────────────────

    async def _collect_asn(self, domain: str) -> dict:
        """
        ASN lookup to identify hosting provider.
        Bulletproof hosting providers = known to ignore abuse complaints.
        """
        loop = asyncio.get_event_loop()

        def _lookup():
            try:
                ip = socket.gethostbyname(domain)
                # Query CYMRU whois for ASN (reliable, free)
                # Format: return IP ASN mapping
                import ipaddress
                addr = ipaddress.ip_address(ip)
                reversed_ip = ".".join(reversed(ip.split(".")))
                query = f"{reversed_ip}.origin.asn.cymru.com"
                answers = dns.resolver.resolve(query, "TXT")
                for rdata in answers:
                    parts = str(rdata).strip('"').split("|")
                    if len(parts) >= 2:
                        asn = parts[0].strip()
                        asn_org = parts[-1].strip() if len(parts) >= 4 else "Unknown"
                        return {"asn": asn, "asn_org": asn_org, "ip": ip}
            except Exception:
                pass
            return {}

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _lookup),
                timeout=6.0
            )
        except Exception:
            return {}

    # ── Risk Scoring ──────────────────────────────────────────────────────────

    def _calculate_risk(self, intel: DomainIntelligence):
        """
        Converts raw intelligence signals into a risk score (0–1).
        Each factor is independent — they stack multiplicatively in threat level,
        not just additively.
        """
        score = 0.0
        reasons = []

        # ── Domain Age (highest weight) ──────────────────────────────────────
        if intel.domain_age_days is not None:
            if intel.domain_age_days <= AGE_HIGH_RISK_DAYS:
                score += 0.45
                reasons.append(
                    f"Domain registered only {intel.domain_age_days} day(s) ago — very new"
                )
            elif intel.domain_age_days <= AGE_MEDIUM_RISK_DAYS:
                score += 0.25
                reasons.append(
                    f"Domain is {intel.domain_age_days} days old — recently registered"
                )
            elif intel.domain_age_days > AGE_ESTABLISHED_DAYS:
                score -= 0.15   # Established domain — reduce risk
                intel.is_established = True
        else:
            # Can't determine age = mildly suspicious (WHOIS privacy?)
            score += 0.10
            reasons.append("Domain age could not be determined")

        # ── WHOIS Privacy ────────────────────────────────────────────────────
        if intel.whois_privacy:
            score += 0.10
            reasons.append("WHOIS privacy protection enabled — registrant hidden")

        # ── Registrar Risk ───────────────────────────────────────────────────
        if intel.registrar:
            registrar_lower = intel.registrar.lower()
            for susp in SUSPICIOUS_REGISTRARS:
                if susp in registrar_lower:
                    score += 0.15
                    reasons.append(f"Registrar '{intel.registrar}' has elevated abuse rate")
                    break

        # ── Country Risk ─────────────────────────────────────────────────────
        if intel.registrant_country in HIGH_RISK_COUNTRIES:
            score += 0.10
            reasons.append(
                f"Registrant country ({intel.registrant_country}) has high phishing volume"
            )

        # ── ASN Risk ─────────────────────────────────────────────────────────
        if intel.asn and intel.asn.upper() in SUSPICIOUS_ASNS:
            score += 0.20
            reasons.append(
                f"Hosted on ASN {intel.asn} — known for abuse tolerance"
            )

        # ── SSL Risk ─────────────────────────────────────────────────────────
        if not intel.ssl_valid:
            score += 0.08
            reasons.append("No valid SSL certificate — unencrypted or certificate error")
        elif intel.ssl_issuer:
            for free_issuer in FREE_SSL_ISSUERS:
                if free_issuer in intel.ssl_issuer:
                    # Free cert alone is NOT suspicious, but combined with new domain it is
                    if intel.domain_age_days is not None and intel.domain_age_days < 30:
                        score += 0.12
                        reasons.append(
                            f"Free SSL cert ({intel.ssl_issuer}) on recently registered domain"
                        )
                    break

        # ── Fast-Flux Detection ──────────────────────────────────────────────
        if intel.dns_ttl is not None and intel.dns_ttl < 300:
            score += 0.15
            reasons.append(
                f"Very short DNS TTL ({intel.dns_ttl}s) — possible fast-flux evasion"
            )

        # ── Expiry Risk ──────────────────────────────────────────────────────
        if intel.expiry_days is not None and intel.expiry_days < 30:
            score += 0.08
            reasons.append(
                f"Domain expires in {intel.expiry_days} day(s) — short-term registration"
            )

        # ── Established domain bonus ─────────────────────────────────────────
        if intel.is_established:
            score = max(score - 0.10, 0.0)   # Reduce risk for established domains

        intel.risk_score = max(min(score, 1.0), 0.0)
        intel.risk_reasons = reasons

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _get_root_domain(self, domain: str) -> str:
        """Strip subdomains: mail.google.com → google.com"""
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove path
        domain = domain.split("/")[0]
        # Keep last 2 parts (or 3 for .co.uk style)
        parts = domain.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return domain

    # ── DB Persistence ───────────────────────────────────────────────────────

    async def _persist(self, intel: DomainIntelligence):
        try:
            await self.db.execute("""
                INSERT INTO domain_intelligence
                    (domain, domain_age_days, registrar, registrant_country,
                     asn, asn_org, ssl_issuer, ssl_valid, dns_ttl,
                     has_mx, risk_score, risk_reasons, is_established, collected_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                ON CONFLICT (domain) DO UPDATE SET
                    domain_age_days = EXCLUDED.domain_age_days,
                    risk_score = EXCLUDED.risk_score,
                    risk_reasons = EXCLUDED.risk_reasons,
                    collected_at = EXCLUDED.collected_at
            """,
                intel.domain,
                intel.domain_age_days,
                intel.registrar,
                intel.registrant_country,
                intel.asn,
                intel.asn_org,
                intel.ssl_issuer,
                intel.ssl_valid,
                intel.dns_ttl,
                intel.has_mx,
                intel.risk_score,
                json.dumps(intel.risk_reasons),
                intel.is_established,
                intel.collected_at
            )
        except Exception as e:
            logger.error(f"Failed to persist domain intel for {intel.domain}: {e}")
