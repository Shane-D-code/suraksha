"""
PhishGuard Forensic Signal Schema

This module defines the structured JSON format for forensic signals
extracted from the Chrome Extension content script.

PART 1 - Browser Live Forensic Agent
"""

from pydantic import BaseModel, Field
from typing import Optional, List


class FormAnalysis(BaseModel):
    """Form behavior analysis signals."""
    login_detected: bool = Field(default=False, description="Whether a login form was detected")
    external_submission: bool = Field(default=False, description="Form submits to external domain")
    submission_domain: Optional[str] = Field(default=None, description="Domain where form submits to")
    hidden_inputs_count: int = Field(default=0, description="Count of hidden input fields")
    password_in_iframe: bool = Field(default=False, description="Password field inside iframe")
    hidden_inputs: Optional[int] = Field(default=None, alias="hidden_inputs_count", description="Count of hidden input fields")


class ScriptResourceAnalysis(BaseModel):
    """Script and resource analysis signals."""
    external_script_count: int = Field(default=0, description="Count of external script tags")
    unique_script_domains: int = Field(default=0, description="Count of unique script domains")
    suspicious_script_domains: List[str] = Field(default_factory=list, description="List of suspicious script domains")


class DOMManipulationIndicators(BaseModel):
    """DOM manipulation detection signals."""
    right_click_disabled: bool = Field(default=False, description="Right-click context menu disabled")
    obfuscated_html_detected: bool = Field(default=False, description="Obfuscated HTML detected")
    iframe_count: int = Field(default=0, description="Count of iframe elements")


class ContentBrandIndicators(BaseModel):
    """Content and brand detection signals."""
    brand_detected: Optional[str] = Field(default=None, description="Detected brand name")
    urgency_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Urgency keyword score")
    keyword_density: float = Field(default=0.0, description="Phishing keyword density")


class URLContext(BaseModel):
    """URL context signals."""
    current_domain: str = Field(..., description="Current page domain")
    page_url: str = Field(..., description="Full page URL")


class ForensicSignals(BaseModel):
    """
    Complete forensic signal package from Chrome Extension.
    
    This is RAW signals only - no scoring, no classification.
    The backend will enrich and analyze these signals.
    """
    # URL Context (required)
    url_context: URLContext
    
    # Form Analysis
    form_analysis: FormAnalysis = Field(default_factory=FormAnalysis)
    
    # Script & Resource Analysis
    script_analysis: ScriptResourceAnalysis = Field(default_factory=ScriptResourceAnalysis)
    
    # DOM Manipulation
    dom_manipulation: DOMManipulationIndicators = Field(default_factory=DOMManipulationIndicators)
    
    # Content & Brand
    content_analysis: ContentBrandIndicators = Field(default_factory=ContentBrandIndicators)
    
    # Additional context
    timestamp: int = Field(default=0, description="Unix timestamp of extraction")
    extension_version: str = Field(default="1.0.0", description="Extension version")
    
    class Config:
        json_schema_extra = {
            "example": {
                "url_context": {
                    "current_domain": "secure-login-verify.xyz",
                    "page_url": "https://secure-login-verify.xyz/account/login"
                },
                "form_analysis": {
                    "login_detected": True,
                    "external_submission": True,
                    "submission_domain": "attacker.com",
                    "hidden_inputs_count": 3,
                    "password_in_iframe": False
                },
                "script_analysis": {
                    "external_script_count": 5,
                    "unique_script_domains": 3,
                    "suspicious_script_domains": ["tracker-analytics.net"]
                },
                "dom_manipulation": {
                    "right_click_disabled": True,
                    "obfuscated_html_detected": False,
                    "iframe_count": 2
                },
                "content_analysis": {
                    "brand_detected": "PayPal",
                    "urgency_score": 0.8,
                    "keyword_density": 0.15
                }
            }
        }

