#!/usr/bin/env python3

import logging
import os
import sys
import json
from typing import List, Dict, Any, Optional, Set
from enum import Enum
from dataclasses import dataclass
from datetime import datetime

# Configure detailed logging
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = os.path.join(log_dir, f"security_scan_{timestamp}.log")

# Configure logging to both file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ProgressLogger:
    def __init__(self):
        self.step_count = 0
        self.current_phase = ""
        
    def start_phase(self, phase_name: str):
        self.current_phase = phase_name
        self.step_count = 0
        logger.info(f"\n{'='*80}")
        logger.info(f"STARTING PHASE: {phase_name}")
        logger.info(f"{'='*80}\n")
        
    def log_step(self, step_description: str, details: Optional[Dict[str, Any]] = None):
        self.step_count += 1
        logger.info(f"[{self.current_phase} - Step {self.step_count}] {step_description}")
        if details:
            logger.info(f"Details: {json.dumps(details, indent=2)}")
            
    def end_phase(self, summary: Optional[str] = None):
        logger.info(f"\n{'-'*80}")
        logger.info(f"COMPLETED PHASE: {self.current_phase} - {self.step_count} steps")
        if summary:
            logger.info(f"Summary: {summary}")
        logger.info(f"{'-'*80}\n")

# Global progress logger
progress = ProgressLogger()

class VulnerabilityType(Enum):
    INJECTION = "Injection"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    XSS = "Cross-Site Scripting"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    VULNERABLE_COMPONENTS = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"

@dataclass
class Vulnerability:
    type: VulnerabilityType
    endpoint: str
    description: str
    severity: str
    evidence: str
    chain_of_thought: List[str]

@dataclass
class EndpointInfo:
    path: str
    methods: Set[str]
    parameters: Dict[str, List[str]]
    response_codes: Dict[str, int]
    content_types: Set[str]
    requires_auth: bool
    discovered_from: str
    related_endpoints: Set[str] 