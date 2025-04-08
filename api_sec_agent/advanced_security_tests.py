#!/usr/bin/env python3

import requests
import json
import re
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
import concurrent.futures
import itertools
from collections import defaultdict
import openai
import random
import string
from datetime import datetime
from common import (
    VulnerabilityType,
    Vulnerability,
    progress,
    logger
)

class AdvancedSecurityTests:
    def __init__(self, ai_model):
        """Initialize the advanced security tests with an AI model for dynamic test generation."""
        self.ai_model = ai_model
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def run_all_tests(self, url: str, method: str, headers: Dict[str, str] = None) -> List[Vulnerability]:
        """Run all advanced security tests on the given URL."""
        if headers:
            self.session.headers.update(headers)
            
        progress.start_phase("Advanced Security Testing")
        
        # Run all test categories
        self._test_csrf(url, method)
        self._test_rate_limiting(url, method)
        self._test_file_upload(url, method)
        self._test_path_traversal(url, method)
        self._test_http_methods(url, method)
        self._test_cors_misconfig(url, method)
        self._test_jwt_vulnerabilities(url, method)
        self._test_graphql_security(url, method)
        self._test_api_versioning(url, method)
        self._test_dependency_scanning(url, method)
        self._test_encryption(url, method)
        self._test_session_management(url, method)
        self._test_input_validation(url, method)
        self._test_error_handling(url, method)
        self._test_api_documentation(url, method)
        self._test_websocket_security(url, method)
        self._test_oauth_openid(url, method)
        self._test_api_gateway(url, method)
        self._test_data_validation(url, method)
        self._test_api_versioning_compatibility(url, method)
        
        progress.end_phase(f"Advanced security testing completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities
    
    def _generate_test_cases(self, test_category: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Use AI to dynamically generate test cases for a specific security test category."""
        progress.log_step(f"Generating test cases for {test_category}")
        
        prompt = f"""
        Generate comprehensive security test cases for {test_category} testing.
        
        Context:
        {json.dumps(context, indent=2)}
        
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
            response = self.ai_model.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security expert generating API security test cases. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={ "type": "json_object" }
            )
            result = json.loads(response.choices[0].message.content)
            
            # Ensure we have a valid test_cases list
            test_cases = result.get('test_cases', [])
            
            # Validate that each test case is a dictionary
            valid_test_cases = []
            for test_case in test_cases:
                if isinstance(test_case, dict):
                    valid_test_cases.append(test_case)
                else:
                    logger.warning(f"Invalid test case format: {test_case}")
            
            progress.log_step(f"Generated {len(valid_test_cases)} test cases for {test_category}", {
                "categories": result.get('test_categories', [])
            })
            return valid_test_cases
        except Exception as e:
            logger.error(f"Error generating test cases for {test_category}: {str(e)}")
            # Return a default test case if there's an error
            return [{
                "name": f"Default {test_category} Test",
                "description": f"Default test for {test_category}",
                "vulnerability_type": "Security Misconfiguration",
                "payload": {},
                "expected_response": "",
                "severity": "Medium",
                "success_criteria": ""
            }]
    
    def _run_test_case(self, url: str, method: str, test_case: Dict[str, Any], category: str) -> None:
        """Run a single test case and check for vulnerabilities."""
        # Ensure test_case is a dictionary
        if not isinstance(test_case, dict):
            logger.error(f"Invalid test case format: {test_case}")
            return
            
        test_name = test_case.get('name', 'Unnamed test')
        test_description = test_case.get('description', 'No description')
        test_vulnerability_type = test_case.get('vulnerability_type', 'Unknown')
        test_severity = test_case.get('severity', 'Medium')
        
        progress.log_step(f"Running test case: {test_name}", {
            "description": test_description,
            "vulnerability_type": test_vulnerability_type,
            "severity": test_severity
        })
        
        try:
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
                response = self.session.request(method, url, params=payload)
            else:
                response = self.session.request(method, url, json=payload)
            
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
                vuln_type = test_vulnerability_type.lower()
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
                        type=VulnerabilityType(test_vulnerability_type),
                        endpoint=url,
                        description=test_description,
                        severity=test_severity,
                        evidence=response.text[:200],
                        chain_of_thought=[
                            f"AI-generated test case: {test_name}",
                            f"Test description: {test_description}",
                            f"Payload used: {json.dumps(payload)[:100]}...",
                            f"Expected response: {expected_response}",
                            f"Success criteria: {success_criteria}"
                        ]
                    )
                )
                progress.log_step(f"Vulnerability found with AI-generated test case", {
                    "test_name": test_name,
                    "vulnerability_type": test_vulnerability_type
                })
                
        except Exception as e:
            logger.error(f"Error running test case: {str(e)}")
            progress.log_step(f"Error in test case", {"error": str(e)})
    
    def _test_csrf(self, url: str, method: str) -> None:
        """Test for CSRF (Cross-Site Request Forgery) vulnerabilities."""
        progress.start_phase("CSRF Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "CSRF",
            "description": "Testing for Cross-Site Request Forgery vulnerabilities"
        }
        
        test_cases = self._generate_test_cases("CSRF", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "CSRF")
            
        progress.end_phase(f"CSRF testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'CSRF' in v.description])} vulnerabilities.")
    
    def _test_rate_limiting(self, url: str, method: str) -> None:
        """Test for rate limiting vulnerabilities."""
        progress.start_phase("Rate Limiting Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Rate Limiting",
            "description": "Testing for API rate limiting and brute force protection"
        }
        
        test_cases = self._generate_test_cases("Rate Limiting", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Rate Limiting")
            
        progress.end_phase(f"Rate limiting testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'Rate Limiting' in v.description])} vulnerabilities.")
    
    def _test_file_upload(self, url: str, method: str) -> None:
        """Test for file upload vulnerabilities."""
        progress.start_phase("File Upload Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "File Upload",
            "description": "Testing for insecure file upload handling"
        }
        
        test_cases = self._generate_test_cases("File Upload", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "File Upload")
            
        progress.end_phase(f"File upload testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'File Upload' in v.description])} vulnerabilities.")
    
    def _test_path_traversal(self, url: str, method: str) -> None:
        """Test for path traversal vulnerabilities."""
        progress.start_phase("Path Traversal Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Path Traversal",
            "description": "Testing for directory traversal vulnerabilities"
        }
        
        test_cases = self._generate_test_cases("Path Traversal", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Path Traversal")
            
        progress.end_phase(f"Path traversal testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.INJECTION and 'Path Traversal' in v.description])} vulnerabilities.")
    
    def _test_http_methods(self, url: str, method: str) -> None:
        """Test for HTTP method vulnerabilities."""
        progress.start_phase("HTTP Method Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "HTTP Methods",
            "description": "Testing for HTTP method restrictions and overrides"
        }
        
        test_cases = self._generate_test_cases("HTTP Methods", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "HTTP Methods")
            
        progress.end_phase(f"HTTP method testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'HTTP Method' in v.description])} vulnerabilities.")
    
    def _test_cors_misconfig(self, url: str, method: str) -> None:
        """Test for CORS misconfiguration vulnerabilities."""
        progress.start_phase("CORS Misconfiguration Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "CORS Misconfiguration",
            "description": "Testing for overly permissive CORS policies"
        }
        
        test_cases = self._generate_test_cases("CORS Misconfiguration", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "CORS Misconfiguration")
            
        progress.end_phase(f"CORS misconfiguration testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'CORS' in v.description])} vulnerabilities.")
    
    def _test_jwt_vulnerabilities(self, url: str, method: str) -> None:
        """Test for JWT vulnerabilities."""
        progress.start_phase("JWT Vulnerability Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "JWT Vulnerabilities",
            "description": "Testing for JWT signature validation, expiration, and algorithm confusion"
        }
        
        test_cases = self._generate_test_cases("JWT Vulnerabilities", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "JWT Vulnerabilities")
            
        progress.end_phase(f"JWT vulnerability testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.BROKEN_AUTH and 'JWT' in v.description])} vulnerabilities.")
    
    def _test_graphql_security(self, url: str, method: str) -> None:
        """Test for GraphQL security vulnerabilities."""
        progress.start_phase("GraphQL Security Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "GraphQL Security",
            "description": "Testing for GraphQL introspection, query complexity, and field-level authorization"
        }
        
        test_cases = self._generate_test_cases("GraphQL Security", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "GraphQL Security")
            
        progress.end_phase(f"GraphQL security testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.INJECTION and 'GraphQL' in v.description])} vulnerabilities.")
    
    def _test_api_versioning(self, url: str, method: str) -> None:
        """Test for API versioning vulnerabilities."""
        progress.start_phase("API Versioning Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "API Versioning",
            "description": "Testing for deprecated API versions and version header handling"
        }
        
        test_cases = self._generate_test_cases("API Versioning", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "API Versioning")
            
        progress.end_phase(f"API versioning testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'API Versioning' in v.description])} vulnerabilities.")
    
    def _test_dependency_scanning(self, url: str, method: str) -> None:
        """Test for dependency vulnerabilities."""
        progress.start_phase("Dependency Scanning")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Dependency Scanning",
            "description": "Testing for known vulnerable dependencies and outdated components"
        }
        
        test_cases = self._generate_test_cases("Dependency Scanning", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Dependency Scanning")
            
        progress.end_phase(f"Dependency scanning completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.VULNERABLE_COMPONENTS])} vulnerabilities.")
    
    def _test_encryption(self, url: str, method: str) -> None:
        """Test for encryption vulnerabilities."""
        progress.start_phase("Encryption Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Encryption",
            "description": "Testing for weak encryption algorithms and proper TLS configuration"
        }
        
        test_cases = self._generate_test_cases("Encryption", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Encryption")
            
        progress.end_phase(f"Encryption testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SENSITIVE_DATA and 'Encryption' in v.description])} vulnerabilities.")
    
    def _test_session_management(self, url: str, method: str) -> None:
        """Test for session management vulnerabilities."""
        progress.start_phase("Session Management Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Session Management",
            "description": "Testing for session fixation, timeout, and invalidation"
        }
        
        test_cases = self._generate_test_cases("Session Management", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Session Management")
            
        progress.end_phase(f"Session management testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.BROKEN_AUTH and 'Session' in v.description])} vulnerabilities.")
    
    def _test_input_validation(self, url: str, method: str) -> None:
        """Test for input validation vulnerabilities."""
        progress.start_phase("Input Validation Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Input Validation",
            "description": "Testing for input length limits, type validation, and sanitization"
        }
        
        test_cases = self._generate_test_cases("Input Validation", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Input Validation")
            
        progress.end_phase(f"Input validation testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.INJECTION and 'Input Validation' in v.description])} vulnerabilities.")
    
    def _test_error_handling(self, url: str, method: str) -> None:
        """Test for error handling vulnerabilities."""
        progress.start_phase("Error Handling Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Error Handling",
            "description": "Testing for consistent error responses and error code standardization"
        }
        
        test_cases = self._generate_test_cases("Error Handling", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Error Handling")
            
        progress.end_phase(f"Error handling testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'Error Handling' in v.description])} vulnerabilities.")
    
    def _test_api_documentation(self, url: str, method: str) -> None:
        """Test for API documentation vulnerabilities."""
        progress.start_phase("API Documentation Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "API Documentation",
            "description": "Testing for exposed API documentation and documentation accuracy"
        }
        
        test_cases = self._generate_test_cases("API Documentation", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "API Documentation")
            
        progress.end_phase(f"API documentation testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'API Documentation' in v.description])} vulnerabilities.")
    
    def _test_websocket_security(self, url: str, method: str) -> None:
        """Test for WebSocket security vulnerabilities."""
        progress.start_phase("WebSocket Security Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "WebSocket Security",
            "description": "Testing for WebSocket authentication and message validation"
        }
        
        test_cases = self._generate_test_cases("WebSocket Security", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "WebSocket Security")
            
        progress.end_phase(f"WebSocket security testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.BROKEN_AUTH and 'WebSocket' in v.description])} vulnerabilities.")
    
    def _test_oauth_openid(self, url: str, method: str) -> None:
        """Test for OAuth/OpenID Connect vulnerabilities."""
        progress.start_phase("OAuth/OpenID Connect Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "OAuth/OpenID Connect",
            "description": "Testing for OAuth implementation and token handling"
        }
        
        test_cases = self._generate_test_cases("OAuth/OpenID Connect", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "OAuth/OpenID Connect")
            
        progress.end_phase(f"OAuth/OpenID Connect testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.BROKEN_AUTH and 'OAuth' in v.description])} vulnerabilities.")
    
    def _test_api_gateway(self, url: str, method: str) -> None:
        """Test for API gateway vulnerabilities."""
        progress.start_phase("API Gateway Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "API Gateway",
            "description": "Testing for API gateway configuration and request routing"
        }
        
        test_cases = self._generate_test_cases("API Gateway", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "API Gateway")
            
        progress.end_phase(f"API gateway testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'API Gateway' in v.description])} vulnerabilities.")
    
    def _test_data_validation(self, url: str, method: str) -> None:
        """Test for data validation vulnerabilities."""
        progress.start_phase("Data Validation Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "Data Validation",
            "description": "Testing for data integrity checks and data format validation"
        }
        
        test_cases = self._generate_test_cases("Data Validation", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "Data Validation")
            
        progress.end_phase(f"Data validation testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.INJECTION and 'Data Validation' in v.description])} vulnerabilities.")
    
    def _test_api_versioning_compatibility(self, url: str, method: str) -> None:
        """Test for API versioning compatibility vulnerabilities."""
        progress.start_phase("API Versioning Compatibility Testing")
        
        # Generate test cases using AI
        context = {
            "url": url,
            "method": method,
            "headers": dict(self.session.headers),
            "test_category": "API Versioning Compatibility",
            "description": "Testing for API version compatibility and version deprecation"
        }
        
        test_cases = self._generate_test_cases("API Versioning Compatibility", context)
        
        for test_case in test_cases:
            self._run_test_case(url, method, test_case, "API Versioning Compatibility")
            
        progress.end_phase(f"API versioning compatibility testing completed. Found {len([v for v in self.vulnerabilities if v.type == VulnerabilityType.SECURITY_MISCONFIG and 'API Versioning Compatibility' in v.description])} vulnerabilities.") 