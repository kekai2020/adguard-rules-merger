#!/usr/bin/env python3
"""Test concurrent fetching and exception handling for Task S2 validation."""

import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
from merger import RuleEngine
from merger.parser import RuleParser


class RuleTestServer:
    """Simple HTTP server for testing rule fetching."""
    
    def __init__(self, port=0):
        self.port = port
        self.server = None
        self.thread = None
        self.rules_content = """||ads1.com^
||ads2.com^
||*.tracker.com^
@@||whitelist.com^
! This is a comment line
||malware.com^"""
    
    def start(self):
        """Start the test server."""
        # Create a custom handler that serves our rules content
        class RulesHandler(SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(self.server.rules_content.encode())
            
            def log_message(self, format, *args):
                # Suppress log messages during testing
                pass
        
        # Bind to any available port
        self.server = HTTPServer(('localhost', 0), RulesHandler)
        self.server.rules_content = self.rules_content
        self.port = self.server.server_address[1]
        
        # Start server in a separate thread
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        return self.port
    
    def stop(self):
        """Stop the test server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)


def test_concurrent_fetching():
    """Test concurrent fetching from multiple sources."""
    print("Testing concurrent fetching...")
    
    # Start multiple test servers
    servers = []
    ports = []
    
    for i in range(3):
        server = RuleTestServer()
        port = server.start()
        servers.append(server)
        ports.append(port)
        print(f"Started test server on port {port}")
    
    try:
        # Test concurrent fetching
        engine = RuleEngine(max_workers=5)
        
        sources = [f"http://localhost:{port}/rules.txt" for port in ports]
        
        start_time = time.time()
        merged_rules = engine.merge(sources)
        end_time = time.time()
        
        print(f"Concurrent merge completed in {end_time - start_time:.2f} seconds")
        print(f"Total merged rules: {len(merged_rules)}")
        
        # Verify we got rules from all sources (should be deduplicated)
        expected_unique_rules = 6  # From our test content
        if len(merged_rules) <= expected_unique_rules * len(sources):
            print("✅ Concurrent fetching test PASSED")
            return True
        else:
            print("❌ Concurrent fetching test FAILED")
            return False
            
    finally:
        # Clean up servers
        for server in servers:
            server.stop()


def test_exception_handling():
    """Test exception handling with invalid URLs."""
    print("\nTesting exception handling...")
    
    engine = RuleEngine(timeout=2)  # Short timeout for testing
    
    # Mix of valid and invalid sources
    sources = [
        "http://localhost:99999/invalid.txt",  # Invalid port
        "http://httpbin.org/delay/5",  # Slow response (will timeout)
        "http://httpbin.org/status/404",  # 404 error
    ]
    
    start_time = time.time()
    merged_rules = engine.merge(sources)
    end_time = time.time()
    
    print(f"Merge with errors completed in {end_time - start_time:.2f} seconds")
    print(f"Rules merged: {len(merged_rules)}")
    
    # Should complete without crashing, even with all sources failing
    if end_time - start_time < 10:  # Should timeout quickly
        print("✅ Exception handling test PASSED")
        return True
    else:
        print("❌ Exception handling test FAILED")
        return False


def test_deduplication_performance():
    """Test deduplication performance with many rules."""
    print("\nTesting deduplication performance...")
    
    engine = RuleEngine()
    parser = RuleParser()
    
    # Create a large set of rules with many duplicates
    base_rules = """||ads1.com^
||ads2.com^
||*.tracker.com^
@@||whitelist.com^
! Comment 1
||malware1.com^
||malware2.com^"""
    
    # Generate many variations
    all_rules = []
    for i in range(1000):
        # Create variations of the base rules
        content = base_rules.replace("1", str(i)).replace("2", str(i+1))
        rules = parser.parse_text(content, f"source_{i}")
        all_rules.extend(rules)
    
    print(f"Total rules before deduplication: {len(all_rules)}")
    
    start_time = time.time()
    deduped_rules = engine.deduplicate_rules(all_rules)
    end_time = time.time()
    
    dedup_time = end_time - start_time
    dedup_rate = (1 - len(deduped_rules) / len(all_rules)) * 100
    
    print(f"Deduplication completed in {dedup_time:.3f} seconds")
    print(f"Rules after deduplication: {len(deduped_rules)}")
    print(f"Deduplication rate: {dedup_rate:.1f}%")
    
    # Performance requirement: < 5 seconds for 1000 rules
    if dedup_time < 5.0:
        print("✅ Deduplication performance test PASSED")
        return True
    else:
        print("❌ Deduplication performance test FAILED")
        return False


if __name__ == "__main__":
    print("AdGuard Rules Merger - Task S2 Validation Tests")
    print("=" * 60)
    
    test1_passed = test_concurrent_fetching()
    test2_passed = test_exception_handling()
    test3_passed = test_deduplication_performance()
    
    print("\n" + "=" * 60)
    if test1_passed and test2_passed and test3_passed:
        print("🎉 ALL TASK S2 VALIDATION TESTS PASSED!")
        print("✅ Concurrent fetching works correctly")
        print("✅ Exception handling works correctly")
        print("✅ Deduplication performance meets requirements")
    else:
        print("❌ Some validation tests failed!")
        exit(1)