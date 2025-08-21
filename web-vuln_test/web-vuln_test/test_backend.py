#!/usr/bin/env python3
"""
Test script for CODEXIO Vulnerability Scanner Backend
This script tests the basic functionality without requiring a full scan
"""

import sys
import os

# Add the Backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Backend'))

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing module imports...")
    
    try:
        import requests
        print("✅ requests module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import requests: {e}")
        return False
    
    try:
        import dns.resolver
        print("✅ dns.resolver module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import dns.resolver: {e}")
        return False
    
    try:
        from bs4 import BeautifulSoup
        print("✅ BeautifulSoup module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import BeautifulSoup: {e}")
        return False
    
    try:
        import google.generativeai as genai
        print("✅ google.generativeai module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import google.generativeai: {e}")
        return False
    
    return True

def test_basic_functionality():
    """Test basic scanner functionality"""
    print("\nTesting basic scanner functionality...")
    
    try:
        from codexiovuln import AdvancedScanner, is_valid_url
        
        # Test URL validation
        test_urls = [
            "http://example.com",
            "https://test.com",
            "invalid-url",
            "ftp://example.com"
        ]
        
        for url in test_urls:
            is_valid = is_valid_url(url)
            status = "✅" if is_valid else "❌"
            print(f"{status} {url}: {is_valid}")
        
        # Test scanner initialization
        scanner = AdvancedScanner(
            target="example.com",
            scan_level=1,
            gemini_analysis=False
        )
        print("✅ Scanner initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        return False

def test_api_key():
    """Test if API key is configured"""
    print("\nTesting API key configuration...")
    
    try:
        from codexiovuln import GEMINI_API_KEY
        
        if GEMINI_API_KEY:
            print("✅ Gemini API key is configured")
            print(f"   Key: {GEMINI_API_KEY[:10]}...")
            return True
        else:
            print("⚠️  No Gemini API key found")
            print("   Set GEMINI_API_KEY environment variable or edit codexiovuln.py")
            return False
            
    except Exception as e:
        print(f"❌ API key test failed: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 50)
    print("CODEXIO Vulnerability Scanner - Backend Test")
    print("=" * 50)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Please install required dependencies:")
        print("   pip install -r Backend/requirements.txt")
        return False
    
    # Test basic functionality
    if not test_basic_functionality():
        print("\n❌ Basic functionality tests failed")
        return False
    
    # Test API key
    test_api_key()
    
    print("\n" + "=" * 50)
    print("✅ Backend tests completed successfully!")
    print("=" * 50)
    print("\nTo run a full scan:")
    print("   python Backend/codexiovuln.py --url http://example.com --ai-analysis")
    print("\nFor help:")
    print("   python Backend/codexiovuln.py --help")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
