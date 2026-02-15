#!/usr/bin/env python3
"""Configuration loader for AdGuard Rules Merger."""

import yaml
from pathlib import Path
from typing import List, Dict, Any


def load_sources_config(config_path: str = "config/sources.yaml") -> List[str]:
    """
    Load filter sources from YAML configuration file.
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        List of enabled source URLs
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    sources = []
    
    # Load main sources
    if "sources" in config:
        for source in config["sources"]:
            if source.get("enabled", True):
                sources.append(source["url"])
    
    return sources


def load_test_sources(config_path: str = "config/sources.yaml") -> List[str]:
    """
    Load test filter sources from YAML configuration file.
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        List of enabled test source URLs
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    sources = []
    
    # Load test sources
    if "test_sources" in config:
        for source in config["test_sources"]:
            if source.get("enabled", True):
                sources.append(source["url"])
    
    return sources


if __name__ == "__main__":
    # Test the configuration loader
    try:
        sources = load_sources_config()
        test_sources = load_test_sources()
        
        print("Main sources:")
        for url in sources:
            print(f"  - {url}")
        
        print("\nTest sources:")
        for url in test_sources:
            print(f"  - {url}")
            
        print(f"\nTotal: {len(sources)} main sources, {len(test_sources)} test sources")
        
    except Exception as e:
        print(f"Error loading configuration: {e}")