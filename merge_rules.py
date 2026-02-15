#!/usr/bin/env python3
"""
Simple CLI script for merging AdGuard rules from multiple sources.

This is a basic implementation for task S2 validation.
"""

import argparse
import logging
import sys
from pathlib import Path

# Add the merger package to the path
sys.path.insert(0, str(Path(__file__).parent))

from merger import RuleEngine


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Merge AdGuard filter rules from multiple sources"
    )
    parser.add_argument(
        "--sources", "-s",
        nargs="+",
        help="List of source URLs to merge",
        required=True
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="merged_rules.txt",
        help="Output file path (default: merged_rules.txt)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum concurrent workers (default: 10)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting AdGuard Rules Merger")
    logger.info(f"Sources: {args.sources}")
    logger.info(f"Output: {args.output}")
    
    try:
        # Initialize the engine
        engine = RuleEngine(
            timeout=args.timeout,
            max_workers=args.max_workers
        )
        
        # Merge rules
        logger.info("Fetching and merging rules...")
        merged_rules = engine.merge(args.sources)
        
        logger.info(f"Successfully merged {len(merged_rules)} rules")
        
        # Write output
        output_path = Path(args.output)
        logger.info(f"Writing merged rules to {output_path}")
        
        with open(output_path, "w", encoding="utf-8") as f:
            for rule in merged_rules:
                f.write(f"{rule}\n")
        
        logger.info(f"Merge completed successfully!")
        logger.info(f"Output saved to: {output_path.absolute()}")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Merge failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()