#!/usr/bin/env python3
"""
Advanced CLI tool for merging AdGuard rules from multiple sources.

Features:
- Multi-format support (AdGuard, Hosts, plain domains)
- Concurrent fetching and parsing
- Conflict detection
- Detailed statistics and reporting
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

# Add the merger package to the path
sys.path.insert(0, str(Path(__file__).parent))

from merger import RuleEngine, MergeReporter
from config_loader import load_sources_config


def setup_logging(verbose: bool = False, quiet: bool = False):
    """Setup logging configuration."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def write_rules_to_file(rules, output_path: Path, stats: dict = None):
    """Write rules to file with optional header."""
    with open(output_path, "w", encoding="utf-8") as f:
        # Write header with metadata
        f.write(f"! Merged AdGuard Filter Rules\n")
        f.write(f"! Generated: {datetime.utcnow().isoformat()}Z\n")
        if stats:
            f.write(f"! Sources: {stats.get('sources_processed', 0)}/{stats.get('sources_total', 0)}\n")
            f.write(f"! Total rules: {len(rules)}\n")
            f.write(f"! Deduplication rate: {stats.get('dedup_rate', 0):.1f}%\n")
            f.write(f"! Processing time: {stats.get('elapsed_time', 0):.2f}s\n")
            if stats.get('conflict_count', 0) > 0:
                f.write(f"! Conflicts detected: {stats['conflict_count']}\n")
        f.write("!\n")
        
        # Write rules
        for rule in rules:
            f.write(f"{rule}\n")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Merge AdGuard filter rules from multiple sources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Merge from config file
  python merge_rules.py --config config/sources.yaml

  # Merge specific sources
  python merge_rules.py -s https://example.com/rules1.txt https://example.com/rules2.txt

  # Merge with conflict detection and detailed report
  python merge_rules.py --config config/sources.yaml --detect-conflicts --report

  # Quiet mode with custom output
  python merge_rules.py --config config/sources.yaml -o output/filter.txt --quiet
        """
    )
    
    # Source options
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--sources", "-s",
        nargs="+",
        help="List of source URLs to merge"
    )
    source_group.add_argument(
        "--config", "-c",
        type=str,
        help="Path to sources configuration file (YAML)"
    )
    
    # Output options
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="merged_rules.txt",
        help="Output file path (default: merged_rules.txt)"
    )
    parser.add_argument(
        "--report", "-r",
        action="store_true",
        help="Generate detailed report"
    )
    parser.add_argument(
        "--report-format",
        choices=["markdown", "text", "json"],
        default="markdown",
        help="Report format (default: markdown)"
    )
    
    # Processing options
    parser.add_argument(
        "--detect-conflicts",
        action="store_true",
        help="Detect conflicts between block and allow rules"
    )
    parser.add_argument(
        "--no-concurrent",
        action="store_true",
        help="Disable concurrent fetch and parse"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Request timeout in seconds (default: 60)"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="Maximum concurrent workers (default: 10)"
    )
    
    # Logging options
    log_group = parser.add_mutually_exclusive_group()
    log_group.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    log_group.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show warnings and errors"
    )
    
    # Info
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.2.0"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.quiet)
    logger = logging.getLogger(__name__)
    
    # Load sources
    if args.config:
        try:
            sources = load_sources_config(args.config)
            logger.info(f"Loaded {len(sources)} sources from {args.config}")
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
    else:
        sources = args.sources
    
    if not sources:
        logger.error("No sources specified!")
        sys.exit(1)
    
    logger.info("Starting AdGuard Rules Merger v0.2.0")
    logger.info(f"Sources: {len(sources)}")
    logger.info(f"Output: {args.output}")
    
    try:
        # Initialize the engine
        engine = RuleEngine(
            timeout=args.timeout,
            max_workers=args.max_workers
        )
        
        # Merge rules with options
        logger.info("Fetching and merging rules...")
        result = engine.merge(
            sources,
            return_stats=True,
            detect_conflicts=args.detect_conflicts,
            concurrent_parse=not args.no_concurrent
        )
        
        rules = result['rules']
        stats = result['stats']
        
        logger.info(f"Successfully merged {stats['total_before']} -> {len(rules)} rules")
        logger.info(f"Deduplication rate: {stats['dedup_rate']:.1f}%")
        logger.info(f"Processing time: {stats['elapsed_time']:.2f}s")
        
        if args.detect_conflicts and stats.get('conflict_count', 0) > 0:
            logger.warning(f"Detected {stats['conflict_count']} rule conflicts")
            for conflict in result.get('conflicts', []):
                logger.warning(f"  Conflict: {conflict['domain']}")
        
        # Write output
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Writing merged rules to {output_path}")
        write_rules_to_file(rules, output_path, stats)
        
        # Generate report if requested
        if args.report:
            reporter = MergeReporter(rules, stats)
            report_ext = {"markdown": "md", "text": "txt", "json": "json"}[args.report_format]
            report_path = output_path.with_suffix(f".report.{report_ext}")
            reporter.save_report(str(report_path), format=args.report_format)
            logger.info(f"Report saved to: {report_path}")
        
        logger.info(f"✅ Merge completed successfully!")
        
        if not args.quiet:
            print(f"\n📊 Statistics:")
            print(f"   Total rules: {len(rules)}")
            print(f"   Block: {stats['block_count']}, Allow: {stats['allow_count']}, Comment: {stats['comment_count']}")
            print(f"   Deduplication: {stats['dedup_rate']:.1f}%")
            print(f"   Time: {stats['elapsed_time']:.2f}s")
            print(f"\n📝 Output: {output_path.absolute()}")
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Merge failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
