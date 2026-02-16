"""Core engine for merging AdGuard rules."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
import requests
import time

from .models import Rule
from .parser import RuleParser


logger = logging.getLogger(__name__)


class DomainTrie:
    """
    Trie tree for efficient domain matching and wildcard coverage detection.
    
    This provides O(m) lookup time where m is the number of domain parts,
    which is more efficient than checking against all wildcard patterns.
    """
    
    def __init__(self):
        self.root = {}
        self.wildcard_endpoints: Set[str] = set()  # Domains that have wildcard coverage
    
    def add_wildcard(self, domain: str) -> None:
        """Add a wildcard domain to the trie."""
        parts = domain.split('.')
        node = self.root
        # Insert domain parts in reverse order (TLD first)
        for part in reversed(parts):
            if part not in node:
                node[part] = {}
            node = node[part]
        # Mark this as a wildcard endpoint
        node['__wildcard__'] = True
        self.wildcard_endpoints.add(domain)
    
    def is_covered(self, domain: str) -> bool:
        """Check if a domain is covered by any wildcard in the trie."""
        parts = domain.split('.')
        node = self.root
        # Check from TLD backwards
        for part in reversed(parts):
            if '__wildcard__' in node:
                return True
            if part not in node:
                return False
            node = node[part]
        return '__wildcard__' in node


class RuleEngine:
    """Core engine for fetching, parsing, and merging AdGuard rules."""

    def __init__(self, timeout: int = 30, max_workers: int = 10):
        """
        Initialize the RuleEngine.

        Args:
            timeout: Timeout for HTTP requests in seconds
            max_workers: Maximum number of concurrent workers for fetching
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.parser = RuleParser()

        # Setup requests session with reasonable defaults
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AdGuard-Rules-Merger/0.1.0'
        })

    def fetch_source(self, source: str) -> str:
        """
        Fetch content from a single source URL or local file path.

        Args:
            source: URL or local file path to fetch

        Returns:
            Content as string

        Raises:
            ValueError: If source is empty or not a string
            requests.RequestException: If the HTTP request fails
            FileNotFoundError: If the local file doesn't exist
            IOError: If the local file can't be read
        """
        # Validate input
        if not isinstance(source, str):
            raise ValueError(f"Source must be a string, got {type(source).__name__}")
        if not source.strip():
            raise ValueError("Source cannot be empty")
        
        source = source.strip()
        
        # Check if source is a local file path
        path = Path(source)
        if path.exists() and path.is_file():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return f.read()
            except IOError as e:
                logger.warning(f"Failed to read local file {source}: {e}")
                raise

        # Otherwise, treat as URL
        try:
            response = self.session.get(source, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {source}: {e}")
            raise

    def fetch_sources_concurrently(self, urls: List[str]) -> Dict[str, str]:
        """
        Fetch content from multiple sources concurrently.

        Args:
            urls: List of URLs to fetch

        Returns:
            Dictionary mapping URLs to their content
        """
        results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all fetch tasks
            future_to_url = {
                executor.submit(self.fetch_source, url): url
                for url in urls
            }

            # Collect results as they complete
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    results[url] = content
                    logger.info(f"Successfully fetched {url}")
                except Exception as e:
                    logger.warning(f"Failed to fetch {url}: {e}")
                    # Continue with other sources even if one fails

        return results

    def fetch_and_parse_concurrently(self, urls: List[str]) -> List[Rule]:
        """
        Fetch and parse content from multiple sources concurrently.
        
        This method combines fetching and parsing in a single concurrent
        operation for better performance.

        Args:
            urls: List of URLs to fetch and parse

        Returns:
            List of parsed Rule objects from all sources
        """
        all_rules = []
        
        def fetch_and_parse(url: str) -> List[Rule]:
            """Fetch and parse a single source."""
            try:
                content = self.fetch_source(url)
                rules = self.parser.parse_text(content, source=url)
                logger.info(f"Fetched and parsed {len(rules)} rules from {url}")
                return rules
            except Exception as e:
                logger.warning(f"Failed to fetch/parse {url}: {e}")
                return []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all fetch-and-parse tasks
            future_to_url = {
                executor.submit(fetch_and_parse, url): url
                for url in urls
            }

            # Collect results as they complete
            for future in as_completed(future_to_url):
                try:
                    rules = future.result()
                    all_rules.extend(rules)
                except Exception as e:
                    url = future_to_url[future]
                    logger.warning(f"Unexpected error processing {url}: {e}")

        return all_rules

    def deduplicate_rules(self, rules: List[Rule]) -> List[Rule]:
        """
        Deduplicate rules using optimized single-pass algorithm.
        
        Uses a combination of hash-based deduplication and Trie-based
        wildcard coverage detection for O(n) average time complexity.

        Args:
            rules: List of rules to deduplicate

        Returns:
            Deduplicated list of rules
            
        Raises:
            TypeError: If rules is not a list
        """
        if not isinstance(rules, list):
            raise TypeError(f"rules must be a list, got {type(rules).__name__}")
        if not rules:
            return []

        # Separate rules by type using single pass
        block_rules: List[Rule] = []
        allow_rules: List[Rule] = []
        comment_rules: List[Rule] = []

        for rule in rules:
            rule_type = rule.type
            if rule_type == 'block':
                block_rules.append(rule)
            elif rule_type == 'allow':
                allow_rules.append(rule)
            else:
                comment_rules.append(rule)

        # Deduplicate each type separately using optimized algorithm
        deduped_block = self._deduplicate_by_type_optimized(block_rules)
        deduped_allow = self._deduplicate_by_type_optimized(allow_rules)

        # Remove comments that are exact duplicates using dict to preserve order
        seen_comments: Set[str] = set()
        unique_comments: List[Rule] = []
        for comment in comment_rules:
            raw = comment.raw
            if raw not in seen_comments:
                seen_comments.add(raw)
                unique_comments.append(comment)

        return deduped_block + deduped_allow + unique_comments

    def _deduplicate_by_type_optimized(self, rules: List[Rule]) -> List[Rule]:
        """
        Optimized single-pass deduplication using Trie for wildcard coverage.
        
        This method combines exact deduplication and wildcard coverage detection
        into a single pass for better performance.

        Args:
            rules: List of rules of the same type

        Returns:
            Deduplicated list of rules
        """
        if not rules:
            return []

        # First pass: collect unique domains and wildcard patterns
        unique_rules: Dict[Tuple[str, str], Rule] = {}
        wildcard_domains: List[str] = []
        
        for rule in rules:
            key = (rule.normalized_domain, rule.type)
            existing = unique_rules.get(key)
            if existing is None:
                unique_rules[key] = rule
                if rule.wildcard:
                    wildcard_domains.append(rule.normalized_domain)
            elif rule.wildcard and not existing.wildcard:
                # Prefer wildcard version as it's more general
                unique_rules[key] = rule
                if rule.normalized_domain not in wildcard_domains:
                    wildcard_domains.append(rule.normalized_domain)

        if not wildcard_domains or not unique_rules:
            return list(unique_rules.values())

        # Build Trie from wildcard domains for efficient lookup
        trie = DomainTrie()
        for domain in wildcard_domains:
            trie.add_wildcard(domain)

        # Second pass: filter out domains covered by wildcards
        final_rules: List[Rule] = []
        for rule in unique_rules.values():
            if rule.wildcard:
                # Always keep wildcard rules
                final_rules.append(rule)
            elif not trie.is_covered(rule.normalized_domain):
                # Keep non-wildcard rules not covered by any wildcard
                final_rules.append(rule)
            else:
                logger.debug(f"Removing redundant rule {rule.domain}")

        return final_rules

    def detect_conflicts(self, rules: List[Rule]) -> List[Dict[str, any]]:
        """
        Detect conflicts between block and allow rules.
        
        A conflict occurs when the same domain is both blocked and allowed.
        
        Args:
            rules: List of rules to check
            
        Returns:
            List of conflict dictionaries with 'domain', 'block_rules', 'allow_rules'
        """
        if not isinstance(rules, list):
            raise TypeError(f"rules must be a list, got {type(rules).__name__}")
        
        # Group rules by normalized domain
        block_by_domain: Dict[str, List[Rule]] = defaultdict(list)
        allow_by_domain: Dict[str, List[Rule]] = defaultdict(list)
        
        for rule in rules:
            if rule.type == 'block':
                block_by_domain[rule.normalized_domain].append(rule)
            elif rule.type == 'allow':
                allow_by_domain[rule.normalized_domain].append(rule)
        
        # Find conflicts
        conflicts = []
        all_domains = set(block_by_domain.keys()) & set(allow_by_domain.keys())
        
        for domain in all_domains:
            conflicts.append({
                'domain': domain,
                'block_rules': block_by_domain[domain],
                'allow_rules': allow_by_domain[domain]
            })
        
        return conflicts

    def merge(self, sources: List[str], return_stats: bool = False, 
              detect_conflicts: bool = False, concurrent_parse: bool = True) -> List[Rule] | Dict[str, any]:
        """
        Merge rules from multiple sources.

        Args:
            sources: List of source URLs or file paths
            return_stats: If True, return dict with 'rules' and 'stats'
            detect_conflicts: Whether to detect block/allow conflicts (implies return_stats=True)
            concurrent_parse: If True, use concurrent fetch-and-parse for better performance

        Returns:
            List of merged and deduplicated rules, or dict if return_stats=True
            
        Raises:
            TypeError: If sources is not a list
        """
        if not isinstance(sources, list):
            raise TypeError(f"sources must be a list, got {type(sources).__name__}")
        
        logger.info(f"Starting merge of {len(sources)} sources")
        start_time = time.time()

        # Fetch and parse content from all sources
        if concurrent_parse:
            # Use concurrent fetch-and-parse for better performance
            all_rules = self.fetch_and_parse_concurrently(sources)
            sources_processed = len(sources)  # Approximate for concurrent mode
        else:
            # Sequential fetch then parse
            all_rules = []
            contents = self.fetch_sources_concurrently(sources)
            sources_processed = len(contents)
            for source_url, content in contents.items():
                try:
                    rules = self.parser.parse_text(content, source=source_url)
                    all_rules.extend(rules)
                    logger.info(f"Parsed {len(rules)} rules from {source_url}")
                except Exception as e:
                    logger.error(f"Failed to parse rules from {source_url}: {e}")

        logger.info(f"Total rules before deduplication: {len(all_rules)}")

        # Deduplicate rules
        deduped_rules = self.deduplicate_rules(all_rules)
        
        # Calculate stats
        block_count = sum(1 for r in deduped_rules if r.type == 'block')
        allow_count = sum(1 for r in deduped_rules if r.type == 'allow')
        comment_count = sum(1 for r in deduped_rules if r.type == 'comment')

        logger.info(f"Total rules after deduplication: {len(deduped_rules)}")

        # Calculate deduplication rate
        dedup_rate = 0.0
        if len(all_rules) > 0:
            dedup_rate = (1 - len(deduped_rules) / len(all_rules)) * 100
            logger.info(f"Deduplication rate: {dedup_rate:.1f}%")

        elapsed_time = time.time() - start_time
        logger.info(f"Merge completed in {elapsed_time:.2f} seconds")
        
        # Return simple list by default (backward compatible)
        if not return_stats and not detect_conflicts:
            return deduped_rules
        
        # Return detailed result
        result = {
            'rules': deduped_rules,
            'stats': {
                'total_before': len(all_rules),
                'total_after': len(deduped_rules),
                'dedup_rate': dedup_rate,
                'block_count': block_count,
                'allow_count': allow_count,
                'comment_count': comment_count,
                'elapsed_time': elapsed_time,
                'sources_processed': sources_processed,
                'sources_total': len(sources)
            }
        }
        
        # Detect conflicts if requested
        if detect_conflicts:
            conflicts = self.detect_conflicts(deduped_rules)
            result['conflicts'] = conflicts
            result['stats']['conflict_count'] = len(conflicts)
            if conflicts:
                logger.warning(f"Detected {len(conflicts)} rule conflicts")

        return result
