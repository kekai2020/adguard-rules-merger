"""Core engine for merging AdGuard rules."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Set, Tuple
import requests
import time

from .models import Rule
from .parser import RuleParser


logger = logging.getLogger(__name__)


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
            requests.RequestException: If the HTTP request fails
            FileNotFoundError: If the local file doesn't exist
            IOError: If the local file can't be read
        """
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

    def deduplicate_rules(self, rules: List[Rule]) -> List[Rule]:
        """
        Deduplicate rules, keeping the most specific ones.

        For example, if we have both *.example.com and ads.example.com,
        we keep *.example.com as it's more general.

        Args:
            rules: List of rules to deduplicate

        Returns:
            Deduplicated list of rules
        """
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

        # Deduplicate each type separately
        deduped_block = self._deduplicate_by_type(block_rules)
        deduped_allow = self._deduplicate_by_type(allow_rules)

        # Remove comments that are exact duplicates using dict to preserve order
        seen_comments: Set[str] = set()
        unique_comments: List[Rule] = []
        for comment in comment_rules:
            raw = comment.raw
            if raw not in seen_comments:
                seen_comments.add(raw)
                unique_comments.append(comment)

        return deduped_block + deduped_allow + unique_comments

    def _deduplicate_by_type(self, rules: List[Rule]) -> List[Rule]:
        """
        Deduplicate rules of the same type using optimized algorithms.

        Uses hash-based deduplication and efficient subdomain checking
        with O(n) average time complexity.

        Args:
            rules: List of rules of the same type

        Returns:
            Deduplicated list of rules
        """
        if not rules:
            return []

        # First pass: remove exact duplicates using dict for O(1) lookup
        unique_rules: Dict[Tuple[str, str], Rule] = {}
        for rule in rules:
            key = (rule.normalized_domain, rule.type)
            existing = unique_rules.get(key)
            if existing is None:
                unique_rules[key] = rule
            elif rule.wildcard and not existing.wildcard:
                # Prefer wildcard version as it's more general
                unique_rules[key] = rule

        if not unique_rules:
            return []

        # Second pass: remove subdomain redundancy using optimized checking
        # Build a set of wildcard domains for O(1) lookup
        wildcard_domains: Set[str] = set()
        wildcard_rules: List[Rule] = []
        non_wildcard_rules: List[Rule] = []

        for rule in unique_rules.values():
            if rule.wildcard:
                wildcard_domains.add(rule.normalized_domain)
                wildcard_rules.append(rule)
            else:
                non_wildcard_rules.append(rule)

        if not wildcard_domains:
            # No wildcards, return all rules
            return list(unique_rules.values())

        # Check non-wildcard rules against wildcard domains
        # Using optimized subdomain checking
        final_rules: List[Rule] = []
        final_rules.extend(wildcard_rules)  # Always keep wildcards

        for rule in non_wildcard_rules:
            if not self._is_domain_covered_by_wildcards(
                rule.normalized_domain, wildcard_domains
            ):
                final_rules.append(rule)
            else:
                logger.debug(f"Removing redundant rule {rule.domain}")

        return final_rules

    def _is_domain_covered_by_wildcards(
        self, domain: str, wildcard_domains: Set[str]
    ) -> bool:
        """
        Check if a domain is covered by any wildcard domain.

        Uses domain part matching for O(m) complexity where m is
        the number of domain parts.

        Args:
            domain: The domain to check
            wildcard_domains: Set of wildcard domain patterns

        Returns:
            True if domain is covered by any wildcard
        """
        # Split domain into parts (e.g., "ads.example.com" -> ["ads", "example", "com"])
        parts = domain.split('.')

        # Check all possible parent domains
        # e.g., for "ads.example.com", check "example.com", "com"
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in wildcard_domains:
                return True

        return False

    def merge(self, sources: List[str]) -> List[Rule]:
        """
        Merge rules from multiple sources.

        Args:
            sources: List of source URLs or file paths

        Returns:
            Merged and deduplicated list of rules
        """
        logger.info(f"Starting merge of {len(sources)} sources")
        start_time = time.time()

        all_rules = []

        # Fetch content from all sources
        contents = self.fetch_sources_concurrently(sources)

        # Parse rules from each source
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

        logger.info(f"Total rules after deduplication: {len(deduped_rules)}")

        # Calculate deduplication rate
        if len(all_rules) > 0:
            dedup_rate = (1 - len(deduped_rules) / len(all_rules)) * 100
            logger.info(f"Deduplication rate: {dedup_rate:.1f}%")

        elapsed_time = time.time() - start_time
        logger.info(f"Merge completed in {elapsed_time:.2f} seconds")

        return deduped_rules
