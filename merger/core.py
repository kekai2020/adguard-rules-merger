"""Core engine for merging AdGuard rules."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
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
    
    def fetch_source(self, url: str) -> str:
        """
        Fetch content from a single source URL.
        
        Args:
            url: URL to fetch
            
        Returns:
            Content as string
            
        Raises:
            requests.RequestException: If the request fails
        """
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
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
        
        # Separate rules by type for easier processing
        block_rules = [r for r in rules if r.type == 'block']
        allow_rules = [r for r in rules if r.type == 'allow']
        comment_rules = [r for r in rules if r.type == 'comment']
        
        # Deduplicate each type separately
        deduped_block = self._deduplicate_by_type(block_rules)
        deduped_allow = self._deduplicate_by_type(allow_rules)
        
        # Remove comments that are exact duplicates
        unique_comments = []
        seen_comments = set()
        for comment in comment_rules:
            if comment.raw not in seen_comments:
                seen_comments.add(comment.raw)
                unique_comments.append(comment)
        
        return deduped_block + deduped_allow + unique_comments
    
    def _deduplicate_by_type(self, rules: List[Rule]) -> List[Rule]:
        """
        Deduplicate rules of the same type.
        
        Args:
            rules: List of rules of the same type
            
        Returns:
            Deduplicated list of rules
        """
        if not rules:
            return []
        
        # First pass: remove exact duplicates
        unique_rules = {}
        for rule in rules:
            key = (rule.normalized_domain, rule.type)
            if key not in unique_rules:
                unique_rules[key] = rule
            else:
                # If we have a duplicate, prefer the wildcard version
                # as it's more general
                existing_rule = unique_rules[key]
                if rule.wildcard and not existing_rule.wildcard:
                    unique_rules[key] = rule
        
        # Second pass: remove subdomain redundancy
        # If we have *.example.com, we don't need ads.example.com
        final_rules = []
        wildcard_rules = []
        
        # Separate wildcard and non-wildcard rules
        for rule in unique_rules.values():
            if rule.wildcard:
                wildcard_rules.append(rule)
            else:
                final_rules.append(rule)
        
        # Check each non-wildcard rule against wildcard rules
        for rule in final_rules[:]:
            is_redundant = False
            for wildcard_rule in wildcard_rules:
                if rule.is_subdomain_of(wildcard_rule):
                    is_redundant = True
                    logger.debug(f"Removing redundant rule {rule.domain} (covered by {wildcard_rule.domain})")
                    break
            
            if not is_redundant:
                # Keep the rule if it's not redundant
                pass
            else:
                # Remove redundant rule
                final_rules.remove(rule)
        
        # Add all wildcard rules back
        final_rules.extend(wildcard_rules)
        
        return final_rules
    
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