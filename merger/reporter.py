"""Report generator for AdGuard rules merge results."""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from .models import Rule


class MergeReporter:
    """Generates detailed reports from merge results."""
    
    def __init__(self, rules: List[Rule], stats: Optional[Dict[str, Any]] = None):
        """
        Initialize the reporter.
        
        Args:
            rules: List of merged rules
            stats: Optional statistics dictionary from merge operation
        """
        self.rules = rules
        self.stats = stats or {}
        
    def generate_markdown_report(self, title: str = "AdGuard Rules Merge Report") -> str:
        """
        Generate a Markdown format report.
        
        Args:
            title: Report title
            
        Returns:
            Markdown formatted report string
        """
        lines = [
            f"# {title}",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "",
            "## Summary",
            "",
        ]
        
        # Add statistics
        if self.stats:
            lines.extend([
                f"- **Total Rules (before dedup):** {self.stats.get('total_before', 'N/A')}",
                f"- **Total Rules (after dedup):** {self.stats.get('total_after', 'N/A')}",
                f"- **Deduplication Rate:** {self.stats.get('dedup_rate', 0):.1f}%",
                f"- **Sources Processed:** {self.stats.get('sources_processed', 0)} / {self.stats.get('sources_total', 0)}",
                f"- **Processing Time:** {self.stats.get('elapsed_time', 0):.3f} seconds",
                "",
                "### Rule Breakdown",
                "",
                f"- **Block Rules:** {self.stats.get('block_count', 0)}",
                f"- **Allow Rules:** {self.stats.get('allow_count', 0)}",
                f"- **Comments:** {self.stats.get('comment_count', 0)}",
                "",
            ])
            
            # Add conflict information if available
            if 'conflict_count' in self.stats:
                lines.extend([
                    f"- **Conflicts Detected:** {self.stats['conflict_count']}",
                    "",
                ])
        
        # Add rule distribution by source
        source_counts: Dict[str, int] = {}
        for rule in self.rules:
            source_counts[rule.source] = source_counts.get(rule.source, 0) + 1
        
        if source_counts:
            lines.extend([
                "## Source Distribution",
                "",
                "| Source | Rule Count |",
                "|--------|------------|",
            ])
            for source, count in sorted(source_counts.items(), key=lambda x: -x[1])[:10]:
                # Truncate long URLs
                display_source = source if len(source) < 50 else source[:47] + "..."
                lines.append(f"| {display_source} | {count} |")
            lines.append("")
        
        # Add top domains
        domain_counts: Dict[str, int] = {}
        for rule in self.rules:
            if rule.type in ('block', 'allow'):
                domain_counts[rule.domain] = domain_counts.get(rule.domain, 0) + 1
        
        if domain_counts:
            lines.extend([
                "## Top Domains",
                "",
                "| Domain | Count |",
                "|--------|-------|",
            ])
            for domain, count in sorted(domain_counts.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"| `{domain}` | {count} |")
            lines.append("")
        
        lines.extend([
            "## Rule Types Distribution",
            "",
        ])
        
        # Calculate type distribution
        type_counts: Dict[str, int] = {}
        for rule in self.rules:
            type_counts[rule.type] = type_counts.get(rule.type, 0) + 1
        
        for rule_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            percentage = (count / len(self.rules) * 100) if self.rules else 0
            bar = "█" * int(percentage / 5)
            lines.append(f"- **{rule_type.capitalize()}:** {count} ({percentage:.1f}%) {bar}")
        
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_json_report(self) -> Dict[str, Any]:
        """
        Generate a JSON format report.
        
        Returns:
            Dictionary containing report data
        """
        # Calculate additional statistics
        source_distribution = {}
        for rule in self.rules:
            source_distribution[rule.source] = source_distribution.get(rule.source, 0) + 1
        
        type_distribution = {}
        for rule in self.rules:
            type_distribution[rule.type] = type_distribution.get(rule.type, 0) + 1
        
        return {
            'generated_at': datetime.utcnow().isoformat(),
            'summary': {
                'total_rules': len(self.rules),
                **self.stats
            },
            'distributions': {
                'by_source': source_distribution,
                'by_type': type_distribution
            }
        }
    
    def generate_text_report(self) -> str:
        """
        Generate a plain text report.
        
        Returns:
            Plain text formatted report string
        """
        lines = [
            "=" * 60,
            "AdGuard Rules Merge Report",
            "=" * 60,
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "",
        ]
        
        if self.stats:
            lines.extend([
                "SUMMARY",
                "-" * 40,
                f"Total Rules (before): {self.stats.get('total_before', 'N/A')}",
                f"Total Rules (after):  {self.stats.get('total_after', 'N/A')}",
                f"Deduplication Rate:   {self.stats.get('dedup_rate', 0):.1f}%",
                f"Sources:              {self.stats.get('sources_processed', 0)}/{self.stats.get('sources_total', 0)}",
                f"Processing Time:      {self.stats.get('elapsed_time', 0):.3f}s",
                "",
                "RULE BREAKDOWN",
                "-" * 40,
                f"Block Rules:  {self.stats.get('block_count', 0)}",
                f"Allow Rules:  {self.stats.get('allow_count', 0)}",
                f"Comments:     {self.stats.get('comment_count', 0)}",
                "",
            ])
        
        return "\n".join(lines)
    
    def save_report(self, filepath: str, format: str = "markdown") -> None:
        """
        Save report to file.
        
        Args:
            filepath: Output file path
            format: Report format ('markdown', 'text', or 'json')
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        if format == "markdown":
            content = self.generate_markdown_report()
        elif format == "text":
            content = self.generate_text_report()
        elif format == "json":
            import json
            content = json.dumps(self.generate_json_report(), indent=2)
        else:
            raise ValueError(f"Unknown format: {format}")
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
