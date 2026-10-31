"""Plain-text Markdown report renderer (no external dependencies).

Moved verbatim during the P1-3 package split; table layout, emoji markers and
deterministic substitutes are unchanged.
"""

from __future__ import annotations

from ..domain_classifier import CATEGORY_LABELS, CATEGORY_ORDER
from .analysis import (
    _STAGE_ORDER,
    _build_matrix,
    _cat_label,
    _defense_layer_rows,
    _dup_emoji,
    _generation_label,
    _modifier_total,
    _ruletype_label,
)
from .analysis import (
    _format_stage_time as _format_stage_time_md,
)


def _cell(text: object) -> str:
    """Escape a value for a GFM table cell.

    ``|`` splits cells even inside backticks, and rule lines (``||x.com^``),
    upstream scam-API reason strings and user-configured source names all
    routinely contain pipes — every free-text table cell goes through this.
    """
    return str(text).replace("|", "\\|")


def _render_stage_timings_md(stage_timings: dict[str, float]) -> list[str]:
    """Render per-stage elapsed times as a Markdown table."""
    if not stage_timings:
        return []
    total = max(sum(stage_timings.values()), 1e-9)
    lines: list[str] = []
    lines.append("### ⏱️ 各阶段执行耗时")
    lines.append("")
    lines.append("| 流水线阶段 | 耗时 | 占比 |")
    lines.append("|---|---:|---:|")
    rendered: set[str] = set()
    for key, label in _STAGE_ORDER:
        if key in stage_timings:
            secs = stage_timings[key]
            pct = secs / total * 100
            lines.append(f"| {label} | {_format_stage_time_md(secs)} | {pct:.1f}% |")
            rendered.add(key)
    for key, secs in stage_timings.items():
        if key not in rendered:
            pct = secs / total * 100
            lines.append(f"| {key} | {_format_stage_time_md(secs)} | {pct:.1f}% |")
    total_ms = sum(stage_timings.values()) * 1000
    total_str = f"{total_ms:.1f} ms" if total_ms >= 1.0 else f"{total_ms * 1000:.0f} µs"
    lines.append(f"| **合计** | **{total_str}** | **100.0%** |")
    lines.append("")
    return lines


def _render_whitelist_audit(outcome) -> list[str]:
    """Render the whitelist threat-intel audit section (nine)."""
    lines: list[str] = []
    # ── 白名单审计 ──
    lines.append("## 九、白名单威胁情报审计")
    lines.append("")
    lines.append(
        "> 多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。"
    )
    lines.append("")
    audit_sum = (getattr(outcome, "whitelist_audit", {}) or {}).get("summary", {})
    if audit_sum:
        lines.append(f"- 🔴 恶意：{audit_sum.get('malicious', 0)}")
        lines.append(f"- 🟡 可疑：{audit_sum.get('suspicious', 0)}")
        lines.append(f"- 🟢 安全：{audit_sum.get('safe', 0)}")
        lines.append(f"- ⚪ 未知：{audit_sum.get('unknown', 0)}")
        lines.append("")
        # V7 P2: render the already-computed risk-score distribution and the
        # top-10 highest-risk domains (previously produced but dropped).
        risk_buckets = audit_sum.get("risk_score_buckets", {})
        if risk_buckets:
            lines.append("### 风险分分布")
            lines.append("")
            lines.append("| 风险分区间 | 数量 |")
            lines.append("|-----------|------|")
            bucket_label = {
                "high(>=50)": "高风险 (≥50)",
                "medium(20-49)": "中风险 (20–49)",
                "low(1-19)": "低风险 (1–19)",
                "none(0)": "无风险 (0)",
            }
            for k in ("high(>=50)", "medium(20-49)", "low(1-19)", "none(0)"):
                cnt = risk_buckets.get(k, 0)
                lines.append(f"| {bucket_label.get(k, k)} | {cnt} |")
            lines.append("")
        top_risky = audit_sum.get("top_risky", [])
        if top_risky:
            rating_short = {
                "malicious": "🔴",
                "suspicious": "🟡",
                "safe": "🟢",
                "unknown": "⚪",
            }
            lines.append("### 风险最高 Top 10")
            lines.append("")
            lines.append("| 域名 | 评级 | 风险分 | 原因 |")
            lines.append("|------|------|--------|------|")
            for tr in top_risky:
                lines.append(
                    f"| `{tr['domain']}` | {rating_short.get(tr.get('rating'), '')} | "
                    f"{tr.get('risk_score', 0)} | {tr.get('reason', '')} |"
                )
            lines.append("")
        # V5: multi-layer defense overview (shared catalog with the HTML table)
        layers_enabled = audit_sum.get("layers_enabled", {})
        layer_hits = audit_sum.get("layer_hits", {})
        if layers_enabled:
            lines.append("### 防御层概览")
            lines.append("")
            lines.append("| 层级 | 检测内容 | 状态 | 成本 | 命中数 |")
            lines.append("|------|---------|------|------|--------|")
            for row in _defense_layer_rows(layers_enabled, layer_hits):
                lines.append(
                    f"| {row['name']} | {row['desc']} | {row['status']} | "
                    f"{row['cost']} | {row['hits']} |"
                )
            lines.append("")
        # V5: category distribution
        cat_counts = audit_sum.get("category_counts", {})
        if cat_counts:
            lines.append("### 白名单域名类别分布")
            lines.append("")
            lines.append("| 类别 | 数量 | 占比 |")
            lines.append("|------|------|------|")
            total_cat = sum(cat_counts.values()) or 1
            for cat in CATEGORY_ORDER:
                cnt = cat_counts.get(cat, 0)
                if cnt == 0:
                    continue
                pct = cnt / total_cat * 100
                label = CATEGORY_LABELS.get(cat, cat)
                lines.append(f"| {label} | {cnt} | {pct:.1f}% |")
            lines.append("")
        # V5: classification confidence distribution
        conf_dist = audit_sum.get("category_confidence", {})
        if conf_dist:
            lines.append("### 分类置信度分布")
            lines.append("")
            lines.append(
                "> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。"
            )
            lines.append("")
            lines.append("| 置信度等级 | 数量 | 占比 |")
            lines.append("|-----------|------|------|")
            total_conf = sum(conf_dist.values()) or 1
            for level in ("high(>=0.9)", "medium(0.6-0.89)", "low(<0.6)"):
                cnt = conf_dist.get(level, 0)
                pct = cnt / total_conf * 100
                label = {
                    "high(>=0.9)": "高置信度 (注册域名匹配)",
                    "medium(0.6-0.89)": "中置信度 (子域名前缀)",
                    "low(<0.6)": "低置信度 (无法分类)",
                }.get(level, level)
                lines.append(f"| {label} | {cnt} | {pct:.1f}% |")
            lines.append("")
    audit_rules_list = (getattr(outcome, "whitelist_audit", {}) or {}).get("rules", [])
    if audit_rules_list:
        lines.append("| 域名 | 评级 | 类别 | 风险分 | 建议动作 | 置信度 | 原因 | 来源 |")
        lines.append("|------|------|------|--------|---------|--------|------|------|")
        rating_md = {
            "malicious": "🔴 恶意",
            "suspicious": "🟡 可疑",
            "safe": "🟢 安全",
            "unknown": "⚪ 未知",
        }
        for r in audit_rules_list:
            label = rating_md.get(r["rating"], r["rating"])
            cat_label = CATEGORY_LABELS.get(r.get("category", "other"), r.get("category", "other"))
            conf = r.get("category_confidence", 0)
            srcs = ", ".join(r.get("sources", []))
            risk = r.get("risk_score", 0)
            rec = r.get("recommendation_label", "")
            lines.append(
                f"| `{_cell(r['domain'])}` | {label} | {cat_label} | {risk} | {rec} | {conf:.2f} | {_cell(r['reason'])} | {_cell(srcs)} |"
            )
        lines.append("")
    else:
        lines.append("*审计未启用或无域名规则*")
        lines.append("")

    return lines


def generate_markdown_report(blocks, allows, outcome, analysis, include_time: bool = False) -> str:
    """Generate a plain-text Markdown report (no external dependencies)."""
    generated_at = _generation_label(include_time)
    if include_time:
        _meta_stamp = generated_at[:19].replace("T", " ")
        _elapsed = f"{outcome.elapsed:.1f}s"
        _footer_stamp = generated_at[:10]
        _cache_value = str(outcome.sources_cached)
        _cache_meta = f" | 缓存命中：{outcome.sources_cached}"
    else:
        _meta_stamp = f"内容版本 {outcome.content_version}"
        _elapsed = "—"
        _footer_stamp = f"内容版本 {outcome.content_version}"
        _cache_value = "—"
        _cache_meta = ""
    total_block = len(blocks)
    total_allow = len(allows)
    raw_count = outcome.raw_count
    cats = analysis["categories"]
    rt = analysis["rule_types"]
    modifier_stats = getattr(outcome, "modifier_stats", {}) or {}
    modifier_total = _modifier_total(modifier_stats)
    source_overlap = getattr(outcome, "source_overlap", {}) or {}
    overlap_pairs = source_overlap.get("pairs", [])
    source_effective = source_overlap.get("source_effective", {})
    contributions = getattr(outcome, "contributions", [])
    contrib_by_name = {c["name"]: c for c in contributions}
    badfilter_removed = getattr(outcome, "badfilter_removed", 0) or 0
    promoted_groups = getattr(outcome, "wildcard_promoted_groups", 0) or 0
    dedup = outcome.exact_merged + outcome.normalized_merged + outcome.regex_merged
    after_dedup = raw_count - dedup
    after_badfilter = after_dedup - badfilter_removed
    agg_net = (
        outcome.aggregated
        + outcome.wildcard_aggregated
        + outcome.wildcard_promoted
        - promoted_groups
    )
    after_agg = after_badfilter - agg_net

    lines: list[str] = []
    lines.append("# AdGuard Rules Merger V8 — 规则分析报告")
    lines.append("")
    lines.append(f"> {_meta_stamp} | 源：{outcome.sources_ok}/{outcome.sources_total}{_cache_meta}")
    lines.append("")

    # ── 概览 ──
    lines.append("## 一、概览")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|------|------|")
    lines.append(f"| Block 规则 | {total_block:,} |")
    lines.append(f"| Allow 白名单 | {total_allow:,} |")
    final_count = total_block + total_allow
    compression = (1 - final_count / raw_count) * 100 if raw_count else 0.0
    # R-1: the headline card is overall compression; the dedup step alone is a
    # distinct "纯去重率" so the two meanings are no longer conflated.
    pure_dedup_rate = (dedup / raw_count * 100) if raw_count else 0.0
    lines.append(f"| 纯去重率（去重阶段） | {pure_dedup_rate:.1f}% |")
    lines.append(
        f"| 最终压缩（原始→输出） | {raw_count:,} → {final_count:,}（-{compression:.0f}%） |"
    )
    # R-3: aggregation savings shown net of promoted wildcard parents.
    lines.append(f"| 聚合精简（净） | {agg_net:,} |")
    lines.append(f"| 冲突消解 | {outcome.conflict_resolved:,} |")
    # R-4: "带 $ 修饰符规则" must be a rule count, not a modifier-token count.
    mod_rule_count = sum(1 for r in blocks if r.modifiers) + sum(1 for r in allows if r.modifiers)
    lines.append(f"| 带 $ 修饰符规则数 | {mod_rule_count:,} |")
    lines.append(f"| 总耗时 | {_elapsed} |")
    lines.append("")

    # 各阶段执行耗时（仅在带时间戳时显示，保证字节稳定）
    if include_time:
        _stage_timings = getattr(outcome, "stage_timings", {}) or {}
        lines.extend(_render_stage_timings_md(_stage_timings))

    # ── 执行摘要（U-1）：3-5 条结论，无需通读全文 ──
    _summary: list[str] = []
    if outcome.failed_sources:
        names = ", ".join(f.get("name", "?") for f in outcome.failed_sources[:3])
        more = "…" if len(outcome.failed_sources) > 3 else ""
        _summary.append(f"- ⚠️ **{len(outcome.failed_sources)} 个源失败**：{names}{more}")
    _summary.append(
        f"- 最终输出 **{total_block:,}** 条 Block + **{total_allow:,}** 条 Allow"
        f"（原始 {raw_count:,}，压缩 **-{compression:.0f}%**）"
    )
    if outcome.conflict_resolved:
        _summary.append(f"- ⚔️ **{outcome.conflict_resolved:,}** 条拦截规则与白名单重叠（拦截保留）")
    _added = getattr(outcome, "added", None)
    _removed = getattr(outcome, "removed", None)
    if _added is not None or _removed is not None:
        _summary.append(
            f"- 🔁 相对 diff：新增 {len(_added or []):,} / 移除 {len(_removed or []):,} 域名"
        )
    if _summary:
        lines.append("### 执行摘要")
        lines.append("")
        lines.extend(_summary)
        lines.append("")

    # ── 失败源（提级到概览之后，风险信息前置）──
    if outcome.failed_sources:
        lines.append("### ⚠️ 失败源")
        lines.append("")
        for f in outcome.failed_sources:
            et = f.get("error_type")
            tag = f" `[{et}]`" if et else ""
            lines.append(f"- **{_cell(f['name'])}**{tag} — {_cell(f['error'])}")
        lines.append("")

    # ── 优化流水线 ──
    lines.append("## 二、优化流水线")
    lines.append("")
    lines.append("| 阶段 | 规则数 | 本阶段减少 |")
    lines.append("|------|--------|-----------|")
    lines.append(f"| 原始规则（Raw） | {raw_count:,} | - |")
    lines.append(
        f"| 去重后（精确 {outcome.exact_merged:,} / 规范化 {outcome.normalized_merged:,} / 正则 {outcome.regex_merged:,}） | {after_dedup:,} | -{dedup:,} |"
    )
    lines.append(
        f"| badfilter 取消后（被 $badfilter 取消） | {after_badfilter:,} | -{badfilter_removed:,} |"
    )
    lines.append(
        f"| 聚合后（净：折叠 {outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted - promoted_groups:,}） | {after_agg:,} | -{agg_net:,} |"
    )
    lines.append(
        f"| 冲突消解后（最终输出） | {total_block + total_allow:,} | -{outcome.conflict_resolved:,} |"
    )
    lines.append("")

    # ── 规则类型与类别 ──
    lines.append("## 三、规则类型与类别分布")
    lines.append("")
    lines.append("### 规则类型")
    lines.append("")
    lines.append("| 类型 | 数量 |")
    lines.append("|------|------|")
    if rt:
        for t, v in sorted(rt.items(), key=lambda x: -x[1]):
            lines.append(f"| {_ruletype_label(t)} | {v:,} |")
    else:
        lines.append("| 无数据 | - |")
    lines.append("")
    lines.append("### 类别分布（Block）")
    lines.append("")
    lines.append("| 类别 | 数量 |")
    lines.append("|------|------|")
    if cats:
        for cat, v in sorted(cats.items(), key=lambda x: -x[1]):
            lines.append(f"| {_cat_label(cat)} | {v:,} |")
    else:
        lines.append("| 无数据 | - |")
    lines.append("")

    # ── 按源贡献 ──
    lines.append("## 四、按源贡献分析（独占 vs 共享）")
    lines.append("")
    lines.append(
        "> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。"
    )
    lines.append("")
    lines.append("| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |")
    lines.append("|------|---------|---------|--------|---------|-----------|--------|")
    if contributions:
        for c in contributions[:25]:
            eff = c.get("effective_rules", c["unique_rules"] + c["shared_rules"])
            cov = c.get("coverage_rate", (eff / c["raw_rules"] * 100) if c["raw_rules"] else 0.0)
            uniq_rate = c.get("unique_rate", (c["unique_rules"] / eff * 100) if eff else 0.0)
            lines.append(
                f"| {_cell(c['name'])} | {c['raw_rules']:,} | {eff:,} | {cov:.1f}% | {c['unique_rules']:,} | {c['shared_rules']:,} | {uniq_rate:.1f}% |"
            )
    else:
        lines.append("| 无数据 | - | - | - | - | - | - |")
    lines.append("")

    # ── 源间重复矩阵 ──
    lines.append("## 五、源间重复矩阵（两两重复规则数 + 重复率）")
    lines.append("")
    lines.append(
        "> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）"
    )
    lines.append("")
    m = _build_matrix(source_overlap)
    m_order, m_eff, m_get = m["order"], m["effective"], m["get"]
    if m_order:
        m_num = {name: i + 1 for i, name in enumerate(m_order)}
        header = "| # | " + " | ".join(str(m_num[n]) for n in m_order) + " |"
        sep = "|---|" + "---|" * len(m_order)
        lines.append(header)
        lines.append(sep)
        for row_name in m_order:
            row_cells = []
            for col_name in m_order:
                if row_name == col_name:
                    row_cells.append(f"**{m_eff.get(row_name, 0):,}**")
                    continue
                cell = m_get(row_name, col_name)
                if not cell:
                    row_cells.append("·")
                    continue
                jac = cell["jaccard"]
                row_cells.append(f"{_dup_emoji(jac)} {cell['overlap']:,} ({jac}%)")
            lines.append(f"| **{m_num[row_name]}** | " + " | ".join(row_cells) + " |")
        lines.append("")
        lines.append("**源编号对照**（按输出覆盖降序）")
        lines.append("")
        lines.append("| # | 源 | 输出覆盖 |")
        lines.append("|---|---|----------|")
        for name in m_order:
            lines.append(f"| {m_num[name]} | {_cell(name)} | {m_eff.get(name, 0):,} |")
        lines.append("")

    lines.append("### 源间重复 Top 20（双向覆盖率明细）")
    lines.append("")
    lines.append("> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。")
    lines.append("")
    lines.append("| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |")
    lines.append("|------|------|-----------|--------|---------|---------|")
    for p in overlap_pairs[:20]:
        jac = p.get("jaccard", 0.0)
        lines.append(
            f"| {_cell(p['source_a'])} | {_cell(p['source_b'])} | {p['overlap']:,} | {_dup_emoji(jac)} {jac}% | {p['rate_a']:.1f}% | {p['rate_b']:.1f}% |"
        )
    if not overlap_pairs:
        lines.append("| - | - | - | - | - | - |")
    lines.append("")

    # ── 各源自去重率 ──
    lines.append("## 六、各源自去重率")
    lines.append("")
    lines.append(
        "> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。"
    )
    lines.append("")
    lines.append("| 源 | 原始规则 | 去重后有效 | 自去重率 |")
    lines.append("|------|---------|-----------|---------|")
    if source_effective:
        for name, eff in source_effective.items():
            c = contrib_by_name.get(name, {})
            raw = c.get("raw_rules", 0)
            self_dedup = (1 - eff / raw) * 100 if raw else 0
            lines.append(f"| {_cell(name)} | {raw:,} | {eff:,} | {self_dedup:.1f}% |")
    else:
        lines.append("| 无数据 | - | - | - |")
    lines.append("")

    # ── 冲突分析 ──
    lines.append("## 七、冲突分析（白名单覆盖拦截）")
    lines.append("")
    lines.append(
        f"> 与白名单重叠的拦截规则（blocks-preserved 政策：拦截规则保留输出、白名单单独成文件，此处仅记录重叠明细；仅显示前 50 条 / 共 {getattr(outcome, 'conflict_resolved', 0):,} 条）。展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域，通配符=白名单通配父域（`*.parent`）覆盖子域。完整清单见 output/conflicts.json。"
    )
    lines.append("")
    lines.append("| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |")
    lines.append("|------|---------|---------|-----------|-----------|------|")
    for c in (getattr(outcome, "conflicts", []) or [])[:50]:
        blocked_srcs = ", ".join(c.get("blocked_sources", [])) or c.get("source", "-")
        allow_srcs = ", ".join(c.get("whitelist_sources", [])) or "-"
        ctype = {"cascade": "级联", "wildcard": "通配符"}.get(
            c.get("conflict_type", "exact"), "精确"
        )
        lines.append(
            f"| `{_cell(c.get('domain', ''))}` | `{_cell(c.get('blocked_rule', ''))}` | {_cell(blocked_srcs)} | `{_cell(c.get('whitelist_rule', ''))}` | {_cell(allow_srcs)} | {ctype} |"
        )
    if not (getattr(outcome, "conflicts", []) or []):
        lines.append("| - | - | - | - | - | - |")
    lines.append("")

    # ── $ 修饰符分布 ──
    lines.append("## 八、$ 修饰符分布")
    lines.append("")
    lines.append(
        "> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。"
    )
    lines.append("")
    lines.append("| 修饰符 | 规则数 | 占比 |")
    lines.append("|--------|--------|------|")
    if modifier_stats:
        for mod, cnt in modifier_stats.items():
            pct = cnt / modifier_total * 100 if modifier_total else 0
            # `|` is a standard AdGuard modifier-value separator (dnstype=A|AAAA,
            # denyallow=a.com|b.com, client=ip|ip) — inside a GFM table row it
            # must be escaped or it splits the cell.
            disp = mod.replace("|", "\\|")
            lines.append(f"| `${disp}` | {cnt:,} | {pct:.1f}% |")
    else:
        lines.append("| 无 | - | - |")
    lines.append("")

    # ── 白名单审计 ──
    lines += _render_whitelist_audit(outcome)

    # ── 语法支持度 ──
    lines.append("## 十、规则语法支持度")
    lines.append("")
    lines.append("| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |")
    lines.append("|---------|---------|------|---------|------|")
    lines.append(
        f"| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | {rt.get('domain', 0):,} |"
    )
    lines.append(
        f"| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | {rt.get('wildcard', 0):,} |"
    )
    lines.append(
        f"| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | {total_allow:,} |"
    )
    lines.append(f"| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | {rt.get('regex', 0):,} |")
    lines.append(f"| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | {rt.get('ip', 0):,} |")
    lines.append("| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |")
    lines.append(
        f"| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | {modifier_total:,} |"
    )
    lines.append(f"| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | {outcome.css_dropped:,} |")
    lines.append("")

    # ── 域名后缀 Top 20 ──
    lines.append("## 十一、域名后缀 Top 20")
    lines.append("")
    lines.append("| 后缀 | 规则数 |")
    lines.append("|------|--------|")
    if analysis["top_suffixes"]:
        for suffix, cnt in analysis["top_suffixes"]:
            lines.append(f"| {suffix} | {cnt:,} |")
    else:
        lines.append("| 无数据 | - |")
    lines.append("")

    # ── 性能指标 ──
    lines.append("## 十二、性能与诊断")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("|------|------|")
    lines.append(f"| 总耗时 | {_elapsed} |")
    lines.append(f"| 源成功率 | {outcome.sources_ok}/{outcome.sources_total} |")
    lines.append(f"| 缓存命中 | {_cache_value} |")
    lines.append(f"| 精确去重 | {outcome.exact_merged:,} |")
    lines.append(f"| 规范化去重 | {outcome.normalized_merged:,} |")
    lines.append(f"| 正则去重 | {outcome.regex_merged:,} |")
    lines.append(f"| 质量过滤丢弃 | {outcome.quality_dropped:,} |")
    lines.append(f"| 模式丢弃 | {outcome.pattern_dropped:,} |")
    lines.append(f"| CSS 丢弃 | {outcome.css_dropped:,} |")
    if getattr(outcome, "unrecognized_dropped", 0):
        lines.append(f"| 未识别行丢弃 | {outcome.unrecognized_dropped:,} |")
    if getattr(outcome, "unsupported_modifier", 0):
        lines.append(f"| 未知修饰符整条忽略 | {outcome.unsupported_modifier:,} |")
    lines.append(f"| 本次新增域名 | {len(outcome.added):,} |")
    lines.append(f"| 本次移除域名 | {len(outcome.removed):,} |")
    lines.append(f"| 平均域名长度 | {analysis['avg_domain_length']:.1f} 字符 |")
    lines.append(
        f"| 最短/最长域名 | {analysis['min_domain_length']} / {analysis['max_domain_length']} 字符 |"
    )
    lines.append("")

    # ── 与上次合并对比 ──
    added = getattr(outcome, "added", []) or []
    removed = getattr(outcome, "removed", []) or []
    if added or removed:
        lines.append("### 🔄 与上次合并对比")
        lines.append("")
        lines.append(f"- 🟢 **新增 {len(added):,} 条**拦截域名")
        lines.append(f"- 🔴 **移除 {len(removed):,} 条**拦截域名")
        lines.append(f"- 📊 **净变化**：{len(added) - len(removed):+,d} 条")
        lines.append("")
        if added:
            lines.append("**新增域名示例（前 20 条）：**")
            lines.append("")
            for d in added[:20]:
                lines.append(f"  - `{d}`")
            if len(added) > 20:
                lines.append(f"  - … 共 {len(added)} 条，完整列表见 output/added.txt")
            lines.append("")
        if removed:
            lines.append("**移除域名示例（前 20 条）：**")
            lines.append("")
            for d in removed[:20]:
                lines.append(f"  - `{d}`")
            if len(removed) > 20:
                lines.append(f"  - … 共 {len(removed)} 条，完整列表见 output/removed.txt")
            lines.append("")

        # 三级对比：上次合并（含源）→ 本次源 → 本次合并 的源级增减
        prev_eff = getattr(outcome, "prev_source_effective", {}) or {}
        current_eff = {c["name"]: c for c in getattr(outcome, "contributions", []) or []}
        if prev_eff or current_eff:
            lines.append("**源级增减（上次合并 → 本次合并，含源）：**")
            lines.append("")
            lines.append("| 源 | 本次原始规则 | 上次输出覆盖 | 本次输出覆盖 | 变化 |")
            lines.append("|---|---:|---:|---:|---|")
            delta_names = sorted(
                set(current_eff) | set(prev_eff),
                key=lambda n: -(current_eff.get(n, {}).get("effective_rules", 0)),
            )
            for name in delta_names:
                c = current_eff.get(name)
                now = c["effective_rules"] if c else 0
                was = prev_eff.get(name, 0)
                delta = now - was
                status = (
                    "本轮缺失"
                    if c is None
                    else ("新增源" if name not in prev_eff else f"{delta:+,}")
                )
                raw = c.get("raw_rules", 0) if c else 0
                lines.append(f"| {_cell(name)} | {raw:,} | {was:,} | {now:,} | {status} |")
            lines.append("")

    # 历史波动（仅 timestamped 模式：history 每次运行都变）
    if include_time:
        snaps = list(getattr(outcome, "prev_history", []) or [])
        snaps.append(
            {
                "timestamp": _generation_label(True)[:19].replace("T", " "),
                "block_count": len(blocks),
                "allow_count": len(allows),
                "added": len(getattr(outcome, "added", []) or []),
                "removed": len(getattr(outcome, "removed", []) or []),
                "sources_ok": getattr(outcome, "sources_ok", 0),
                "sources_total": getattr(outcome, "sources_total", 0),
            }
        )
        if len(snaps) > 1:
            lines.append("### 📈 历史波动（最近 12 次运行）")
            lines.append("")
            lines.append(
                "> 规则规模与增减量的运行间波动，取自 output/history.json（仅 report_timestamp 模式记录）。"
            )
            lines.append("")
            lines.append("| 运行时间 | Block | Allow | 新增 | 移除 | 源成功 |")
            lines.append("|---|---:|---:|---:|---:|---|")
            for s in snaps[-12:]:
                lines.append(
                    f"| {s.get('timestamp', '?')} | {s.get('block_count', 0):,} | "
                    f"{s.get('allow_count', 0):,} | {s.get('added', 0):,} | "
                    f"{s.get('removed', 0):,} | {s.get('sources_ok', 0)}/{s.get('sources_total', 0)} |"
                )
            lines.append("")

    lines.append("---")
    lines.append(f"*AdGuard Rules Merger V8 · 自动生成 · {_footer_stamp}*")
    lines.append("")
    return "\n".join(lines)
