"""HTML report renderer (overlap matrix, layer table, self-contained charts).

The distribution charts are rendered as pure-CSS bars (Item4/5, Doubao), so
the report is fully self-contained: no CDN, no ECharts script, no
``typeof echarts`` guard and no network access needed — the same data is also
present in the tables.
"""

from __future__ import annotations

from html import escape as _esc

from ..domain_classifier import CATEGORY_LABELS, CATEGORY_ORDER
from .analysis import (
    _STAGE_ORDER,
    _build_matrix,
    _cat_label,
    _defense_layer_rows,
    _dup_color,
    _dup_legend_html,
    _format_stage_time,
    _generation_label,
    _modifier_total,
    _overlap_heat_color,
)


def _render_audit_fragments(outcome, audit_summary, source_overlap, overlap_pairs, contributions):
    # V5: whitelist audit rows
    whitelist_audit = getattr(outcome, "whitelist_audit", {}) or {}
    audit_rules = whitelist_audit.get("rules", [])
    audit_rows = ""
    rating_tag = {
        "malicious": "tag-red",
        "suspicious": "tag-yellow",
        "safe": "tag-green",
        "unknown": "tag-blue",
    }
    rating_label = {
        "malicious": "🔴 恶意",
        "suspicious": "🟡 可疑",
        "safe": "🟢 安全",
        "unknown": "⚪ 未知",
    }
    for r in audit_rules:
        tag_cls = rating_tag.get(r["rating"], "tag-blue")
        label = rating_label.get(r["rating"], r["rating"])
        cat_label = CATEGORY_LABELS.get(r.get("category", "other"), r.get("category", "other"))
        conf = r.get("category_confidence", 0)
        conf_cls = "tag-green" if conf >= 0.9 else ("tag-yellow" if conf >= 0.6 else "tag-blue")
        risk = r.get("risk_score", 0)
        rec = r.get("recommendation_label", "")
        audit_rows += (
            f"<tr><td><code>{_esc(r['domain'])}</code></td>"
            f"<td><span class='tag {tag_cls}'>{label}</span></td>"
            f"<td>{_esc(str(cat_label))}</td>"
            f"<td class='num'>{risk}</td>"
            f"<td>{_esc(rec)}</td>"
            f"<td><span class='tag {conf_cls}'>{conf:.2f}</span></td>"
            f"<td>{_esc(r['reason'])}</td>"
            f"<td>{_esc(', '.join(r.get('sources', [])))}</td></tr>\n"
        )
    if not audit_rows and whitelist_audit:
        audit_rows = (
            '<tr><td colspan="8" class="empty-state">白名单审计未启用或无域名规则</td></tr>'
        )

    # V5: whitelist category distribution rows
    cat_counts = audit_summary.get("category_counts", {})
    cat_rows = ""
    if cat_counts:
        total_cat = sum(cat_counts.values()) or 1
        for cat in CATEGORY_ORDER:
            cnt = cat_counts.get(cat, 0)
            if cnt == 0:
                continue
            pct = cnt / total_cat * 100
            label = CATEGORY_LABELS.get(cat, cat)
            cat_rows += (
                f"<tr><td>{label}</td><td>{cnt}</td>"
                f"<td><div class='bar-bg'><div class='bar-fill' style='width:{pct:.1f}%'></div></div></td>"
                f"<td>{pct:.1f}%</td></tr>\n"
            )
    if not cat_rows:
        cat_rows = '<tr><td colspan="4" class="empty-state">分类统计不可用</td></tr>'

    # V5: classification confidence distribution
    conf_dist = audit_summary.get("category_confidence", {})
    conf_rows = ""
    if conf_dist:
        total_conf = sum(conf_dist.values()) or 1
        for level in ("high(>=0.9)", "medium(0.6-0.89)", "low(<0.6)"):
            cnt = conf_dist.get(level, 0)
            pct = cnt / total_conf * 100
            label = {
                "high(>=0.9)": "高置信度 (注册域名匹配)",
                "medium(0.6-0.89)": "中置信度 (子域名前缀)",
                "low(<0.6)": "低置信度 (无法分类)",
            }.get(level, level)
            conf_rows += (
                f"<tr><td>{label}</td><td>{cnt}</td>"
                f"<td><div class='bar-bg'><div class='bar-fill' style='width:{pct:.1f}%'></div></div></td>"
                f"<td>{pct:.1f}%</td></tr>\n"
            )

    # V5: multi-layer defense overview
    layers_enabled = audit_summary.get("layers_enabled", {})
    layer_hits = audit_summary.get("layer_hits", {})
    layer_rows = ""
    if layers_enabled:
        for row in _defense_layer_rows(layers_enabled, layer_hits):
            layer_rows += (
                f"<tr><td>{row['name']}</td><td>{row['desc']}</td>"
                f"<td><span class='tag {row['status_cls']}'>{row['status']}</span></td>"
                f"<td>{row['cost']}</td><td class='num'>{row['hits']}</td></tr>\n"
            )

    # V5: source effective coverage rows
    source_effective = source_overlap.get("source_effective", {})
    effective_rows = ""
    contrib_by_name = {c["name"]: c for c in contributions}
    for name, eff in source_effective.items():
        c = contrib_by_name.get(name, {})
        raw = c.get("raw_rules", 0)
        self_dedup = (1 - eff / raw) * 100 if raw else 0
        effective_rows += f"<tr><td>{_esc(name)}</td><td>{raw:,}</td><td>{eff:,}</td><td>{self_dedup:.1f}%</td></tr>\n"
    if not effective_rows:
        effective_rows = '<tr><td colspan="4" class="empty-state">暂无数据</td></tr>'

    # V5: top overlap pairs (top 20)
    overlap_rows = ""
    for p in overlap_pairs[:20]:
        bg_a = _overlap_heat_color(p["rate_a"])
        bg_b = _overlap_heat_color(p["rate_b"])
        overlap_rows += (
            f"<tr><td>{_esc(p['source_a'])}</td><td>{_esc(p['source_b'])}</td>"
            f"<td>{p['overlap']:,}</td>"
            f"<td style='background:{bg_a}'>{p['rate_a']:.1f}%</td>"
            f"<td style='background:{bg_b}'>{p['rate_b']:.1f}%</td></tr>\n"
        )
    if not overlap_rows:
        overlap_rows = '<tr><td colspan="5" class="empty-state">无源间重复</td></tr>'

    # V5.2: full pairwise duplicate matrix
    matrix = _build_matrix(source_overlap)
    m_order = matrix["order"]
    m_eff = matrix["effective"]
    m_get = matrix["get"]
    matrix_numbers = {name: i + 1 for i, name in enumerate(m_order)}
    matrix_legend_rows = ""
    for name in m_order:
        matrix_legend_rows += (
            f"<tr><td style='text-align:center'>{matrix_numbers[name]}</td>"
            f"<td>{_esc(name)}</td><td>{m_eff.get(name, 0):,}</td></tr>\n"
        )
    matrix_header = "<th>#</th>" + "".join(
        f"<th style='text-align:center'>{matrix_numbers[n]}</th>" for n in m_order
    )
    matrix_rows = ""
    for row_name in m_order:
        cells_html = []
        for col_name in m_order:
            if row_name == col_name:
                cells_html.append(
                    f"<td style='background:#eee;text-align:center;color:#666'>"
                    f"{m_eff.get(row_name, 0):,}</td>"
                )
                continue
            cell = m_get(row_name, col_name)
            if not cell:
                cells_html.append("<td style='text-align:center;color:#ccc'>·</td>")
                continue
            jac = cell["jaccard"]
            bg = _dup_color(jac)
            tip = (
                f"{row_name} × {col_name}：共同 {cell['overlap']:,} 条，"
                f"重复率 {jac}%（{cell['rate_a']}% / {cell['rate_b']}%）"
            )
            fg = "#fff" if jac >= 80 else "#333"
            cells_html.append(
                f"<td style='background:{bg};text-align:center;color:{fg}' title='{_esc(tip)}'>"
                f"{cell['overlap']:,}<br><small>{jac}%</small></td>"
            )
        matrix_rows += (
            f"<tr><th style='text-align:center;background:#f5f7fa'>"
            f"{matrix_numbers[row_name]}</th>" + "".join(cells_html) + "</tr>\n"
        )
    if not m_order:
        matrix_rows = '<tr><td class="empty-state">无源间重复</td></tr>'
        matrix_header = ""

    failed_html = ""
    if outcome.failed_sources:
        items = "".join(
            f"<li><b>{_esc(f['name'])}</b> — {_esc(f['error'])}</li>"
            for f in outcome.failed_sources
        )
        failed_html = f'<div class="section" style="border-left:4px solid #dc3545"><h2>⚠️ 失败源 ({len(outcome.failed_sources)})</h2><ul>{items}</ul></div>'

    return {
        "audit_rows": audit_rows,
        "cat_rows": cat_rows,
        "conf_rows": conf_rows,
        "layer_rows": layer_rows,
        "effective_rows": effective_rows,
        "overlap_rows": overlap_rows,
        "matrix_header": matrix_header,
        "matrix_legend_rows": matrix_legend_rows,
        "matrix_rows": matrix_rows,
        "failed_html": failed_html,
    }


def _render_contrib_rows(outcome) -> str:
    rows = ""
    for c in getattr(outcome, "contributions", [])[:25]:
        eff = c.get("effective_rules", c["unique_rules"] + c["shared_rules"])
        cov = c.get("coverage_rate", (eff / c["raw_rules"] * 100) if c["raw_rules"] else 0.0)
        uniq_rate = c.get("unique_rate", (c["unique_rules"] / eff * 100) if eff else 0.0)
        rows += (
            f"<tr><td>{_esc(c['name'])}</td><td>{c['raw_rules']:,}</td>"
            f"<td>{eff:,}</td><td>{cov:.1f}%</td>"
            f"<td>{c['unique_rules']:,}</td><td>{c['shared_rules']:,}</td>"
            f"<td>{uniq_rate:.1f}%</td></tr>\n"
        )
    return rows or '<tr><td colspan="7" class="empty-state">暂无数据</td></tr>'


def _render_modifier_rows(modifier_stats, modifier_total) -> str:
    rows = ""
    if modifier_stats:
        for mod, cnt in modifier_stats.items():
            pct = cnt / modifier_total * 100 if modifier_total else 0
            # P0 hardening: the modifier VALUE part is raw upstream-list text
            # (only the key is normalized), so it must be escaped before it is
            # interpolated into report.html — an unescaped `$dnsrewrite=...`
            # value was a stored-XSS vector committed to the repo.
            rows += (
                f"<tr><td><code>${_esc(mod)}</code></td><td>{cnt:,}</td><td>{pct:.1f}%</td></tr>\n"
            )
    return rows or '<tr><td colspan="3" class="empty-state">无带修饰符规则</td></tr>'


def _render_conflict_rows(outcome) -> str:
    rows = ""
    for c in (getattr(outcome, "conflicts", []) or [])[:50]:
        blocked_srcs = ", ".join(c.get("blocked_sources", [])) or c.get("source", "-")
        allow_srcs = ", ".join(c.get("whitelist_sources", [])) or "-"
        ctype = c.get("conflict_type", "exact")
        ctype_tag = {"cascade": "级联", "wildcard": "通配符"}.get(ctype, "精确")
        rows += (
            f"<tr><td><code>{_esc(c.get('domain', ''))}</code></td>"
            f"<td><code>{_esc(c.get('blocked_rule', ''))}</code></td>"
            f"<td>{_esc(blocked_srcs)}</td>"
            f"<td><code>{_esc(c.get('whitelist_rule', ''))}</code></td>"
            f"<td>{_esc(allow_srcs)}</td>"
            f"<td><span class='tag tag-yellow'>{ctype_tag}</span></td></tr>\n"
        )
    return rows or '<tr><td colspan="6" class="empty-state">无冲突</td></tr>'


def _render_stage_timing_rows(stage_timings: dict[str, float]) -> str:
    """Render per-stage elapsed-time rows with a share-of-total bar.

    Renders in fixed pipeline order (from _STAGE_ORDER); any unknown keys
    not in the predefined order are appended at the end.
    """
    if not stage_timings:
        return '<tr><td colspan="4" class="empty-state">无阶段耗时数据</td></tr>'
    total = max(sum(stage_timings.values()), 1e-9)
    rows = ""
    rendered_keys: set[str] = set()

    # Render in fixed predefined order first
    for key, label in _STAGE_ORDER:
        if key in stage_timings:
            secs = stage_timings[key]
            pct = secs / total * 100
            bar_w = min(100.0, pct)
            rows += (
                f"<tr><td>{label}</td>"
                f"<td class='num'>{_format_stage_time(secs)}</td>"
                f"<td class='num'>{pct:.1f}%</td>"
                f"<td class='bar-cell'><div class='bar' style='width:{bar_w:.1f}%'></div></td></tr>\n"
            )
            rendered_keys.add(key)

    # Append any unknown keys not in predefined order
    for key, secs in stage_timings.items():
        if key not in rendered_keys:
            pct = secs / total * 100
            bar_w = min(100.0, pct)
            rows += (
                f"<tr><td>{key}</td>"
                f"<td class='num'>{_format_stage_time(secs)}</td>"
                f"<td class='num'>{pct:.1f}%</td>"
                f"<td class='bar-cell'><div class='bar' style='width:{bar_w:.1f}%'></div></td></tr>\n"
            )

    # total row
    total_ms = sum(stage_timings.values()) * 1000
    total_str = f"{total_ms:.1f} ms" if total_ms >= 1.0 else f"{total_ms * 1000:.0f} µs"
    rows += (
        f"<tr class='total-row'><td>合计</td>"
        f"<td class='num'>{total_str}</td>"
        f"<td class='num'>100.0%</td>"
        f"<td class='bar-cell'><div class='bar bar-total' style='width:100%'></div></td></tr>\n"
    )
    return rows


def _render_source_delta_rows(outcome) -> str:
    """Per-source effective-coverage delta vs the previous run (三级对比).

    Current side comes from ``outcome.contributions``; the previous side from
    ``outcome.prev_source_effective`` (loaded by the diff stage). Sources seen
    only in one run are flagged 新增 / 已移除.
    """
    current = {c["name"]: c for c in getattr(outcome, "contributions", []) or []}
    prev = getattr(outcome, "prev_source_effective", {}) or {}
    rows = ""
    names = sorted(
        set(current) | set(prev), key=lambda n: (-(current.get(n, {}).get("effective_rules", 0)), n)
    )
    for name in names:
        c = current.get(name)
        now = c["effective_rules"] if c else 0
        raw = c.get("raw_rules", 0) if c else 0
        was = prev.get(name, 0)
        delta = now - was
        if c is None:
            status = "<span class='tag tag-blue'>本轮缺失</span>"
        elif name not in prev:
            status = "<span class='tag tag-green'>新增源</span>"
        elif delta == 0:
            status = "—"
        else:
            cls = "tag-green" if delta > 0 else "tag-red"
            sign = "+" if delta > 0 else ""
            status = f"<span class='tag {cls}'>{sign}{delta:,}</span>"
        cov = c.get("coverage_rate", 0.0) if c else 0.0
        rows += (
            f"<tr><td>{_esc(name)}</td><td class='num'>{raw:,}</td>"
            f"<td class='num'>{was:,}</td><td class='num'>{now:,}</td>"
            f"<td>{status}</td><td class='num'>{cov:.1f}%</td></tr>\n"
        )
    return rows


def _render_history_trend_rows(outcome) -> str:
    """Historical fluctuation table from the previous history.json snapshots
    (plus this run as the newest row). Renders only in timestamped mode — the
    history log changes on every run, which would break byte determinism."""
    snaps = list(getattr(outcome, "prev_history", []) or [])
    snaps.append(
        {
            "timestamp": _generation_label(True)[:19].replace("T", " "),
            "block_count": len(getattr(outcome, "blocks", []) or []),
            "allow_count": len(getattr(outcome, "allows", []) or []),
            "added": len(getattr(outcome, "added", []) or []),
            "removed": len(getattr(outcome, "removed", []) or []),
            "sources_ok": getattr(outcome, "sources_ok", 0),
            "sources_total": getattr(outcome, "sources_total", 0),
            "current": True,
        }
    )
    snaps = snaps[-12:]
    max_total = (
        max((s.get("block_count", 0) + s.get("allow_count", 0) for s in snaps), default=1) or 1
    )
    rows = ""
    for s in snaps:
        total = s.get("block_count", 0) + s.get("allow_count", 0)
        w = max(2.0, total / max_total * 100)
        stamp = _esc(str(s.get("timestamp", "?")))
        label = "本轮" if s.get("current") else ""
        rows += (
            f"<tr><td>{stamp} {label}</td>"
            f"<td class='num'>{s.get('block_count', 0):,}</td>"
            f"<td class='num'>{s.get('allow_count', 0):,}</td>"
            f"<td class='bar-cell'><div class='bar' style='width:{w:.1f}%'></div></td>"
            f"<td class='num'>{s.get('added', 0):,}</td>"
            f"<td class='num'>{s.get('removed', 0):,}</td>"
            f"<td class='num'>{s.get('sources_ok', 0)}/{s.get('sources_total', 0)}</td></tr>\n"
        )
    return rows


def generate_html_report(blocks, allows, outcome, analysis, include_time: bool = False) -> str:
    generated_at = _generation_label(include_time)
    # R6: the previous-run diff is CONTENT-derived (added/removed rule lists
    # come from comparing rule sets), so it renders in deterministic mode too —
    # same rule set ⇒ same bytes. Only run-fact decorations stay behind
    # include_time.
    _added_list = getattr(outcome, "added", []) or []
    _removed_list = getattr(outcome, "removed", []) or []
    diff_section = ""
    if _added_list or _removed_list:
        _net = len(_added_list) - len(_removed_list)
        _diff_rows = ""
        if _added_list:
            _sample = "".join(f"<li><code>{d}</code></li>" for d in _added_list[:20])
            _more = (
                f'<p class="note">… 共 {len(_added_list):,} 条，完整列表见 output/added.txt</p>'
                if len(_added_list) > 20
                else ""
            )
            _diff_rows += f'<h3 style="color:#28a745">🟢 新增 {len(_added_list):,} 条拦截域名</h3><ul style="columns:2;column-gap:30px">{_sample}</ul>{_more}'
        if _removed_list:
            _sample = "".join(f"<li><code>{d}</code></li>" for d in _removed_list[:20])
            _more = (
                f'<p class="note">… 共 {len(_removed_list):,} 条，完整列表见 output/removed.txt</p>'
                if len(_removed_list) > 20
                else ""
            )
            _diff_rows += f'<h3 style="color:#dc3545">🔴 移除 {len(_removed_list):,} 条拦截域名</h3><ul style="columns:2;column-gap:30px">{_sample}</ul>{_more}'
        # 三级对比：上次合并（含源）→ 本次源 → 本次合并 的源级增减
        _src_delta_rows = _render_source_delta_rows(outcome)
        _src_delta = ""
        if _src_delta_rows:
            _src_delta = (
                '<h3 style="margin:18px 0 8px">📊 源级增减（上次合并 → 本次合并，含源）</h3>'
                '<div class="table-wrap"><table>'
                "<thead><tr><th>源</th><th class='num'>本次原始规则</th>"
                "<th class='num'>上次输出覆盖</th><th class='num'>本次输出覆盖</th>"
                "<th>变化</th><th class='num'>覆盖率</th></tr></thead>"
                f"<tbody>{_src_delta_rows}</tbody></table></div>"
                '<p class="note">输出覆盖 = 该源参与最终规则的条数（独占+共享，含聚合折叠归并）；'
                '"本轮缺失" = 上次运行存在的源本次未出现或失败。与上方规则级 新增/移除 对照，可定位变化来自哪个源。</p>'
            )
        diff_section = (
            '\n  <div class="section" id="diff-compare">\n'
            '    <h2><span class="sec-no">14</span>🔄 与上次合并对比（规则级 + 源级）</h2>\n'
            f'    <p class="sec-intro">相对上次合并的规则集变化。净变化：<strong>{_net:+,d}</strong> 条拦截规则。'
            "对比基线：<code>diff_against</code> 指向的上一次 output 目录。</p>\n"
            f"    {_diff_rows}\n    {_src_delta}\n"
            "  </div>\n"
        )

    if include_time:
        _meta_stamp = f"合并时间 {generated_at[:19].replace('T', ' ')}"
        _elapsed_value = f"{outcome.elapsed:.1f}s"

        # 各阶段执行耗时
        stage_timings = getattr(outcome, "stage_timings", {}) or {}
        stage_rows = _render_stage_timing_rows(stage_timings)
        stage_sum_ms = sum(stage_timings.values()) * 1000

        # 历史波动（仅 timestamped 模式：history 每次运行都变，嵌入会破坏字节确定性）
        _trend_rows = _render_history_trend_rows(outcome)
        history_section = (
            '\n  <div class="section" id="history-trend">\n'
            '    <h2><span class="sec-no">15</span>📈 历史波动（最近 12 次运行）</h2>\n'
            '    <p class="sec-intro">规则规模与增减量的运行间波动，取自 output/history.json 趋势日志'
            "（仅 report_timestamp 模式记录/渲染，保持确定性产物稳定）。柱长 = 规则总量相对峰值。</p>\n"
            '    <div class="table-wrap"><table>'
            "<thead><tr><th>运行时间</th><th class='num'>Block</th><th class='num'>Allow</th>"
            "<th>规模（相对峰值）</th><th class='num'>新增</th><th class='num'>移除</th>"
            "<th class='num'>源成功</th></tr></thead>"
            f"<tbody>{_trend_rows}</tbody></table></div>\n  </div>\n"
        )
        toc_history_li = '<li><a href="#history-trend">15 · 历史波动</a></li>'

        _footer_stamp = generated_at[:10]
        _cache_value = str(outcome.sources_cached)
        _cache_meta = f" | 缓存：{outcome.sources_cached}"
        _merge_time_card = (
            f'<div class="stat-card"><div class="value">'
            f"{generated_at[:19].replace('T', ' ')}</div>"
            "<div class='label'>合并时间</div></div>"
        )
    else:
        _meta_stamp = f"内容版本 {outcome.content_version}"
        # Always show the real wall-clock elapsed (not "—"); the timestamp
        # line stays deterministic-optional via report_timestamp, but the
        # elapsed figure is a run fact and should never read as zero/missing.
        _elapsed_value = f"{outcome.elapsed:.1f}s"
        _footer_stamp = f"内容版本 {outcome.content_version}"
        _cache_value = "—"
        _cache_meta = ""
        _merge_time_card = ""
        stage_rows = ""
        stage_sum_ms = 0.0
        history_section = ""
        toc_history_li = ""
    total_block = len(blocks)
    total_allow = len(allows)
    raw_count = outcome.raw_count
    dedup_rate = (1 - (total_block + total_allow) / raw_count) * 100 if raw_count else 0
    cats = analysis["categories"]
    top_suffix_labels = [s[0] for s in analysis["top_suffixes"]]
    top_suffix_values = [s[1] for s in analysis["top_suffixes"]]
    cat_chart_labels = [_cat_label(k) for k in cats]
    cat_chart_values = [cats[k] for k in cats]
    rt = analysis["rule_types"]
    domain_count = rt.get("domain", 0)
    wildcard_count = rt.get("wildcard", 0)
    regex_count = rt.get("regex", 0)
    ip_count = rt.get("ip", 0)
    modifier_stats = getattr(outcome, "modifier_stats", {}) or {}
    modifier_total = _modifier_total(modifier_stats)
    mod_rule_count = sum(1 for r in blocks if r.modifiers) + sum(1 for r in allows if r.modifiers)
    dedup_steps = (
        getattr(outcome, "exact_merged", 0)
        + getattr(outcome, "normalized_merged", 0)
        + getattr(outcome, "regex_merged", 0)
    )
    pure_dedup_rate = (dedup_steps / raw_count * 100) if raw_count else 0
    source_overlap = getattr(outcome, "source_overlap", {}) or {}
    overlap_pairs = source_overlap.get("pairs", [])

    contrib_rows = _render_contrib_rows(outcome)

    modifier_rows = _render_modifier_rows(modifier_stats, modifier_total)

    conflict_rows = _render_conflict_rows(outcome)

    # R7: source-side census table (complete picture incl. removed rules)
    _census = getattr(outcome, "modifier_stats_sources", {}) or {}
    _census_total = sum(_census.values())
    if _census:
        _census_rows = "".join(
            f"<tr><td><code>${_esc(mod)}</code></td><td>{cnt:,}</td>"
            f"<td>{cnt / _census_total * 100:.1f}%</td></tr>\n"
            for mod, cnt in sorted(_census.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        _census_block = (
            '<h3 style="margin:14px 0 8px">🔎 源侧修饰符普查（合并移除前，全量）</h3>'
            '<div class="table-wrap"><table>'
            "<thead><tr><th>修饰符</th><th class='num'>token 数</th><th class='num'>占比</th></tr></thead>"
            f"<tbody>{_census_rows}</tbody></table></div>"
        )
    else:
        _census_block = ""

    # V5: whitelist audit setup
    contributions = getattr(outcome, "contributions", [])
    whitelist_audit = getattr(outcome, "whitelist_audit", {}) or {}
    audit_summary = whitelist_audit.get("summary", {})
    cat_counts = audit_summary.get("category_counts", {})
    conf_dist = audit_summary.get("category_confidence", {})

    # V8.3: per-stage elapsed times — only when timestamped (byte-stable otherwise).
    # (computed inside the include_time block below)

    # V5/V5.2: audit tables, source-overlap matrix, failed-source banner
    _audit_frag = _render_audit_fragments(
        outcome, audit_summary, source_overlap, overlap_pairs, contributions
    )
    audit_rows = _audit_frag["audit_rows"]
    cat_rows = _audit_frag["cat_rows"]
    conf_rows = _audit_frag["conf_rows"]
    layer_rows = _audit_frag["layer_rows"]
    effective_rows = _audit_frag["effective_rows"]
    overlap_rows = _audit_frag["overlap_rows"]
    matrix_header = _audit_frag["matrix_header"]
    matrix_legend_rows = _audit_frag["matrix_legend_rows"]
    matrix_rows = _audit_frag["matrix_rows"]
    failed_html = _audit_frag["failed_html"]

    badfilter_removed = getattr(outcome, "badfilter_removed", 0) or 0
    promoted_groups = getattr(outcome, "wildcard_promoted_groups", 0) or 0
    dedup = outcome.exact_merged + outcome.normalized_merged + outcome.regex_merged
    after_dedup = raw_count - dedup
    after_badfilter = after_dedup - badfilter_removed
    # Aggregation net removal: exact/wildcard folds drop a child outright, but
    # wildcard promotion absorbs N children AND adds one new wildcard parent per
    # group — so the net reduction subtracts the parents created.
    agg_net = (
        outcome.aggregated
        + outcome.wildcard_aggregated
        + outcome.wildcard_promoted
        - promoted_groups
    )
    after_agg = after_badfilter - agg_net

    # Funnel proportional bars (restored from v7 CSS funnel): each step's bar
    # width = its count / raw_count. Data口径 unchanged; only the visual bar
    # is added on top of the existing step rows.
    def _funnel_w(n: int) -> float:
        return max(2.0, n / raw_count * 100) if raw_count else 0.0

    funnel_steps = [
        ("原始规则（Raw）", raw_count, "-"),
        (
            f"去重后（精确 {outcome.exact_merged:,} / 规范化 {outcome.normalized_merged:,} / 正则 {outcome.regex_merged:,}）",
            after_dedup,
            f"-{dedup:,}",
        ),
        (
            "badfilter 取消后（被 $badfilter 取消的规则）",
            after_badfilter,
            f"-{badfilter_removed:,}",
        ),
        (
            f"聚合后（净：折叠 {outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted - promoted_groups:,}）",
            after_agg,
            f"-{agg_net:,}",
        ),
        (
            "冲突消解后（最终输出）",
            total_block + total_allow,
            f"-{outcome.conflict_resolved:,}",
        ),
    ]
    funnel_html = ""
    for name, cnt, diff in funnel_steps:
        w = _funnel_w(cnt)
        funnel_html += (
            f'<div class="funnel-step"><div class="step-name">{name}</div>'
            f'<div class="step-bar"><div class="bar-fill" style="width:{w:.1f}%"></div></div>'
            f'<div class="step-count">{cnt:,}</div><div class="step-diff">{diff}</div></div>\n'
        )

    # U-1: compact executive summary (3-5 takeaways) at the top of the report.
    compression_pct = (1 - (total_block + total_allow) / raw_count) * 100 if raw_count else 0.0
    _summary_items: list[str] = []
    if outcome.failed_sources:
        names = ", ".join(f.get("name", "?") for f in outcome.failed_sources[:3])
        more = "…" if len(outcome.failed_sources) > 3 else ""
        _summary_items.append(
            f"<li>⚠️ <strong>{len(outcome.failed_sources)} 个源失败</strong>：{_esc(names)}{more}</li>"
        )
    _summary_items.append(
        f"<li>最终输出 <strong>{total_block:,}</strong> 条 Block + <strong>{total_allow:,}</strong> 条 Allow"
        f"（原始 {raw_count:,}，压缩 <strong>-{compression_pct:.0f}%</strong>）</li>"
    )
    if outcome.conflict_resolved:
        _summary_items.append(
            f"<li>⚔️ <strong>{outcome.conflict_resolved:,}</strong> 条拦截规则与白名单重叠（拦截保留）</li>"
        )
    _added = getattr(outcome, "added", None)
    _removed = getattr(outcome, "removed", None)
    if _added is not None or _removed is not None:
        _summary_items.append(
            f"<li>🔁 相对 diff：新增 {len(_added or []):,} / 移除 {len(_removed or []):,} 域名</li>"
        )
    _summary_html = (
        '<div class="section" id="summary"><h2>✨ 执行摘要</h2><ul class="summary-list">'
        + "".join(_summary_items)
        + "</ul></div>"
    )

    # Item4/5 (Doubao): self-contained CSS bar charts (offline, no CDN) —
    # replaces the external chart library + script with pure-CSS bars so the
    # report is fully self-contained and needs no network access.
    def _bar(label, cnt, pct, color="#3282b8"):
        return (
            f'<div style="display:flex;align-items:center;margin:6px 0">'
            f'<div style="width:110px;font-size:.85em">{_esc(label)}</div>'
            f'<div style="flex:1;background:#eef2f7;border-radius:4px;height:16px">'
            f'<div style="width:{max(1.0, pct):.1f}%;background:{color};height:16px;border-radius:4px"></div></div>'
            f'<div style="width:70px;text-align:right;font-size:.85em">{cnt:,}</div></div>'
        )

    total_rt = max(1, domain_count + wildcard_count + regex_count + ip_count)
    rule_type_bars = "\n".join(
        [
            _bar("普通域名", domain_count, domain_count / total_rt * 100, "#3282b8"),
            _bar("通配符", wildcard_count, wildcard_count / total_rt * 100, "#6ab04c"),
            _bar("正则", regex_count, regex_count / total_rt * 100, "#f0932b"),
            _bar("IP", ip_count, ip_count / total_rt * 100, "#9b59b6"),
        ]
    )
    max_cat = max(cat_chart_values or [1])
    cat_bars = "\n".join(
        _bar(cat_chart_labels[i], cat_chart_values[i], cat_chart_values[i] / max_cat * 100)
        for i in range(len(cat_chart_labels))
        if cat_chart_values[i]
    )
    max_suf = max(top_suffix_values or [1])
    suffix_bars = "\n".join(
        _bar(top_suffix_labels[i], top_suffix_values[i], top_suffix_values[i] / max_suf * 100)
        for i in range(len(top_suffix_labels))
    )

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AdGuard Rules Merger V8 - 规则分析报告</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f5f7fa; color:#333; line-height:1.6; }}
.container {{ max-width:1280px; margin:0 auto; padding:20px; }}
.header {{ background:linear-gradient(135deg,#0f4c75 0%,#3282b8 100%); color:#fff; padding:40px; border-radius:12px; margin-bottom:30px; }}
.header h1 {{ font-size:2.2em; margin-bottom:8px; }}
.header .subtitle {{ opacity:.9; font-size:1.1em; }}
.header .meta {{ margin-top:15px; font-size:.9em; opacity:.8; }}
.stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:30px; }}
.stat-card {{ background:#fff; padding:20px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); text-align:center; border-top:3px solid #3282b8; }}
.stat-card .value {{ font-size:1.7em; font-weight:700; color:#3282b8; font-variant-numeric:tabular-nums; }}
.stat-card .label {{ color:#666; font-size:.82em; margin-top:4px; }}
.bar-bg {{ background:#eef2f7; border-radius:4px; height:18px; overflow:hidden; min-width:80px; }}
.bar-fill {{ background:linear-gradient(90deg,#3282b8,#5ba3d9); height:100%; border-radius:4px; }}
.bar-cell {{ min-width:170px; }}
.bar {{ height:12px; background:#3282b8; border-radius:3px; display:inline-block; }}
.bar-total {{ background:#7d5ba6; }}
.total-row td {{ font-weight:700; border-top:2px solid #dde3ea; }}
.section {{ background:#fff; padding:25px; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); margin-bottom:25px; scroll-margin-top:12px; }}
.section h2 {{ margin-bottom:14px; color:#0f4c75; border-left:4px solid #3282b8; padding-left:15px; font-size:1.3em; }}
.sec-no {{ display:inline-block; min-width:2.4em; color:#3282b8; font-weight:700; margin-right:4px; }}
.sec-intro {{ font-size:.88em; color:#666; margin:0 0 14px; }}
.toc {{ background:#fff; border-radius:10px; box-shadow:0 2px 8px rgba(0,0,0,.06); padding:14px 20px; margin-bottom:25px; }}
.toc summary {{ cursor:pointer; font-weight:600; color:#0f4c75; }}
.toc ol {{ margin:10px 0 0 22px; columns:2; column-gap:32px; }}
.toc li {{ margin:4px 0; font-size:.9em; }}
.toc a {{ color:#3282b8; text-decoration:none; }}
.toc a:hover {{ text-decoration:underline; }}
.two-col {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:25px; }}
.chart {{ width:100%; height:350px; }}
.table-wrap {{ overflow-x:auto; margin-top:12px; }}
table {{ width:100%; border-collapse:collapse; font-size:.9em; }}
th,td {{ padding:9px 12px; text-align:left; border-bottom:1px solid #eee; }}
thead th {{ background:#f8f9fa; font-weight:600; color:#555; position:sticky; top:0; z-index:1; }}
tbody tr:nth-child(even) {{ background:#fafbfc; }}
tbody tr:hover {{ background:#f0f5fa; }}
.num {{ font-variant-numeric:tabular-nums; text-align:right; white-space:nowrap; }}
.empty-state {{ text-align:center; color:#999; padding:18px 12px; }}
.funnel-step {{ display:flex; align-items:center; padding:12px 15px; margin:8px 0; border-radius:8px; background:#f8f9fa; }}
.funnel-step .step-name {{ flex:1; font-weight:500; }}
.funnel-step .step-count {{ font-weight:700; color:#3282b8; font-variant-numeric:tabular-nums; }}
.funnel-step .step-diff {{ width:120px; text-align:right; color:#28a745; font-size:.9em; font-variant-numeric:tabular-nums; }}
.step-bar {{ flex:2; background:#eef2f7; border-radius:4px; height:14px; margin:0 12px; overflow:hidden; }}
.tag {{ display:inline-block; padding:2px 10px; border-radius:12px; font-size:.82em; font-weight:500; white-space:nowrap; }}
.tag-green {{ background:#d4edda; color:#155724; }}
.tag-blue {{ background:#d1ecf1; color:#0c5460; }}
.tag-yellow {{ background:#fff3cd; color:#856404; }}
.tag-red {{ background:#f8d7da; color:#721c24; }}
.footer {{ text-align:center; color:#999; padding:20px; font-size:.85em; }}
.note {{ font-size:.85em; color:#888; margin-top:8px; }}
@media(max-width:768px) {{
  .two-col {{ grid-template-columns:1fr; }}
  .toc ol {{ columns:1; }}
  .header {{ padding:22px; }}
  .header h1 {{ font-size:1.6em; }}
  .section {{ padding:16px; }}
  table {{ font-size:.82em; }}
  th,td {{ padding:7px 8px; }}
}}
@media print {{
  @page {{ margin:14mm; }}
  body {{ background:#fff; }}
  .toc {{ display:none; }}
  .header {{ background:#fff; color:#000; box-shadow:none; border-bottom:2px solid #333; }}
  .header h1, .header .subtitle, .header .meta {{ color:#000; }}
  .section {{ box-shadow:none; border:1px solid #ccc; break-inside:avoid; }}
  .stat-card {{ box-shadow:none; border:1px solid #ccc; }}
  .chart {{ break-inside:avoid; }}
  thead th {{ position:static; }}
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ AdGuard Rules Merger V8</h1>
    <div class="subtitle">专业规则合并分析报告</div>
    <div class="meta">{_meta_stamp} | 源：{outcome.sources_ok}/{outcome.sources_total}{_cache_meta}</div>
  </div>

  {failed_html}

  {_summary_html}

  <details class="toc" open>
    <summary>📑 报告目录（点击折叠 / 展开）</summary>
    <ol>
      <li><a href="#overview">01 · 概览指标</a></li>
      <li><a href="#funnel">02 · 优化流水线漏斗</a></li>
      <li><a href="#rule-types">03 · 规则类型与类别分布</a></li>
      <li><a href="#suffixes">04 · 域名后缀 Top 20</a></li>
      <li><a href="#contributions">05 · 按源贡献分析</a></li>
      <li><a href="#overlap-matrix">06 · 源间重复矩阵</a></li>
      <li><a href="#overlap-top">07 · 源间重复 Top 20</a></li>
      <li><a href="#conflicts">08 · 冲突分析</a></li>
      <li><a href="#self-dedup">09 · 各源自去重率</a></li>
      <li><a href="#modifiers">10 · $ 修饰符分布</a></li>
      <li><a href="#audit">11 · 白名单多层防御审计</a></li>
      <li><a href="#grammar">12 · 规则语法支持度</a></li>
      <li><a href="#performance">13 · 性能与诊断</a></li>
      {toc_history_li}
    </ol>
  </details>

  <div class="stats-grid" id="overview">
    <div class="stat-card"><div class="value">{total_block:,}</div><div class="label">Block 规则</div></div>
    <div class="stat-card"><div class="value">{total_allow:,}</div><div class="label">Allow 白名单</div></div>
    <div class="stat-card"><div class="value">{dedup_rate:.1f}%</div><div class="label">整体压缩率（原始→最终）</div></div>
    <div class="stat-card"><div class="value">{pure_dedup_rate:.1f}%</div><div class="label">纯去重率（去重阶段）</div></div>
    <div class="stat-card"><div class="value">{agg_net:,}</div><div class="label">聚合精简（净）</div></div>
    <div class="stat-card"><div class="value">{outcome.conflict_resolved:,}</div><div class="label">冲突消解</div></div>
    <div class="stat-card"><div class="value">{mod_rule_count:,}</div><div class="label">带 $ 修饰符规则数</div></div>
    <div class="stat-card"><div class="value">{_elapsed_value}</div><div class="label">总耗时</div></div>
    {_merge_time_card}
  </div>

  <div class="section" id="stage-timings">
    <h2><span class="sec-no">01b</span>⏱️ 各阶段执行耗时</h2>
    <p class="sec-intro">流水线各阶段真实执行耗时与占比。由引擎在 <code>run()</code> 内逐阶段 <code>time.perf_counter()</code> 打点采集，合计 {stage_sum_ms:.1f} ms。<br><small>注：以上仅统计引擎内部处理耗时，不含文件写入导出时间。</small></p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>阶段</th><th>耗时</th><th>占比</th><th>时间轴</th></tr></thead>
      <tbody>
      {stage_rows}
      </tbody>
    </table>
    </div>
  </div>

  <div class="section" id="funnel">
    <h2><span class="sec-no">02</span>📊 优化流水线漏斗</h2>
    <p class="sec-intro">从原始规则到最终输出的逐级收敛：精确/规范化/正则去重 → badfilter 取消 → 聚合折叠（净） → 冲突消解。每一步标注本阶段减少量，且 Raw − 各步减少 = 最终输出数。</p>
    {funnel_html}
  </div>

  <div class="two-col">
    <div class="section" id="rule-types"><h2><span class="sec-no">03</span>📋 规则类型分布</h2><p class="sec-intro">普通域名 / 通配符 / 正则 / IP 四类规则的占比。</p>{rule_type_bars}</div>
    <div class="section"><h2>🏷️ 类别分布</h2><p class="sec-intro">Block 规则按广告 / 追踪 / 恶意 / 钓鱼 / 挖矿等类别拆分。</p>{cat_bars}</div>
  </div>

  <div class="section" id="suffixes"><h2><span class="sec-no">04</span>🌐 域名后缀 Top 20</h2><p class="sec-intro">出现频率最高的注册后缀（含 co.cn 等二级国家后缀折叠），反映规则集中的域名生态。</p>{suffix_bars}</div>

  <div class="section" id="contributions">
    <h2><span class="sec-no">05</span>🔗 按源贡献分析（独占 vs 共享）</h2>
    <p class="note">统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享，含聚合折叠后归入父规则的）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。覆盖率低说明该源大量规则被去重/聚合吸收；独占率低说明该源内容几乎被其他源覆盖，可考虑精简。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>源</th><th class="num">原始规则</th><th class="num">输出覆盖</th><th class="num">覆盖率</th><th class="num">独占规则</th><th class="num">与他源共享</th><th class="num">独占率</th></tr></thead>
      <tbody>{contrib_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="overlap-matrix">
    <h2><span class="sec-no">06</span>🔄 源间重复矩阵（两两重复规则数 + 重复率）</h2>
    <p class="note">每格：上行 = 两源共同拥有的规则数，下行小字 = 对称重复率（Jaccard = 共同/并集）。对角线为该源输出覆盖数。颜色按重复率分级：{_dup_legend_html()}（悬停查看双方各自的覆盖率）。宽表可左右滑动。</p>
    <div class="table-wrap">
    <table style="font-size:12px;">
      <thead><tr>{matrix_header}</tr></thead>
      <tbody>{matrix_rows}</tbody>
    </table>
    </div>
    <h3 style="margin-top:18px;font-size:15px;">源编号对照（按输出覆盖降序）</h3>
    <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>源</th><th class="num">输出覆盖</th></tr></thead>
      <tbody>{matrix_legend_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="overlap-top">
    <h2><span class="sec-no">07</span>🔄 源间重复 Top 20（双向覆盖率明细）</h2>
    <p class="note">每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。颜色：<span style="background:#f8d7da;padding:2px 8px;">≥80%</span> <span style="background:#fff3cd;padding:2px 8px;">≥50%</span> <span style="background:#d1ecf1;padding:2px 8px;">≥20%</span> <span style="background:#d4edda;padding:2px 8px;">&lt;20%</span></p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>源 A</th><th>源 B</th><th class="num">共同规则数</th><th class="num">A 覆盖率</th><th class="num">B 覆盖率</th></tr></thead>
      <tbody>{overlap_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="conflicts">
    <h2><span class="sec-no">08</span>⚔️ 冲突分析（白名单覆盖拦截）</h2>
    <p class="note">与白名单重叠的拦截规则（blocks-preserved 政策：拦截规则保留输出、白名单单独成文件，此处仅记录重叠明细；仅显示前 50 条 / 共 {outcome.conflict_resolved:,} 条）。展示双方来源，便于追溯是哪个源的白名单覆盖了哪个源的拦截。精确=域名完全匹配，级联=白名单父域覆盖子域。完整清单见 output/conflicts.json。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>域名</th><th>被拦规则</th><th>被拦来源</th><th>白名单规则</th><th>白名单来源</th><th>类型</th></tr></thead>
      <tbody>{conflict_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="self-dedup">
    <h2><span class="sec-no">09</span>📐 各源自去重率（原始 vs 去重后有效）</h2>
    <p class="note">有效规则数 = 去重后该源仍覆盖的规则数；自去重率 = 1 - 有效/原始，反映该源内部及与其他源的重复程度。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>源</th><th class="num">原始规则</th><th class="num">去重后有效</th><th class="num">自去重率</th></tr></thead>
      <tbody>{effective_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="modifiers">
    <h2><span class="sec-no">10</span>🎯 $ 修饰符分布</h2>
    <p class="note">保留 <code>$</code> 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>修饰符</th><th class="num">规则数</th><th class="num">占比</th></tr></thead>
      <tbody>{modifier_rows}</tbody>
    </table>
    </div>
    <p class="note">上表统计<strong>最终输出</strong>中的修饰符（合并语义会移除部分规则：$badfilter 及其目标被取消、解析期未知修饰符整条丢弃、跨源重复键只计一次），因此不是全量。下方为<strong>源侧普查</strong>：合并去重/取消之前的全部已解析修饰符 token 计数。</p>
    {_census_block}
  </div>

  <div class="section" id="audit">
    <h2><span class="sec-no">11</span>🛡️ 白名单多层防御审计</h2>
    <p class="sec-intro">多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。</p>
    <p class="note"><span class="tag tag-red">🔴 恶意</span> 建议移除此白名单；<span class="tag tag-yellow">🟡 可疑</span> 需人工确认；<span class="tag tag-green">🟢 安全</span> 可放心放行。需在配置中启用 <code>whitelist_audit.enabled</code>。</p>
    {"<div class='stats-grid' style='margin:15px 0'><div class='stat-card'><div class='value'>" + str(audit_summary.get("malicious", 0)) + "</div><div class='label'>🔴 恶意</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get("suspicious", 0)) + "</div><div class='label'>🟡 可疑</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get("safe", 0)) + "</div><div class='label'>🟢 安全</div></div><div class='stat-card'><div class='value'>" + str(audit_summary.get("unknown", 0)) + "</div><div class='label'>⚪ 未知</div></div></div>" if audit_summary else ""}
    {"<h3 style='margin:20px 0 10px'>🏗️ 防御层概览</h3><div class='table-wrap'><table><thead><tr><th>层级</th><th>检测内容</th><th>状态</th><th>成本</th><th class='num'>命中数</th></tr></thead><tbody>" + layer_rows + "</tbody></table></div>" if layer_rows else ""}
    {"<h3 style='margin:20px 0 10px'>📂 白名单域名类别分布</h3><div class='table-wrap'><table><thead><tr><th>类别</th><th class='num'>数量</th><th>占比</th><th class='num'>百分比</th></tr></thead><tbody>" + cat_rows + "</tbody></table></div>" if cat_counts else ""}
    {"<h3 style='margin:20px 0 10px'>🎯 分类置信度分布</h3><p class='note' style='margin:5px 0'>高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。</p><div class='table-wrap'><table><thead><tr><th>置信度等级</th><th class='num'>数量</th><th>占比</th><th class='num'>百分比</th></tr></thead><tbody>" + conf_rows + "</tbody></table></div>" if conf_dist else ""}
    <h3 style="margin:20px 0 10px">🔍 逐条审计详情</h3>
    <div class="table-wrap">
    <table>
      <thead><tr><th>域名</th><th>评级</th><th>类别</th><th class="num">风险分</th><th>建议动作</th><th class="num">置信度</th><th>原因</th><th>来源</th></tr></thead>
      <tbody>{audit_rows if audit_rows else '<tr><td colspan="8" class="empty-state">审计未启用</td></tr>'}</tbody>
    </table>
    </div>
  </div>

  <div class="section" id="grammar">
    <h2><span class="sec-no">12</span>📝 规则语法支持度矩阵</h2>
    <p class="sec-intro">各类规则语法在 DNS 层的支持情况、处理方式与当前数量；CSS/JS 等浏览器层语法在 DNS 输出中丢弃。</p>
    <div class="table-wrap">
    <table>
      <thead><tr><th>规则类型</th><th>语法示例</th><th>状态</th><th>处理方式</th><th class="num">数量</th></tr></thead>
      <tbody>
        <tr><td>Block 域名</td><td><code>||example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>核心输出</td><td>{domain_count:,}</td></tr>
        <tr><td>通配符</td><td><code>||*.example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>聚合覆盖子域</td><td>{wildcard_count:,}</td></tr>
        <tr><td>Allow 白名单</td><td><code>@@||example.com^</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>分离到 whitelist.txt</td><td>{total_allow:,}</td></tr>
        <tr><td>正则</td><td><code>/ads.*/</code></td><td><span class="tag tag-blue">✅ 保留</span></td><td>原样保留</td><td>{regex_count:,}</td></tr>
        <tr><td>IP 规则</td><td><code>||8.8.8.8^</code></td><td><span class="tag tag-blue">✅ 支持</span></td><td>按域名字符串处理</td><td>{ip_count:,}</td></tr>
        <tr><td>Hosts</td><td><code>0.0.0.0 example.com</code></td><td><span class="tag tag-green">✅ 支持</span></td><td>转换为 ||domain^</td><td>-</td></tr>
        <tr><td>$ 修饰符</td><td><code>||x.com^$important</code></td><td><span class="tag tag-green">✅ 保留</span></td><td>保留修饰符，纳入去重键，跳过聚合，$important 抗白名单</td><td>{modifier_total:,}</td></tr>
        <tr><td>CSS/JS</td><td><code>##.ad</code></td><td><span class="tag tag-red">❌ 丢弃</span></td><td>DNS 层不支持</td><td>{outcome.css_dropped:,}</td></tr>
      </tbody>
    </table>
    </div>
  </div>

  <div class="two-col" id="performance">
    <div class="section"><h2><span class="sec-no">13</span>⚡ 性能指标</h2>
      <table>
        <tr><td>总耗时</td><td><strong>{_elapsed_value}</strong></td></tr>
        <tr><td>源成功率</td><td>{outcome.sources_ok}/{outcome.sources_total}</td></tr>
        <tr><td>缓存命中</td><td>{_cache_value}</td></tr>
        <tr><td>精确去重</td><td>{outcome.exact_merged:,}</td></tr>
        <tr><td>规范化去重</td><td>{outcome.normalized_merged:,}</td></tr>
        <tr><td>正则去重</td><td>{outcome.regex_merged:,}</td></tr>
        <tr><td>本次新增域名</td><td>{len(outcome.added):,}</td></tr>
        <tr><td>本次移除域名</td><td>{len(outcome.removed):,}</td></tr>
      </table>
    </div>
    <div class="section"><h2>📏 域名长度统计</h2>
      <table>
        <tr><td>平均域名长度</td><td>{analysis["avg_domain_length"]:.1f} 字符</td></tr>
        <tr><td>最短域名</td><td>{analysis["min_domain_length"]} 字符</td></tr>
        <tr><td>最长域名</td><td>{analysis["max_domain_length"]} 字符</td></tr>
      </table>
    </div>
  </div>

  {history_section}
  <!-- 与上次合并对比 -->
  {diff_section}

  <div class="footer">AdGuard Rules Merger V8 · 自动生成 · {_footer_stamp}</div>
</div>
</body>
</html>"""
    return html
