"""
Advanced PDF report generator with executive summary, anomaly heatmap timeline,
zero-day intelligence, MITRE ATT&CK table, and remediation steps.
"""
import io
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Colour palette
C_BLACK    = (10, 10, 15)
C_DARK     = (13, 17, 23)
C_GREEN    = (0, 255, 159)
C_RED      = (255, 0, 60)
C_ORANGE   = (255, 107, 0)
C_CYAN     = (0, 212, 255)
C_GREY     = (100, 116, 139)
C_WHITE    = (224, 230, 239)
C_CRITICAL = (255, 0, 60)
C_HIGH     = (255, 107, 0)
C_MEDIUM   = (255, 204, 0)
C_LOW      = (0, 212, 255)
C_INFO     = (100, 116, 139)


SEVERITY_COLOURS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
    "INFO":     C_INFO,
}


class AdvancedReportGenerator:
    """Generates a professional multi-section PDF incident report."""

    def generate(self, result: dict, watermark_text: str = "") -> bytes:
        """Build and return the complete PDF as bytes."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, HRFlowable, KeepTogether,
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
            from reportlab.lib.units import inch, mm
            from reportlab.lib import colors
            from reportlab.lib.colors import HexColor, Color

            def rgb(r, g, b):
                return Color(r / 255, g / 255, b / 255)

            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf, pagesize=A4,
                leftMargin=20*mm, rightMargin=20*mm,
                topMargin=20*mm, bottomMargin=20*mm,
            )

            styles = getSampleStyleSheet()
            base = styles["Normal"]
            S = self._build_styles(styles, rgb)

            meta    = result.get("meta", {})
            risk    = result.get("risk", {})
            ensemble = result.get("ensemble", {})
            zd      = result.get("zero_day", {})
            existing= result.get("existing", {})
            kc      = result.get("kill_chain")

            story = []

            # ── Cover header ──────────────────────────────────────────────────
            story.append(Paragraph("SOC AI ASSISTANT PRO", S["h_title"]))
            story.append(Paragraph("Incident Analysis Report", S["h_subtitle"]))
            story.append(Spacer(1, 4*mm))
            story.append(HRFlowable(width="100%", thickness=1, color=rgb(*C_GREEN)))
            story.append(Spacer(1, 3*mm))

            ts = meta.get("generated_at", datetime.utcnow().isoformat())
            story.append(Paragraph(f"Generated: {ts}  |  Mode: {meta.get('mode','tool').upper()}  |  v{meta.get('tool_version','2.0')}", S["meta"]))
            if watermark_text:
                story.append(Paragraph(f"Customer: {watermark_text}", S["meta"]))
            story.append(Spacer(1, 6*mm))

            # ── Risk banner ───────────────────────────────────────────────────
            level     = risk.get("level", "INFO")
            composite = risk.get("composite_score", 0)
            level_col = rgb(*SEVERITY_COLOURS.get(level, C_INFO))
            risk_table = Table(
                [[Paragraph(f"RISK LEVEL: {level}", S["risk_label"]),
                  Paragraph(f"Composite Score: {composite:.1f}/100", S["risk_score"])]],
                colWidths=["50%", "50%"],
            )
            risk_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), level_col),
                ("TEXTCOLOR",  (0, 0), (-1, -1), rgb(*C_BLACK)),
                ("ALIGN",      (0, 0), (0, 0), "LEFT"),
                ("ALIGN",      (1, 0), (1, 0), "RIGHT"),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("ROUNDEDCORNERS", [4]),
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 6*mm))

            # ── 1. Executive Summary ──────────────────────────────────────────
            story.append(Paragraph("1. EXECUTIVE SUMMARY", S["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
            story.append(Spacer(1, 3*mm))
            verdict_dict = ensemble.get("verdict", {})
            summary_text = (
                verdict_dict.get("explanation", "") or
                f"Analysis completed. Composite threat score: {composite:.1f}/100. "
                f"Severity: {level}. Alert: {'YES' if risk.get('alert') else 'NO'}."
            )
            story.append(Paragraph(summary_text, S["body"]))
            story.append(Spacer(1, 4*mm))

            # ── 2. Ensemble ML Scores ─────────────────────────────────────────
            story.append(Paragraph("2. ENSEMBLE MODEL SCORES", S["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
            story.append(Spacer(1, 3*mm))
            model_rows = [
                [Paragraph("<b>Model</b>", S["th"]),
                 Paragraph("<b>Score</b>", S["th"]),
                 Paragraph("<b>Confidence</b>", S["th"]),
                 Paragraph("<b>Weight</b>", S["th"]),
                 Paragraph("<b>Method</b>", S["th"])],
            ]
            for m in verdict_dict.get("model_details", []):
                score = m.get("score", 0)
                bar_w = int(score / 5)
                bar = "█" * bar_w + "░" * (20 - bar_w)
                model_rows.append([
                    Paragraph(m["model"].replace("_", " ").title(), S["td"]),
                    Paragraph(f"{score}  {bar}", S["td_mono"]),
                    Paragraph(f"{m['confidence']:.0%}", S["td"]),
                    Paragraph(f"{m['weight']:.0%}", S["td"]),
                    Paragraph(m.get("method", "")[:40], S["td_small"]),
                ])
            ml_table = Table(model_rows, colWidths=["22%", "32%", "13%", "11%", "22%"])
            ml_table.setStyle(self._default_table_style(rgb))
            story.append(ml_table)
            story.append(Spacer(1, 5*mm))

            # ── 3. Zero-Day Intelligence ──────────────────────────────────────
            zd_score = zd.get("zero_day_score", 0)
            if zd_score > 0:
                story.append(Paragraph("3. ZERO-DAY INTELLIGENCE", S["section"]))
                story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
                story.append(Spacer(1, 3*mm))
                zd_label = zd.get("label", "N/A")
                zd_action= zd.get("action", "N/A")
                story.append(Paragraph(
                    f"Zero-Day Score: <b>{zd_score:.1f}/100</b> | "
                    f"Confidence: <b>{zd_label}</b> | "
                    f"Recommended Action: <b>{zd_action.replace('_', ' ').upper()}</b>",
                    S["body_bold"]
                ))
                story.append(Spacer(1, 3*mm))

                sig_rows = [[Paragraph("<b>Method</b>", S["th"]),
                             Paragraph("<b>Score</b>", S["th"]),
                             Paragraph("<b>Evidence</b>", S["th"])]]
                for sig in zd.get("signals", []):
                    sig_rows.append([
                        Paragraph(sig["method"].replace("_", " ").title(), S["td"]),
                        Paragraph(f"{sig['score']:.1f}", S["td"]),
                        Paragraph(str(sig.get("evidence", ""))[:120], S["td_small"]),
                    ])
                sig_table = Table(sig_rows, colWidths=["28%", "14%", "58%"])
                sig_table.setStyle(self._default_table_style(rgb))
                story.append(sig_table)
                story.append(Spacer(1, 3*mm))

                if zd.get("yara_rule"):
                    story.append(Paragraph("Auto-generated YARA Rule:", S["subheader"]))
                    story.append(Paragraph(
                        zd["yara_rule"].replace("\n", "<br/>").replace(" ", "&nbsp;"),
                        S["code"]
                    ))
                story.append(Spacer(1, 4*mm))

            # ── 4. Existing Threat Detection ──────────────────────────────────
            story.append(Paragraph("4. EXISTING THREAT DETECTION", S["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
            story.append(Spacer(1, 3*mm))

            # YARA hits
            yara_hits = existing.get("yara_hits", [])
            if yara_hits:
                story.append(Paragraph(f"YARA Matches ({len(yara_hits)}):", S["subheader"]))
                for h in yara_hits[:10]:
                    story.append(Paragraph(f"• <b>{h['rule']}</b> — {', '.join(h.get('strings',[])[:3])}", S["body"]))
                story.append(Spacer(1, 2*mm))

            # MITRE hits
            mitre_hits = existing.get("mitre_hits", [])
            if mitre_hits:
                story.append(Paragraph(f"MITRE ATT&CK Techniques ({len(mitre_hits)}):", S["subheader"]))
                mitre_rows = [[Paragraph("<b>ID</b>", S["th"]),
                               Paragraph("<b>Technique</b>", S["th"]),
                               Paragraph("<b>Tactic</b>", S["th"]),
                               Paragraph("<b>Evidence</b>", S["th"])]]
                for h in mitre_hits[:15]:
                    mitre_rows.append([
                        Paragraph(h.get("technique_id", ""), S["td_mono"]),
                        Paragraph(h.get("name", "")[:40], S["td"]),
                        Paragraph(h.get("tactic", ""), S["td_small"]),
                        Paragraph(", ".join(h.get("matched_on", [])[:3]), S["td_small"]),
                    ])
                mt = Table(mitre_rows, colWidths=["14%", "30%", "22%", "34%"])
                mt.setStyle(self._default_table_style(rgb))
                story.append(mt)
                story.append(Spacer(1, 2*mm))

            # CVEs
            cves = existing.get("cves", [])
            if cves:
                story.append(Paragraph(f"CVE Correlations ({len(cves)}):", S["subheader"]))
                cve_rows = [[Paragraph("<b>CVE ID</b>", S["th"]),
                             Paragraph("<b>CVSS</b>", S["th"]),
                             Paragraph("<b>Severity</b>", S["th"]),
                             Paragraph("<b>Description</b>", S["th"])]]
                for c in cves[:10]:
                    cve_rows.append([
                        Paragraph(c.get("cve_id", ""), S["td_mono"]),
                        Paragraph(str(c.get("cvss_score", "")), S["td"]),
                        Paragraph(c.get("severity", ""), S["td"]),
                        Paragraph(str(c.get("description", ""))[:100], S["td_small"]),
                    ])
                ct = Table(cve_rows, colWidths=["18%", "10%", "14%", "58%"])
                ct.setStyle(self._default_table_style(rgb))
                story.append(ct)
            story.append(Spacer(1, 5*mm))

            # ── 5. Kill Chain ─────────────────────────────────────────────────
            if kc:
                story.append(Paragraph("5. KILL CHAIN RECONSTRUCTION", S["section"]))
                story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
                story.append(Spacer(1, 3*mm))
                story.append(Paragraph(f"Seed IOC: <b>{kc.get('seed_ioc','')}</b>  |  "
                                        f"Related IOCs discovered: <b>{kc.get('pivot_count',0)}</b>  |  "
                                        f"Timeline events: <b>{kc.get('timeline_events',0)}</b>", S["body"]))
                story.append(Spacer(1, 2*mm))
                analysis = str(kc.get("kill_chain_analysis", "")).replace("\n", "<br/>")
                if analysis:
                    story.append(Paragraph(analysis[:3000], S["body"]))
                story.append(Spacer(1, 5*mm))

            # ── 6. Remediation ────────────────────────────────────────────────
            story.append(Paragraph("6. REMEDIATION RECOMMENDATIONS", S["section"]))
            story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
            story.append(Spacer(1, 3*mm))
            remediation_steps = self._derive_remediation(risk, existing, zd)
            for i, step in enumerate(remediation_steps, 1):
                story.append(Paragraph(f"<b>{i}.</b> {step}", S["body"]))
                story.append(Spacer(1, 1*mm))
            story.append(Spacer(1, 5*mm))

            # ── Footer ────────────────────────────────────────────────────────
            story.append(HRFlowable(width="100%", thickness=0.5, color=rgb(*C_GREY)))
            story.append(Spacer(1, 2*mm))
            story.append(Paragraph(
                "Generated by SOC AI Assistant Pro v2.0 | Commercial License | "
                "For authorized security operations only.",
                S["footer"]
            ))

            doc.build(story)
            buf.seek(0)
            return buf.read()

        except Exception as exc:
            logger.error("[Report] PDF generation failed: %s", exc, exc_info=True)
            return b""

    # ── Style builders ────────────────────────────────────────────────────────

    @staticmethod
    def _build_styles(styles, rgb):
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        def mk(name, **kw):
            return ParagraphStyle(name=name, **kw)

        return {
            "h_title":    mk("h_title",   fontName="Helvetica-Bold", fontSize=22, textColor=rgb(*C_GREEN), alignment=TA_CENTER, spaceAfter=4),
            "h_subtitle": mk("h_subtitle",fontName="Helvetica",      fontSize=13, textColor=rgb(*C_WHITE), alignment=TA_CENTER, spaceAfter=2),
            "meta":       mk("meta",       fontName="Helvetica",      fontSize=8,  textColor=rgb(*C_GREY),  alignment=TA_CENTER),
            "section":    mk("section",    fontName="Helvetica-Bold", fontSize=12, textColor=rgb(*C_CYAN),  spaceBefore=8, spaceAfter=2),
            "subheader":  mk("subheader",  fontName="Helvetica-Bold", fontSize=10, textColor=rgb(*C_WHITE), spaceBefore=4, spaceAfter=2),
            "body":       mk("body",       fontName="Helvetica",      fontSize=9,  textColor=rgb(*C_WHITE), leading=13),
            "body_bold":  mk("body_bold",  fontName="Helvetica-Bold", fontSize=9,  textColor=rgb(*C_WHITE), leading=13),
            "code":       mk("code",       fontName="Courier",        fontSize=7,  textColor=rgb(*C_GREEN), backColor=rgb(*C_DARK), leading=10),
            "td":         mk("td",         fontName="Helvetica",      fontSize=8,  textColor=rgb(*C_WHITE)),
            "td_small":   mk("td_small",   fontName="Helvetica",      fontSize=7,  textColor=rgb(*C_GREY)),
            "td_mono":    mk("td_mono",    fontName="Courier",        fontSize=8,  textColor=rgb(*C_CYAN)),
            "th":         mk("th",         fontName="Helvetica-Bold", fontSize=8,  textColor=rgb(*C_BLACK)),
            "risk_label": mk("risk_label", fontName="Helvetica-Bold", fontSize=14, textColor=rgb(*C_BLACK)),
            "risk_score": mk("risk_score", fontName="Helvetica-Bold", fontSize=12, textColor=rgb(*C_BLACK), alignment=2),
            "footer":     mk("footer",     fontName="Helvetica",      fontSize=7,  textColor=rgb(*C_GREY),  alignment=TA_CENTER),
        }

    @staticmethod
    def _default_table_style(rgb):
        from reportlab.platypus import TableStyle
        return TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), rgb(*C_DARK)),
            ("BACKGROUND",    (0, 1), (-1, -1), rgb(20, 27, 38)),
            ("GRID",          (0, 0), (-1, -1), 0.3, rgb(*C_GREY)),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [rgb(16, 22, 32), rgb(20, 27, 38)]),
        ])

    @staticmethod
    def _derive_remediation(risk, existing, zd) -> list[str]:
        steps = []
        level = risk.get("level", "INFO")

        if level in ("CRITICAL", "HIGH"):
            steps.append("Immediately isolate the affected host(s) from the network to prevent lateral movement.")
        if existing.get("yara_hits"):
            rules = [h["rule"] for h in existing["yara_hits"][:3]]
            steps.append(f"Quarantine files matching YARA rules: {', '.join(rules)}. Run full AV scan.")
        if existing.get("cves"):
            cve_ids = [c["cve_id"] for c in existing["cves"][:3]]
            steps.append(f"Apply patches for: {', '.join(cve_ids)}. Check vendor advisories.")
        mitre = existing.get("mitre_hits", [])
        if any("T1059" in h.get("technique_id", "") for h in mitre):
            steps.append("Audit PowerShell execution policy. Enable ScriptBlock logging. Review encoded commands.")
        if any("T1003" in h.get("technique_id", "") for h in mitre):
            steps.append("Rotate all credentials on affected systems. Check for credential exposure.")
        if any("T1071" in h.get("technique_id", "") for h in mitre):
            steps.append("Block identified C2 IPs/domains at firewall and DNS. Capture traffic for forensics.")
        if zd.get("zero_day_score", 0) > 60:
            steps.append("Novel attack pattern detected. Preserve memory image and logs. Engage incident response team.")

        if not steps:
            steps.append("No immediate action required. Continue monitoring. Review logs periodically.")
        return steps[:6]
