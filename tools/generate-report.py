#!/usr/bin/env python3
"""
Obsidian Security Suite — PDF Report Generator
Generates professional security audit reports from JSON audit data.

Usage: python3 generate-report.py <audit_json> <output_pdf> [--company "Company Name"]
"""

import json
import sys
import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm, cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas


# =============================================================================
# COLORS
# =============================================================================

COLORS = {
    'primary':    HexColor('#1a1a2e'),
    'accent':     HexColor('#16213e'),
    'highlight':  HexColor('#0f3460'),
    'blue':       HexColor('#2196F3'),
    'green':      HexColor('#4CAF50'),
    'yellow':     HexColor('#FF9800'),
    'red':        HexColor('#F44336'),
    'dark_red':   HexColor('#B71C1C'),
    'light_gray': HexColor('#f5f5f5'),
    'med_gray':   HexColor('#9e9e9e'),
    'dark_gray':  HexColor('#424242'),
    'bg_dark':    HexColor('#1a1a2e'),
    'white':      white,
    'black':      black,
}

SEVERITY_COLORS = {
    'CRITICAL': HexColor('#B71C1C'),
    'HIGH':     HexColor('#E65100'),
    'MEDIUM':   HexColor('#F57F17'),
    'LOW':      HexColor('#1565C0'),
    'INFO':     HexColor('#616161'),
}

SEVERITY_BG = {
    'CRITICAL': HexColor('#FFEBEE'),
    'HIGH':     HexColor('#FFF3E0'),
    'MEDIUM':   HexColor('#FFFDE7'),
    'LOW':      HexColor('#E3F2FD'),
    'INFO':     HexColor('#F5F5F5'),
}


# =============================================================================
# STYLES
# =============================================================================

def get_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'CoverTitle', parent=styles['Title'],
        fontSize=36, textColor=COLORS['white'],
        alignment=TA_LEFT, spaceAfter=10,
        fontName='Helvetica-Bold'
    ))
    styles.add(ParagraphStyle(
        'CoverSubtitle', parent=styles['Normal'],
        fontSize=16, textColor=HexColor('#B0BEC5'),
        alignment=TA_LEFT, spaceAfter=6,
        fontName='Helvetica'
    ))
    styles.add(ParagraphStyle(
        'SectionTitle', parent=styles['Heading1'],
        fontSize=18, textColor=COLORS['primary'],
        spaceBefore=20, spaceAfter=10,
        fontName='Helvetica-Bold',
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        'SubSection', parent=styles['Heading2'],
        fontSize=13, textColor=COLORS['highlight'],
        spaceBefore=12, spaceAfter=6,
        fontName='Helvetica-Bold'
    ))
    styles.add(ParagraphStyle(
        'BodyText2', parent=styles['Normal'],
        fontSize=10, textColor=COLORS['dark_gray'],
        alignment=TA_JUSTIFY, spaceAfter=6,
        leading=14, fontName='Helvetica'
    ))
    styles.add(ParagraphStyle(
        'SmallGray', parent=styles['Normal'],
        fontSize=8, textColor=COLORS['med_gray'],
        alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        'ScoreGrade', parent=styles['Title'],
        fontSize=64, alignment=TA_CENTER,
        fontName='Helvetica-Bold', spaceAfter=0
    ))
    styles.add(ParagraphStyle(
        'TableCell', parent=styles['Normal'],
        fontSize=9, textColor=COLORS['dark_gray'],
        leading=12, fontName='Helvetica'
    ))
    styles.add(ParagraphStyle(
        'TableHeader', parent=styles['Normal'],
        fontSize=9, textColor=COLORS['white'],
        leading=12, fontName='Helvetica-Bold'
    ))
    styles.add(ParagraphStyle(
        'IssueTitle', parent=styles['Normal'],
        fontSize=11, textColor=COLORS['black'],
        fontName='Helvetica-Bold', spaceAfter=2
    ))
    styles.add(ParagraphStyle(
        'IssueDesc', parent=styles['Normal'],
        fontSize=9, textColor=COLORS['dark_gray'],
        leading=12, fontName='Helvetica', spaceAfter=2
    ))
    styles.add(ParagraphStyle(
        'Recommendation', parent=styles['Normal'],
        fontSize=9, textColor=COLORS['highlight'],
        leading=12, fontName='Helvetica-Oblique',
        leftIndent=10, spaceAfter=8
    ))

    return styles


# =============================================================================
# COVER PAGE
# =============================================================================

class CoverPage:
    def __init__(self, audit_data, company_name):
        self.data = audit_data
        self.company = company_name

    def draw(self, canvas_obj, doc):
        w, h = A4

        # Dark background
        canvas_obj.setFillColor(COLORS['primary'])
        canvas_obj.rect(0, 0, w, h, fill=1)

        # Accent stripe
        canvas_obj.setFillColor(COLORS['highlight'])
        canvas_obj.rect(0, h - 180, w, 180, fill=1)

        # Company name
        canvas_obj.setFillColor(COLORS['white'])
        canvas_obj.setFont('Helvetica-Bold', 14)
        canvas_obj.drawString(40, h - 50, self.company)

        # Title
        canvas_obj.setFont('Helvetica-Bold', 38)
        canvas_obj.drawString(40, h - 110, "Security Audit")
        canvas_obj.setFont('Helvetica-Bold', 38)
        canvas_obj.drawString(40, h - 155, "Report")

        # Divider line
        canvas_obj.setStrokeColor(COLORS['blue'])
        canvas_obj.setLineWidth(3)
        canvas_obj.line(40, h - 200, 200, h - 200)

        # Metadata
        canvas_obj.setFillColor(HexColor('#B0BEC5'))
        canvas_obj.setFont('Helvetica', 12)
        y = h - 240
        fields = [
            ("Server", self.data.get('hostname', 'Unknown')),
            ("Date", self.data.get('timestamp', 'Unknown')),
            ("Audit ID", self.data.get('audit_id', 'Unknown')),
            ("Scan Path", self.data.get('scan_path', '/')),
        ]
        for label, value in fields:
            canvas_obj.setFillColor(HexColor('#78909C'))
            canvas_obj.setFont('Helvetica', 10)
            canvas_obj.drawString(40, y, label.upper())
            canvas_obj.setFillColor(COLORS['white'])
            canvas_obj.setFont('Helvetica', 12)
            canvas_obj.drawString(40, y - 18, str(value))
            y -= 50

        # Score circle
        score = self.data.get('score', 0)
        grade, grade_color = get_grade(score)

        cx, cy, r = w - 120, h - 320, 60
        canvas_obj.setFillColor(HexColor('#16213e'))
        canvas_obj.circle(cx, cy, r + 5, fill=1, stroke=0)
        canvas_obj.setFillColor(grade_color)
        canvas_obj.circle(cx, cy, r, fill=1, stroke=0)
        canvas_obj.setFillColor(COLORS['white'])
        canvas_obj.setFont('Helvetica-Bold', 42)
        canvas_obj.drawCentredString(cx, cy - 8, grade)
        canvas_obj.setFont('Helvetica', 10)
        canvas_obj.drawCentredString(cx, cy - 28, f"{score}/100")

        # Footer
        canvas_obj.setFillColor(HexColor('#455A64'))
        canvas_obj.setFont('Helvetica', 9)
        canvas_obj.drawString(40, 40, f"Generated by Obsidian Security Suite v{self.data.get('obsidian_version', '1.0.0')}")
        canvas_obj.drawRightString(w - 40, 40, "CONFIDENTIAL")


# =============================================================================
# HELPERS
# =============================================================================

def get_grade(score):
    if score >= 90: return 'A', COLORS['green']
    if score >= 80: return 'A-', COLORS['green']
    if score >= 70: return 'B', COLORS['yellow']
    if score >= 60: return 'C', COLORS['yellow']
    if score >= 50: return 'D', COLORS['red']
    return 'F', COLORS['dark_red']


def severity_badge(severity, styles):
    color = SEVERITY_COLORS.get(severity, COLORS['med_gray'])
    return Paragraph(
        f'<font color="{color.hexval()}">{severity}</font>',
        styles['TableCell']
    )


def colored_bar(value, max_val=100, width=120):
    """Return a simple text representation of a bar."""
    if value >= 90:
        color = '#F44336'
    elif value >= 80:
        color = '#FF9800'
    elif value >= 60:
        color = '#FFC107'
    else:
        color = '#4CAF50'
    return f'<font color="{color}"><b>{value}%</b></font>'


# =============================================================================
# REPORT BUILDER
# =============================================================================

def build_report(audit_data, output_path, company_name="Obsidian Security"):
    styles = get_styles()
    cover = CoverPage(audit_data, company_name)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=30*mm,
        rightMargin=25*mm,
        topMargin=25*mm,
        bottomMargin=25*mm,
        title=f"Security Audit Report — {audit_data.get('hostname', 'Server')}",
        author=company_name,
        subject="Security Audit Report",
    )

    story = []

    # --- COVER PAGE (manual) ---
    # We'll use onFirstPage callback

    # Blank first page (cover drawn via callback)
    story.append(Spacer(1, 500))
    story.append(PageBreak())

    # --- EXECUTIVE SUMMARY ---
    story.append(Paragraph("Executive Summary", styles['SectionTitle']))
    story.append(HRFlowable(width="100%", color=COLORS['blue'], thickness=2, spaceAfter=10))

    score = audit_data.get('score', 0)
    grade, grade_color = get_grade(score)
    issues = audit_data.get('issues', audit_data.get('findings', []))
    critical_count = sum(1 for i in issues if i.get('severity') == 'CRITICAL')
    high_count = sum(1 for i in issues if i.get('severity') == 'HIGH')
    medium_count = sum(1 for i in issues if i.get('severity') == 'MEDIUM')
    low_count = sum(1 for i in issues if i.get('severity') == 'LOW')

    # Score summary
    score_text = f"""
    This security audit of <b>{audit_data.get('hostname', 'the server')}</b> was conducted on
    <b>{audit_data.get('timestamp', 'unknown date')}</b>. The server received a security score of
    <font color="{grade_color.hexval()}"><b>{score}/100 (Grade: {grade})</b></font>.
    """

    if critical_count > 0:
        score_text += f"""<br/><br/>
        <font color="#B71C1C"><b>IMMEDIATE ACTION REQUIRED:</b></font> {critical_count} critical issue(s)
        were found that require urgent attention. These include potential malware infections, critical
        misconfigurations, or active security threats.
        """
    elif high_count > 0:
        score_text += f"""<br/><br/>
        <font color="#E65100"><b>{high_count} high-priority issue(s)</b></font> were identified that
        should be addressed within the next 48 hours.
        """
    else:
        score_text += """<br/><br/>
        No critical or high-severity issues were found. The server's security posture is reasonable,
        though some improvements are recommended.
        """

    story.append(Paragraph(score_text, styles['BodyText2']))
    story.append(Spacer(1, 10))

    # Issues summary table
    summary_data = [
        [Paragraph('<b>Severity</b>', styles['TableHeader']),
         Paragraph('<b>Count</b>', styles['TableHeader']),
         Paragraph('<b>Action Required</b>', styles['TableHeader'])],
        [Paragraph('<font color="#B71C1C">CRITICAL</font>', styles['TableCell']),
         Paragraph(f'<b>{critical_count}</b>', styles['TableCell']),
         Paragraph('Immediate — within hours', styles['TableCell'])],
        [Paragraph('<font color="#E65100">HIGH</font>', styles['TableCell']),
         Paragraph(f'<b>{high_count}</b>', styles['TableCell']),
         Paragraph('Urgent — within 48 hours', styles['TableCell'])],
        [Paragraph('<font color="#F57F17">MEDIUM</font>', styles['TableCell']),
         Paragraph(f'<b>{medium_count}</b>', styles['TableCell']),
         Paragraph('Plan — within 1 week', styles['TableCell'])],
        [Paragraph('<font color="#1565C0">LOW</font>', styles['TableCell']),
         Paragraph(f'<b>{low_count}</b>', styles['TableCell']),
         Paragraph('Consider — when convenient', styles['TableCell'])],
    ]

    summary_table = Table(summary_data, colWidths=[80, 60, 250])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
        ('TEXTCOLOR', (0, 0), (-1, 0), COLORS['white']),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, COLORS['med_gray']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # --- SYSTEM OVERVIEW ---
    story.append(Paragraph("System Overview", styles['SectionTitle']))
    story.append(HRFlowable(width="100%", color=COLORS['blue'], thickness=2, spaceAfter=10))

    sys_info = audit_data.get('system', {})
    health = audit_data.get('health', {})

    sys_data = [
        [Paragraph('<b>Property</b>', styles['TableHeader']),
         Paragraph('<b>Value</b>', styles['TableHeader']),
         Paragraph('<b>Status</b>', styles['TableHeader'])],
    ]

    # Build system rows
    rows = [
        ('Operating System', sys_info.get('os', 'Unknown'), 'ok'),
        ('Kernel', sys_info.get('kernel', 'Unknown'), 'ok'),
        ('CPU Cores', str(sys_info.get('cpu_cores', '?')), 'ok'),
        ('Memory', f"{sys_info.get('memory_mb', 0)} MB", 'ok'),
        ('Web Server', sys_info.get('webserver', 'Unknown'), 'ok'),
        ('Firewall', sys_info.get('firewall', 'none'),
         'critical' if sys_info.get('firewall') == 'none' else 'ok'),
        ('PHP Version', sys_info.get('php_version', 'N/A'),
         'critical' if sys_info.get('php_version', '8').startswith('7') else 'ok'),
        ('cPanel', sys_info.get('cpanel', 'N/A'), 'ok'),
        ('CPU Usage', f"{colored_bar(health.get('cpu_percent', 0))}", 'metric'),
        ('Memory Usage', f"{colored_bar(health.get('memory_percent', 0))}", 'metric'),
        ('Disk Usage', f"{colored_bar(health.get('disk_percent', 0))}", 'metric'),
    ]

    for prop, val, status in rows:
        status_text = ''
        if status == 'ok':
            status_text = '<font color="#4CAF50">OK</font>'
        elif status == 'critical':
            status_text = '<font color="#F44336">ISSUE</font>'
        elif status == 'metric':
            status_text = ''

        sys_data.append([
            Paragraph(f'<b>{prop}</b>', styles['TableCell']),
            Paragraph(str(val), styles['TableCell']),
            Paragraph(status_text, styles['TableCell']),
        ])

    sys_table = Table(sys_data, colWidths=[120, 220, 60])
    sys_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLORS['primary']),
        ('GRID', (0, 0), (-1, -1), 0.5, COLORS['med_gray']),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(sys_table)
    story.append(PageBreak())

    # --- DETAILED FINDINGS ---
    story.append(Paragraph("Detailed Findings", styles['SectionTitle']))
    story.append(HRFlowable(width="100%", color=COLORS['blue'], thickness=2, spaceAfter=10))

    if not issues:
        story.append(Paragraph(
            "No security issues were found during this audit. The server appears to be well-configured.",
            styles['BodyText2']
        ))
    else:
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_issues = sorted(issues, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))

        for idx, issue in enumerate(sorted_issues, 1):
            sev = issue.get('severity', 'INFO')
            sev_color = SEVERITY_COLORS.get(sev, COLORS['med_gray'])
            bg_color = SEVERITY_BG.get(sev, COLORS['light_gray'])

            issue_block = []
            issue_block.append(Paragraph(
                f'<font color="{sev_color.hexval()}"><b>[{sev}]</b></font> '
                f'<b>{issue.get("title", "Unknown Issue")}</b> '
                f'<font color="#9e9e9e">({issue.get("category", "General")})</font>',
                styles['IssueTitle']
            ))
            issue_block.append(Paragraph(
                issue.get('description', issue.get('detail', '')),
                styles['IssueDesc']
            ))
            rec = issue.get('recommendation', issue.get('remediation', ''))
            if rec:
                issue_block.append(Paragraph(
                    f'<b>Recommendation:</b> {rec}',
                    styles['Recommendation']
                ))
            issue_block.append(Spacer(1, 6))

            # Wrap in KeepTogether to avoid splitting across pages
            story.append(KeepTogether(issue_block))

    story.append(PageBreak())

    # --- MALWARE FINDINGS ---
    malware_raw = audit_data.get('malware', [])
    # Handle both list format and summary dict format
    if isinstance(malware_raw, dict):
        malware = []
        # Convert summary dict to list of finding objects
        for key, val in malware_raw.items():
            if isinstance(val, int) and val > 0:
                malware.append({'type': key, 'path': 'See findings above', 'detail': f'{val} detected'})
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        malware.append(item)
                    else:
                        malware.append({'type': key, 'path': str(item), 'detail': ''})
    else:
        malware = malware_raw if isinstance(malware_raw, list) else []
    if malware:
        story.append(Paragraph("Malware Analysis", styles['SectionTitle']))
        story.append(HRFlowable(width="100%", color=COLORS['red'], thickness=2, spaceAfter=10))

        story.append(Paragraph(
            f"The malware scanner found <font color='#B71C1C'><b>{len(malware)} potential threat(s)</b></font> "
            f"on this server. Each finding is detailed below.",
            styles['BodyText2']
        ))
        story.append(Spacer(1, 8))

        mal_data = [
            [Paragraph('<b>Type</b>', styles['TableHeader']),
             Paragraph('<b>Location</b>', styles['TableHeader']),
             Paragraph('<b>Details</b>', styles['TableHeader'])],
        ]
        for m in malware:
            mtype = m.get('type', 'unknown').replace('_', ' ').title()
            mal_data.append([
                Paragraph(f'<font color="#B71C1C"><b>{mtype}</b></font>', styles['TableCell']),
                Paragraph(m.get('path', 'Unknown')[:60], styles['TableCell']),
                Paragraph(m.get('detail', '')[:100], styles['TableCell']),
            ])

        mal_table = Table(mal_data, colWidths=[90, 150, 160])
        mal_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['dark_red']),
            ('GRID', (0, 0), (-1, -1), 0.5, COLORS['med_gray']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#FFEBEE'), COLORS['white']]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(mal_table)
        story.append(PageBreak())

    # --- BOT TRAFFIC ---
    bots = audit_data.get('bots', {})
    bot_findings = bots.get('findings', [])
    family_summary = bots.get('family_summary', [])
    # Also accept top_bots format from audit.sh
    if not bot_findings and bots.get('top_bots'):
        bot_findings = [{'pattern': b.get('name', 'Unknown'), 'hits': b.get('requests', 0)}
                        for b in bots['top_bots']]
    if bot_findings:
        story.append(Paragraph("Bot Traffic Analysis", styles['SectionTitle']))
        story.append(HRFlowable(width="100%", color=COLORS['yellow'], thickness=2, spaceAfter=10))

        story.append(Paragraph(
            f"Analysis detected <b>{bots.get('total_bad_requests', 0)} requests</b> from "
            f"known malicious or aggressive bots.",
            styles['BodyText2']
        ))
        story.append(Spacer(1, 8))

        # --- Bot Family Summary (new section) ---
        family_colors = {
            'ddos_botnet': COLORS['dark_red'],
            'ai_crawler': HexColor('#E65100'),
            'seo_crawler': HexColor('#F57F17'),
            'vuln_scanner': COLORS['dark_red'],
            'scraper': HexColor('#4A148C'),
            'generic': COLORS['med_gray'],
        }

        if family_summary:
            story.append(Paragraph(
                '<b>Bot Family Breakdown</b>',
                styles['SubSection']
            ))
            story.append(Paragraph(
                'Detected bots classified by family and intent:',
                styles['BodyText2']
            ))
            story.append(Spacer(1, 6))

            fam_data = [
                [Paragraph('<b>Family</b>', styles['TableHeader']),
                 Paragraph('<b>Total Hits</b>', styles['TableHeader']),
                 Paragraph('<b>Threat Level</b>', styles['TableHeader'])],
            ]
            threat_map = {
                'ddos_botnet': 'CRITICAL',
                'vuln_scanner': 'HIGH',
                'ai_crawler': 'HIGH',
                'scraper': 'MEDIUM',
                'seo_crawler': 'MEDIUM',
                'generic': 'LOW',
            }
            # Sort by total hits descending
            for fam in sorted(family_summary, key=lambda x: x.get('total_hits', 0), reverse=True):
                fam_id = fam.get('family', 'generic')
                fam_color = family_colors.get(fam_id, COLORS['med_gray'])
                threat = threat_map.get(fam_id, 'MEDIUM')
                threat_color = SEVERITY_COLORS.get(threat, COLORS['med_gray'])
                fam_data.append([
                    Paragraph(f'<font color="{fam_color.hexval()}"><b>{fam.get("label", fam_id)}</b></font>', styles['TableCell']),
                    Paragraph(f'<b>{fam.get("total_hits", 0):,}</b>', styles['TableCell']),
                    Paragraph(f'<font color="{threat_color.hexval()}"><b>{threat}</b></font>', styles['TableCell']),
                ])

            fam_table = Table(fam_data, colWidths=[180, 80, 80])
            fam_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLORS['bg_dark']),
                ('GRID', (0, 0), (-1, -1), 0.5, COLORS['med_gray']),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(fam_table)
            story.append(Spacer(1, 12))

            # Family descriptions — explain each family to the client
            for fam in sorted(family_summary, key=lambda x: x.get('total_hits', 0), reverse=True):
                fam_id = fam.get('family', 'generic')
                fam_color = family_colors.get(fam_id, COLORS['med_gray'])
                # Get description from the first bot finding in this family
                desc = ''
                for bf in bot_findings:
                    if bf.get('family') == fam_id and bf.get('family_description'):
                        desc = bf['family_description']
                        break
                if desc:
                    story.append(Paragraph(
                        f'<font color="{fam_color.hexval()}"><b>{fam.get("label", fam_id)}</b></font>: {desc}',
                        styles['BodyText2']
                    ))
                    story.append(Spacer(1, 4))

            story.append(Spacer(1, 12))

        # --- Individual bot table ---
        story.append(Paragraph(
            '<b>Individual Bot Detections</b>',
            styles['SubSection']
        ))
        story.append(Spacer(1, 6))

        bot_data = [
            [Paragraph('<b>Bot / Pattern</b>', styles['TableHeader']),
             Paragraph('<b>Family</b>', styles['TableHeader']),
             Paragraph('<b>Requests</b>', styles['TableHeader'])],
        ]
        for b in bot_findings:
            fam_label = b.get('family_label', b.get('family', '—'))
            fam_id = b.get('family', 'generic')
            fam_color = family_colors.get(fam_id, COLORS['med_gray'])
            bot_data.append([
                Paragraph(b.get('pattern', 'Unknown'), styles['TableCell']),
                Paragraph(f'<font color="{fam_color.hexval()}">{fam_label}</font>', styles['TableCell']),
                Paragraph(f"<b>{b.get('hits', 0):,}</b>", styles['TableCell']),
            ])

        bot_table = Table(bot_data, colWidths=[170, 120, 70])
        bot_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLORS['accent']),
            ('GRID', (0, 0), (-1, -1), 0.5, COLORS['med_gray']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLORS['white'], COLORS['light_gray']]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(bot_table)
        story.append(PageBreak())

    # --- RECOMMENDATIONS SUMMARY ---
    story.append(Paragraph("Prioritized Action Plan", styles['SectionTitle']))
    story.append(HRFlowable(width="100%", color=COLORS['blue'], thickness=2, spaceAfter=10))

    story.append(Paragraph(
        "The following actions are recommended, ordered by priority:",
        styles['BodyText2']
    ))
    story.append(Spacer(1, 8))

    priority_num = 1
    for sev_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        sev_issues = [i for i in sorted_issues if i.get('severity') == sev_level] if issues else []
        if not sev_issues:
            continue

        sev_color = SEVERITY_COLORS.get(sev_level, COLORS['med_gray'])
        story.append(Paragraph(
            f'<font color="{sev_color.hexval()}"><b>{sev_level} Priority</b></font>',
            styles['SubSection']
        ))

        for issue in sev_issues:
            rec = issue.get('recommendation', issue.get('remediation', 'Review and address.'))
            story.append(Paragraph(
                f"<b>{priority_num}.</b> {issue.get('title', 'Issue')}: {rec}",
                styles['BodyText2']
            ))
            priority_num += 1

        story.append(Spacer(1, 6))

    # --- FOOTER ---
    story.append(PageBreak())
    story.append(Paragraph("About This Report", styles['SectionTitle']))
    story.append(HRFlowable(width="100%", color=COLORS['blue'], thickness=2, spaceAfter=10))

    story.append(Paragraph(
        f"This report was generated automatically by <b>Obsidian Security Suite v{audit_data.get('obsidian_version', '1.0.0')}</b>. "
        f"The audit scans for common security issues including malware, misconfigurations, "
        f"aggressive bot traffic, outdated software, and file integrity problems.",
        styles['BodyText2']
    ))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This report is confidential and intended only for the server administrator or "
        "authorized security personnel. The findings represent a point-in-time assessment and "
        "should be re-evaluated periodically.",
        styles['BodyText2']
    ))
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"Report generated: {audit_data.get('timestamp', 'Unknown')}<br/>"
        f"Audit ID: {audit_data.get('audit_id', 'Unknown')}<br/>"
        f"Prepared by: {company_name}",
        styles['SmallGray']
    ))

    # Build with cover page
    def first_page(canvas_obj, doc):
        cover.draw(canvas_obj, doc)

    def later_pages(canvas_obj, doc):
        w, h = A4
        # Header
        canvas_obj.setFillColor(COLORS['primary'])
        canvas_obj.rect(0, h - 20, w, 20, fill=1, stroke=0)
        canvas_obj.setFillColor(COLORS['white'])
        canvas_obj.setFont('Helvetica', 7)
        canvas_obj.drawString(30*mm, h - 15, f"Security Audit Report — {audit_data.get('hostname', 'Server')}")
        canvas_obj.drawRightString(w - 25*mm, h - 15, "CONFIDENTIAL")

        # Footer
        canvas_obj.setFillColor(COLORS['med_gray'])
        canvas_obj.setFont('Helvetica', 8)
        canvas_obj.drawString(30*mm, 15*mm, f"Obsidian Security Suite | {company_name}")
        canvas_obj.drawRightString(w - 25*mm, 15*mm, f"Page {doc.page}")

    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)
    return output_path


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 generate-report.py <audit.json> <output.pdf> [--company 'Name']")
        sys.exit(1)

    json_path = sys.argv[1]
    pdf_path = sys.argv[2]

    company = "Obsidian Security"
    if '--company' in sys.argv:
        idx = sys.argv.index('--company')
        if idx + 1 < len(sys.argv):
            company = sys.argv[idx + 1]

    with open(json_path, 'r') as f:
        data = json.load(f)

    output = build_report(data, pdf_path, company)
    print(f"Report generated: {output}")
