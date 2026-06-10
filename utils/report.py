from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

SEVERITY_COLORS = {
    'critical': colors.HexColor('#dc2626'),
    'high':     colors.HexColor('#ea580c'),
    'medium':   colors.HexColor('#ca8a04'),
    'low':      colors.HexColor('#2563eb'),
}

VERDICT_COLORS = {
    'PHISHING':   colors.HexColor('#dc2626'),
    'SUSPICIOUS': colors.HexColor('#ca8a04'),
    'SAFE':       colors.HexColor('#16a34a'),
}


def generate_report(url: str, result: dict) -> str:
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'reports/phishing_report_{timestamp}.pdf'

    doc = SimpleDocTemplate(filename, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Title'],
                                  fontSize=22, textColor=colors.HexColor('#0f172a'),
                                  spaceAfter=4)
    sub_style = ParagraphStyle('Sub', parent=styles['Normal'],
                                fontSize=10, textColor=colors.HexColor('#64748b'),
                                spaceAfter=12)
    h2_style = ParagraphStyle('H2', parent=styles['Heading2'],
                               fontSize=13, textColor=colors.HexColor('#1e293b'),
                               spaceBefore=16, spaceAfter=6)
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
                                 fontSize=10, textColor=colors.HexColor('#334155'),
                                 leading=16)

    story = []

    # Header
    story.append(Paragraph('🔍 Phishing URL Analysis Report', title_style))
    story.append(Paragraph(f'Generated: {result["analyzed_at"]}  |  Tool: PhishGuard v1.0', sub_style))
    story.append(HRFlowable(width='100%', thickness=2, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.4*cm))

    # Verdict box
    verdict = result['verdict']
    v_color = VERDICT_COLORS.get(verdict, colors.black)
    verdict_table = Table(
        [[Paragraph(f'<b>VERDICT: {result["verdict_label"]}</b>', ParagraphStyle('V', fontSize=16, textColor=colors.white, alignment=TA_CENTER)),
          Paragraph(f'<b>Risk Score: {result["score"]}/100</b>', ParagraphStyle('S', fontSize=16, textColor=colors.white, alignment=TA_CENTER))]],
        colWidths=['60%', '40%']
    )
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), v_color),
        ('PADDING', (0,0), (-1,-1), 12),
        ('ROUNDEDCORNERS', [8]),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 0.5*cm))

    # URL
    story.append(Paragraph('<b>Analyzed URL</b>', h2_style))
    story.append(Paragraph(f'<font name="Courier">{url}</font>', body_style))
    story.append(Spacer(1, 0.3*cm))

    # Risk Factors
    if result['reasons']:
        story.append(Paragraph('⚠ Risk Factors Detected', h2_style))
        for reason, severity in result['reasons']:
            sev_color = SEVERITY_COLORS.get(severity, colors.black)
            row = Table(
                [[Paragraph(f'<b>{severity.upper()}</b>', ParagraphStyle('Sev', fontSize=8, textColor=colors.white, alignment=TA_CENTER)),
                  Paragraph(reason, body_style)]],
                colWidths=[1.8*cm, None]
            )
            row.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), sev_color),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('PADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(row)
            story.append(Spacer(1, 0.15*cm))

    # Positive signals
    if result['positive_signals']:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph('✅ Positive Signals', h2_style))
        for signal in result['positive_signals']:
            story.append(Paragraph(f'• {signal}', body_style))

    # Technical breakdown
    story.append(Paragraph('📊 Technical Analysis', h2_style))
    f = result['features']
    ssl = result['ssl']
    age = result['domain_age']

    tech_data = [
        ['Feature', 'Value'],
        ['URL Length', str(f['url_length']) + ' characters'],
        ['HTTPS', '✓ Yes' if f['uses_https'] else '✗ No'],
        ['TLD', f['tld']],
        ['Subdomain Depth', str(f['subdomain_depth'])],
        ['Phishing Keywords', str(f['keyword_count']) + ' found'],
        ['SSL Valid', '✓ Yes' if ssl.get('valid') else '✗ No'],
        ['SSL Expiry', ssl.get('expiry', 'N/A') or 'N/A'],
        ['Domain Age', f"{age.get('age_days', 'N/A')} days" if age.get('age_days') else 'N/A'],
        ['Registrar', age.get('registrar', 'N/A') or 'N/A'],
    ]

    if result.get('virustotal'):
        vt = result['virustotal']
        tech_data.append(['VirusTotal Malicious', f"{vt['malicious']} / {vt['total']} engines"])

    t = Table(tech_data, colWidths=['45%', '55%'])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # Footer
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#e2e8f0')))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        'PhishGuard | Phishing URL Detection Tool — For educational and cybersecurity research purposes only.',
        ParagraphStyle('Footer', fontSize=8, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)
    ))

    doc.build(story)
    return filename
