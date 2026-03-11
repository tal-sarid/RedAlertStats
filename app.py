#!/usr/bin/env python3
"""
Tzeva Adom Stats - Web Server

Run:  python app.py [--host HOST] [--port PORT] [--debug]
Open: http://localhost:5000
"""

import argparse
import os
from datetime import datetime

from flask import Flask, redirect, request, render_template
from analyzer import fetch_alert_history, analyze_alerts, format_duration, build_oref_url

app = Flask(__name__)

DEFAULT_FROM = '28.02.2026'

LANG_OPTIONS = [
    ('he', 'עברית'),
    ('en', 'English'),
    ('ru', 'Русский'),
    ('ar', 'العربية'),
]
LANG_NAMES = dict(LANG_OPTIONS)


# ── Date helpers ──────────────────────────────────────────────────────────────

def api_to_html_date(d: str) -> str:
    """'DD.MM.YYYY' → 'YYYY-MM-DD' for HTML date inputs."""
    try:
        return datetime.strptime(d, '%d.%m.%Y').strftime('%Y-%m-%d')
    except Exception:
        return ''


def html_to_api_date(d: str) -> str:
    """'YYYY-MM-DD' → 'DD.MM.YYYY' for the Oref API."""
    try:
        return datetime.strptime(d, '%Y-%m-%d').strftime('%d.%m.%Y')
    except Exception:
        return d


# ── Template context builders ─────────────────────────────────────────────────

def form_ctx(city='', from_val='', to_val='', lang='he', error='') -> dict:
    """Base context shared by all pages (populates the query form)."""
    return {
        'city':         city,
        'from_val':     from_val,
        'to_val':       to_val,
        'lang':         lang,
        'lang_options': LANG_OPTIONS,
        'error':        error,
    }


def build_report_ctx(analysis: dict, city: str, from_api: str,
                     to_api: str, lang: str) -> dict:
    """Flatten analysis data into plain values the report template can render."""
    periods     = analysis['threat_periods']
    fp_warnings = analysis['false_positive_warnings']
    fp_count    = len(fp_warnings)
    warn_count  = analysis['total_warnings']
    fp_ratio    = (fp_count / warn_count * 100) if warn_count else 0.0

    lead_times = [
        (p.start - p.warning_time).total_seconds()
        for p in periods
        if p.had_warning and p.warning_time and not p.ongoing
    ]
    closed = [p.duration for p in periods if not p.ongoing]

    period_rows = []
    for i, p in enumerate(periods, 1):
        if p.had_warning and p.warning_time:
            secs = int((p.start - p.warning_time).total_seconds())
            m, s = divmod(secs, 60)
            warn_lead = f'+{m}m{s:02d}s'
        else:
            warn_lead = None

        period_rows.append({
            'index':             i,
            'start':             p.start.strftime('%Y-%m-%d %H:%M:%S'),
            'end':               p.end.strftime('%Y-%m-%d %H:%M:%S') if not p.ongoing else None,
            'duration':          format_duration(p.duration),
            'ongoing':           p.ongoing,
            'warn_lead':         warn_lead,
            'consecutive_count': p.consecutive_count,
        })

    fp_rows = [
        {
            'index':     i,
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S') if ts else '—',
        }
        for i, (_, ts, _cat) in enumerate(fp_warnings, 1)
    ]

    # Newest first; indices already reflect chronological order (1 = oldest)
    period_rows.reverse()
    fp_rows.reverse()

    tcp = analysis['category_counts']

    return {
        'city_display':        analysis['city_display'] or city,
        'from_date':           from_api,
        'to_date':             to_api,
        'lang_name':           LANG_NAMES.get(lang, lang),
        'total_records':       analysis['total_alerts'],
        'actual_count':        analysis['actual_alerts'],
        'period_count':        len(periods),
        'with_hup':            analysis['periods_with_headup'],
        'without_hup':         analysis['periods_without_headup'],
        'total_dur':           format_duration(analysis['total_duration']),
        'avg_dur':             format_duration(sum(closed) / len(closed)) if closed else 'N/A',
        'max_dur':             format_duration(max(closed)) if closed else 'N/A',
        'warning_count':       warn_count,
        'fp_count':            fp_count,
        'fp_ratio':            fp_ratio,
        'avg_lead':            format_duration(sum(lead_times) / len(lead_times)) if lead_times else 'N/A',
        'cat_rocket':          tcp.get(1, 0),
        'cat_aircraft':        tcp.get(2, 0),
        'cat_allclear':        tcp.get(13, 0),
        'cat_headup':          tcp.get(14, 0),
        'true_positive_count': warn_count - fp_count,
        'period_rows':         period_rows,
        'fp_rows':             fp_rows,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    ctx = form_ctx(
        from_val=api_to_html_date(DEFAULT_FROM),
        to_val=datetime.now().strftime('%Y-%m-%d'),
    )
    return render_template('index.html', **ctx)


@app.route('/report')
def report():
    city      = request.args.get('city', '').strip()
    from_html = request.args.get('from_date', '')
    to_html   = request.args.get('to_date', '')
    lang      = request.args.get('lang', 'he')

    from_v = from_html or api_to_html_date(DEFAULT_FROM)
    to_v   = to_html   or datetime.now().strftime('%Y-%m-%d')

    def render_form(error='', status=200):
        ctx = form_ctx(city=city, from_val=from_v, to_val=to_v, lang=lang, error=error)
        return render_template('index.html', **ctx), status

    if not city:
        return render_form('City name is required.')

    from_api = html_to_api_date(from_v)
    to_api   = html_to_api_date(to_v)

    try:
        alerts = fetch_alert_history(from_api, to_api, city, lang)
    except Exception as e:
        return render_form(f'Failed to fetch data from the Oref API: {e}', status=502)

    if not alerts:
        return render_form(
            f'No alert records found for \u201c{city}\u201d ({lang.upper()}) '
            f'between {from_api} and {to_api}. '
            'Verify the city name spelling \u2014 it must match the selected language.'
        )

    analysis = analyze_alerts(alerts, city_filter=city)

    ctx = {
        **form_ctx(city=city, from_val=from_v, to_val=to_v, lang=lang),
        **build_report_ctx(analysis, city, from_api, to_api, lang),
    }
    return render_template('report.html', **ctx)


@app.route('/raw-data')
def raw_data():
    city      = request.args.get('city', '').strip()
    from_html = request.args.get('from_date', '')
    to_html   = request.args.get('to_date', '')
    lang      = request.args.get('lang', 'he')

    from_v = from_html or api_to_html_date(DEFAULT_FROM)
    to_v   = to_html   or datetime.now().strftime('%Y-%m-%d')

    oref_url = build_oref_url(html_to_api_date(from_v), html_to_api_date(to_v), city, lang)
    return redirect(oref_url)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tzeva Adom Stats web server')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--debug', action='store_true', default=False, help='Enable Flask debug mode')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)

# ────────────────────────────────────────────────────────────────────────────

