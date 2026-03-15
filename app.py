#!/usr/bin/env python3
"""
Red Alert Stats - Web Server

Run:  python app.py [--host HOST] [--port PORT] [--debug]
Open: http://localhost:5000
"""

import argparse
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests
from flask import Flask, jsonify, redirect, request, render_template
from analyzer import fetch_alert_history, analyze_alerts, format_duration, build_home_front_command_url, ALERT_TZ

app = Flask(__name__)

DEFAULT_FROM = '28.02.2026'


def _rle_alert_sequence(seq):
    """Run-length encode an alert category sequence.
    Returns a list of dicts: [{'cat': int, 'count': int}, ...]
    """
    if not seq:
        return []
    result = []
    current, count = seq[0], 1
    for item in seq[1:]:
        if item == current:
            count += 1
        else:
            result.append({'cat': current, 'count': count})
            current, count = item, 1
    result.append({'cat': current, 'count': count})
    return result

LANG_OPTIONS = [
    ('he', '🇮🇱', 'עברית'),
    ('en', '🇬🇧', 'English'),
    ('ru', '🇷🇺', 'Русский'),
    ('ar', '🇸🇦', 'العربية'),
]
LANG_NAMES = {code: label for code, _, label in LANG_OPTIONS}

_TRANSLATIONS_DIR = os.path.join(os.path.dirname(__file__), 'translations')
_TRANSLATIONS: dict[str, dict] = {}

def get_t(lang: str) -> dict:
    if lang not in _TRANSLATIONS:
        path = os.path.join(_TRANSLATIONS_DIR, f'{lang}.json')
        fallback = os.path.join(_TRANSLATIONS_DIR, 'en.json')
        try:
            with open(path, encoding='utf-8') as f:
                _TRANSLATIONS[lang] = json.load(f)
        except FileNotFoundError:
            with open(fallback, encoding='utf-8') as f:
                _TRANSLATIONS[lang] = json.load(f)
    return _TRANSLATIONS[lang]


# ── Date helpers ──────────────────────────────────────────────────────────────

def api_to_html_date(d: str) -> str:
    """'DD.MM.YYYY' → 'YYYY-MM-DD' for HTML date inputs."""
    try:
        return datetime.strptime(d, '%d.%m.%Y').strftime('%Y-%m-%d')
    except Exception:
        return ''


def html_to_api_date(d: str) -> str:
    """'YYYY-MM-DD' → 'DD.MM.YYYY' for the Home Front Command API."""
    try:
        return datetime.strptime(d, '%Y-%m-%d').strftime('%d.%m.%Y')
    except Exception:
        return d


# ── Template context builders ─────────────────────────────────────────────────

def form_ctx(city='', from_val='', to_val='', lang='he', error='', mode=3) -> dict:
    """Base context shared by all pages (populates the query form)."""
    return {
        'city':         city,
        'from_val':     from_val,
        'to_val':       to_val,
        'lang':         lang,
        'lang_options': LANG_OPTIONS,
        'error':        error,
        't':            get_t(lang),
        'dir':          'rtl' if get_t(lang).get('rtl') else 'ltr',
        'arabic_nums':  'true' if get_t(lang).get('arabic_numerals') else 'false',
        'mode':         mode,
    }


def build_charts_data(alerts: list, analysis: dict, city: str = '', date_range: list = None) -> dict:
    """Build JSON-serialisable chart data from raw alerts + analysis results."""
    if city:
        filtered = [a for a in alerts if a.get('data', '').strip() == city.strip()]
    else:
        filtered = alerts

    date_rockets:   dict = defaultdict(int)
    date_aircraft:  dict = defaultdict(int)
    date_warn_tp:   dict = defaultdict(int)
    date_warn_fp:   dict = defaultdict(int)
    hour_rockets:   dict = defaultdict(int)
    hour_aircraft:  dict = defaultdict(int)
    hour_warn_tp:   dict = defaultdict(int)
    hour_warn_fp:   dict = defaultdict(int)

    for alert in filtered:
        dt  = alert.get('alertPreciseDateTime')
        cat = alert.get('category')
        if dt is None:
            continue
        date_key = dt.strftime('%Y-%m-%d')
        hour     = dt.hour
        if cat == 1:
            date_rockets[date_key]  += 1
            hour_rockets[hour]      += 1
        elif cat == 2:
            date_aircraft[date_key] += 1
            hour_aircraft[hour]     += 1

    for warn_dt, is_tp in analysis['warnings'].items():
        date_key = warn_dt.strftime('%Y-%m-%d')
        hour     = warn_dt.hour
        if is_tp:
            date_warn_tp[date_key] += 1
            hour_warn_tp[hour]     += 1
        else:
            date_warn_fp[date_key] += 1
            hour_warn_fp[hour]     += 1

    data_dates = sorted(set(date_rockets) | set(date_aircraft) | set(date_warn_tp) | set(date_warn_fp))
    all_dates  = sorted(set(date_range) | set(data_dates)) if date_range else data_dates

    date_shelter_total:   dict = defaultdict(float)
    date_shelter_periods: dict = defaultdict(list)
    date_lead_times:      dict = defaultdict(list)
    for period in analysis['threat_periods']:
        if period.ongoing:
            continue
        dk = period.start.strftime('%Y-%m-%d')
        date_shelter_total[dk]   += period.duration
        date_shelter_periods[dk].append(period.duration)
        if period.had_warning and period.warning_time:
            lead = (period.start - period.warning_time).total_seconds()
            date_lead_times[dk].append(lead)

    shelter_dates = sorted(date_shelter_total.keys())
    shelter_full  = sorted(set(date_range) | set(shelter_dates)) if date_range else shelter_dates
    warn_dates    = sorted(date_lead_times.keys())
    warn_full     = sorted(set(date_range) | set(warn_dates)) if date_range else warn_dates
    merged_dates  = sorted(set(shelter_full) | set(warn_full))
    true_pos  = analysis['total_warnings'] - len(analysis['false_positive_warnings'])
    false_pos = len(analysis['false_positive_warnings'])

    return {
        'threats_per_date': {
            'dates':    all_dates,
            'has_data': bool(data_dates),
            'rockets':  [date_rockets.get(d, 0)   for d in all_dates],
            'aircraft': [date_aircraft.get(d, 0)  for d in all_dates],
            'warn_tp':  [date_warn_tp.get(d, 0)   for d in all_dates],
            'warn_fp':  [date_warn_fp.get(d, 0)   for d in all_dates],
        },
        'shelter_and_lead_per_date': {
            'dates':           merged_dates,
            'has_data':        bool(shelter_dates) or bool(warn_dates),
            'shelter_seconds': [round(date_shelter_total.get(d, 0)) for d in merged_dates],
            'lead_seconds':    [
                round(sum(date_lead_times[d])) if d in date_lead_times else 0
                for d in merged_dates
            ],
        },
        'threats_per_hour': {
            'hours':    list(range(24)),
            'rockets':  [hour_rockets.get(h, 0)   for h in range(24)],
            'aircraft': [hour_aircraft.get(h, 0)  for h in range(24)],
            'warn_tp':  [hour_warn_tp.get(h, 0)   for h in range(24)],
            'warn_fp':  [hour_warn_fp.get(h, 0)   for h in range(24)],
        },
        'threat_types': {
            'rockets':  analysis['category_counts'].get(1, 0),
            'aircraft': analysis['category_counts'].get(2, 0),
        },
        'warning_accuracy': {
            'true_positive':  true_pos,
            'false_positive': false_pos,
        },
        'shelter_by_type': {
            'warned':   analysis['periods_with_headup'],
            'surprise': analysis['periods_without_headup'],
        },
    }


def build_report_ctx(analysis: dict, city: str, from_api: str,
                     to_api: str, lang: str, mode: int = 0) -> dict:
    """Flatten analysis data into plain values the report template can render."""
    t = get_t(lang)
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
            lead_secs = int((p.start - p.warning_time).total_seconds())
            warn_lead = '+' + format_duration(lead_secs, t)
        else:
            warn_lead = None

        period_rows.append({
            'index':             i,
            'start':             p.start.strftime('%Y-%m-%d %H:%M:%S'),
            'end':               p.end.strftime('%Y-%m-%d %H:%M:%S') if not p.ongoing else None,
            'duration':          format_duration(p.duration, t),
            'ongoing':           p.ongoing,
            'warn_lead':         warn_lead,
            'consecutive_count': p.consecutive_count,
            'alert_icons':       _rle_alert_sequence(p.alert_sequence),
        })

    all_warnings = analysis['warnings']  # {datetime -> is_true_positive}
    warning_rows = [
        {
            'index':     i,
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S') if ts else '—',
            'is_tp':     is_tp,
        }
        for i, (ts, is_tp) in enumerate(
            sorted(all_warnings.items(), key=lambda x: x[0]), 1
        )
    ]

    # Newest first; indices already reflect chronological order (1 = oldest)
    period_rows.reverse()
    warning_rows.reverse()

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
        'total_dur':           format_duration(analysis['total_duration'], t),
        'avg_dur':             format_duration(sum(closed) / len(closed), t) if closed else 'N/A',
        'max_dur':             format_duration(max(closed), t) if closed else 'N/A',
        'warning_count':       warn_count,
        'fp_count':            fp_count,
        'fp_ratio':            fp_ratio,
        'avg_lead':            format_duration(sum(lead_times) / len(lead_times), t) if lead_times else 'N/A',
        'cat_rocket':          tcp.get(1, 0),
        'cat_aircraft':        tcp.get(2, 0),
        'cat_allclear':        tcp.get(13, 0),
        'cat_headup':          tcp.get(14, 0),
        'true_positive_count': warn_count - fp_count,
        'period_rows':         period_rows,
        'warning_rows':        warning_rows,
        'mode':                mode,
        'mode_label':          t.get(f'mode_{mode}', ''),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    lang = request.args.get('lang', 'he')
    try:
        mode = int(request.args.get('mode', 3))
        if mode not in (0, 1, 2, 3):
            mode = 3
    except (ValueError, TypeError):
        mode = 3
    ctx = form_ctx(
        lang=lang,
        from_val=api_to_html_date(DEFAULT_FROM),
        to_val=datetime.now().strftime('%Y-%m-%d'),
        mode=mode,
    )
    return render_template('index.html', **ctx)


@app.route('/report')
def report():
    city      = request.args.get('city', '').strip()
    from_html = request.args.get('from_date', '')
    to_html   = request.args.get('to_date', '')
    lang      = request.args.get('lang', 'he')
    try:
        mode = int(request.args.get('mode', 3))
        if mode not in (0, 1, 2, 3):
            mode = 3
    except (ValueError, TypeError):
        mode = 3

    from_v = from_html or api_to_html_date(DEFAULT_FROM)
    to_v   = to_html   or datetime.now().strftime('%Y-%m-%d')
    t      = get_t(lang)

    def render_form(error='', status=200):
        ctx = form_ctx(city=city, from_val=from_v, to_val=to_v, lang=lang, error=error, mode=mode)
        return render_template('index.html', **ctx), status

    if not city:
        return render_form(t.get('err_city_required', 'City name is required.'))

    from_api = html_to_api_date(from_v)
    to_api   = html_to_api_date(to_v)

    try:
        alerts = fetch_alert_history(from_api, to_api, city, lang, mode)
    except Exception as e:
        msg = t.get('err_fetch_failed', 'Failed to fetch data from the Home Front Command API: {detail}')
        return render_form(msg.format(detail=e), status=502)

    if not alerts:
        if mode == 0:
            msg = t.get('err_no_records',
                        'No alert records found for \u201c{city}\u201d between {from_date} and {to_date}. '
                        'Verify the city name spelling \u2014 it must match the selected language.')
            error_str = msg.format(city=city, from_date=from_api, to_date=to_api)
        else:
            msg = t.get('err_no_records_preset',
                        'No alert records found for \u201c{city}\u201d. '
                        'Verify the city name spelling \u2014 it must match the selected language.')
            error_str = msg.format(city=city)
        return render_form(error_str)

    analysis = analyze_alerts(alerts, city_filter=city)

    # Build the full calendar date range for the query so bar charts show
    # every day in the selected range, including days with zero events.
    _today = datetime.now(ALERT_TZ).date()
    _MODE_DAYS = {1: 1, 2: 7, 3: 30}
    if mode in _MODE_DAYS:
        _start = _today - timedelta(days=_MODE_DAYS[mode])
        _end   = _today
    else:
        try:
            _start = datetime.strptime(from_api, '%d.%m.%Y').date()
            _end   = datetime.strptime(to_api,   '%d.%m.%Y').date()
        except Exception:
            _start = _end = _today
    date_range = []
    _d = _start
    while _d <= _end:
        date_range.append(_d.strftime('%Y-%m-%d'))
        _d += timedelta(days=1)

    ctx = {
        **form_ctx(city=city, from_val=from_v, to_val=to_v, lang=lang, mode=mode),
        **build_report_ctx(analysis, city, from_api, to_api, lang, mode),
        'charts_data': build_charts_data(alerts, analysis, city, date_range),
    }
    return render_template('report.html', **ctx)


@app.route('/api/districts')
def api_districts():
    lang = request.args.get('lang', 'he')
    if lang not in LANG_NAMES:
        lang = 'he'
    try:
        resp = requests.get(
            'https://alerts-history.oref.org.il/Shared/Ajax/GetDistricts.aspx',
            params={'lang': lang},
            timeout=10,
        )
        resp.raise_for_status()
        return jsonify(resp.json())
    except Exception:
        return jsonify([]), 502


@app.route('/raw-data')
def raw_data():
    city      = request.args.get('city', '').strip()
    from_html = request.args.get('from_date', '')
    to_html   = request.args.get('to_date', '')
    lang      = request.args.get('lang', 'he')
    try:
        mode = int(request.args.get('mode', 3))
        if mode not in (0, 1, 2, 3):
            mode = 3
    except (ValueError, TypeError):
        mode = 3

    from_v = from_html or api_to_html_date(DEFAULT_FROM)
    to_v   = to_html   or datetime.now().strftime('%Y-%m-%d')

    home_front_command_url = build_home_front_command_url(html_to_api_date(from_v), html_to_api_date(to_v), city, lang, mode)
    return redirect(home_front_command_url)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Red Alert Stats web server')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on (default: 5000)')
    parser.add_argument('--debug', action='store_true', default=False, help='Enable Flask debug mode')
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=args.debug)

# ────────────────────────────────────────────────────────────────────────────

