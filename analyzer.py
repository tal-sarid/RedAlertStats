#!/usr/bin/env python3
"""Red Alert Analyzer - Analyze Israeli Home Front Command alert data from its API.

Usage:
  python analyzer.py --city "תל אביב - מרכז העיר"
  python analyzer.py --city "Tel Aviv - City Center" --lang en
  python analyzer.py --from-date 01.03.2026 --to-date 10.03.2026 --city "תל אביב - מרכז העיר"
"""

import json
import requests
import argparse
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import defaultdict
from typing import List, Dict, Tuple, Optional, NamedTuple

# Configuration constants
HEADUP_TIMEOUT_SECONDS = 1800  # 30 minutes - how long a head-up warning remains valid
ALERT_TZ = ZoneInfo('Asia/Jerusalem')  # All Home Front Command alert timestamps are in Israel time


class ThreatPeriod(NamedTuple):
    start: datetime
    end: datetime
    duration: float
    had_warning: bool
    warning_time: Optional[datetime]
    consecutive_count: int
    ongoing: bool = False
    alert_sequence: tuple = ()  # Chronological list of alert categories (1 or 2) in this period


def build_home_front_command_url(from_date: str, to_date: str, city_name: str, lang: str = 'he') -> str:
    """Build the Home Front Command alert history URL from API-format dates ('DD.MM.YYYY')."""
    from urllib.parse import urlencode
    base = 'https://alerts-history.oref.org.il/Shared/Ajax/GetAlarmsHistory.aspx'
    params = urlencode({
        'lang':     lang,
        'fromDate': from_date,
        'toDate':   to_date,
        'mode':     3,
        'city_0':   city_name,
    })
    return f'{base}?{params}'


def fetch_alert_history(from_date: str, to_date: str, city_name: str, lang: str = 'he') -> List[Dict]:
    """
    Fetch alert history from the Home Front Command API.

    Args:
        from_date: String in format 'DD.MM.YYYY'
        to_date: String in format 'DD.MM.YYYY'
        city_name: City name in the specified language
        lang: Language code (default: 'he' for Hebrew)

    Returns:
        List of alert dictionaries
    """
    try:
        response = requests.get(build_home_front_command_url(from_date, to_date, city_name, lang), timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []

def add_precise_datetime(alerts: List[Dict]) -> None:
    """Parse and add alertPreciseDateTime to each alert using 'date' and 'time' fields."""
    for alert in alerts:
        date_str = alert.get('date')  # format: DD.MM.YYYY
        time_str = alert.get('time')  # format: HH:MM:SS
        if not date_str or not time_str:
            alert['alertPreciseDateTime'] = None
            continue
        try:
            alert['alertPreciseDateTime'] = datetime.strptime(f"{date_str} {time_str}", "%d.%m.%Y %H:%M:%S").replace(tzinfo=ALERT_TZ)
        except Exception:
            alert['alertPreciseDateTime'] = None

def analyze_alerts(alerts: List[Dict], city_filter: Optional[str] = None) -> Dict:
    """
    Analyze alert data in a single pass to calculate counts and durations.

    Category meanings:
    - 1: "ירי רקטות וטילים" (Rocket fire - ACTUAL THREAT, requires shelter)
    - 2: "חדירת כלי טיס עוין" (Enemy aircraft infiltration - ACTUAL THREAT)
    - 13: "האירוע הסתיים" or "ניתן לצאת..." (Event ended - exit shelter)
    - 14: "בדקות הקרובות צפויות..." (Expected warning - may be false alarm)

    Args:
        alerts: List of alert dictionaries from API
        city_filter: Optional city name filter (in the language specified by lang)
        lang: Language code ('he', 'en', 'ru', 'ar')

    Returns:
        Dictionary with analysis results
    """

    # Filter by city if specified
    if city_filter:
        alerts = [a for a in alerts
                 if a.get('data', '').strip() == city_filter.strip()]

    total_alerts = len(alerts)
    category_counts = defaultdict(int)
    
    # Store city display name
    city_name = None
    city_display = None
    
    # Count categories upfront
    for alert in alerts:
        category = alert.get('category')
        category_counts[category] += 1
        
        if city_name is None:
            city_name = alert.get('data', 'Unknown').strip()
            city_display = city_name

    # Single pass through sorted alerts
    add_precise_datetime(alerts)  # Add precise datetime for better analysis
    alerts_sorted = sorted(alerts, key=lambda x: x.get('alertPreciseDateTime'))

    # Track warnings: (timestamp_str, is_true_positive)
    warnings = {}  # timestamp_str -> is_true_positive (bool)
    
    # Track threat periods
    threat_periods = []  # (start_dt, end_dt, duration, had_warning, warning_time, consecutive_count)
    
    active_threat_start = None
    active_threat_count = 0
    active_threat_had_warning = False
    active_threat_warning_time = None
    active_threat_sequence = []  # Chronological alert categories for the current period
    last_period_end_dt = None  # Warnings before this time are already consumed by a previous period

    for alert in alerts_sorted:
        category = alert.get('category')
        alert_datetime = alert.get('alertPreciseDateTime')

        # Category 14: Warning
        if category == 14:
            if alert_datetime not in warnings:
                warnings[alert_datetime] = False  # Initially not a true positive

        # Category 1 or 2: Threat alert
        elif category in (1, 2):
            if active_threat_start is None:
                # Start new threat period
                active_threat_start = alert_datetime
                active_threat_count = 1
                active_threat_had_warning = False
                active_threat_warning_time = None
                active_threat_sequence = [category]
                
                # Mark matching warnings as true positives (only fresh ones, after the last all-clear)
                for warning_dt in warnings:
                    if (alert_datetime - warning_dt).total_seconds() <= HEADUP_TIMEOUT_SECONDS:
                        if last_period_end_dt is None or warning_dt > last_period_end_dt:
                            warnings[warning_dt] = True
                            if active_threat_warning_time is None:
                                active_threat_warning_time = warning_dt
                                active_threat_had_warning = True
            else:
                # Continue existing threat period
                active_threat_count += 1
                active_threat_sequence.append(category)
                
                # Also mark newer warnings as true positives (same freshness guard as above)
                for warning_dt in warnings:
                    if warnings[warning_dt] is False:  # Not yet marked
                        if (alert_datetime - warning_dt).total_seconds() <= HEADUP_TIMEOUT_SECONDS:
                            if last_period_end_dt is None or warning_dt > last_period_end_dt:
                                warnings[warning_dt] = True

        # Category 13: All-clear
        elif category == 13:
            if active_threat_start is not None:
                # End threat period
                duration = (alert_datetime - active_threat_start).total_seconds()
                threat_periods.append(ThreatPeriod(
                    start=active_threat_start,
                    end=alert_datetime,
                    duration=duration,
                    had_warning=active_threat_had_warning,
                    warning_time=active_threat_warning_time,
                    consecutive_count=active_threat_count,
                    alert_sequence=tuple(active_threat_sequence)
                ))
                
                last_period_end_dt = alert_datetime
                active_threat_start = None
                active_threat_count = 0
                active_threat_had_warning = False
                active_threat_warning_time = None
                active_threat_sequence = []
            else:
                # All-clear with no active threat: the preceding warning window is closed,
                # so warnings before this point are no longer eligible as head-ups
                last_period_end_dt = alert_datetime

    # Calculate metrics
    total_warnings = len(warnings)

    # Capture any still-active threat period (no all-clear received yet)
    if active_threat_start is not None:
        now = datetime.now(ALERT_TZ)
        duration = (now - active_threat_start).total_seconds()
        threat_periods.append(ThreatPeriod(
            start=active_threat_start,
            end=now,
            duration=duration,
            had_warning=active_threat_had_warning,
            warning_time=active_threat_warning_time,
            consecutive_count=active_threat_count,
            ongoing=True,
            alert_sequence=tuple(active_threat_sequence)
        ))

    periods_with_headup = sum(1 for period in threat_periods if period.had_warning)
    periods_without_headup = len(threat_periods) - periods_with_headup
    total_duration = sum(period.duration for period in threat_periods)

    # False positive warnings: those not marked as true positives
    false_positive_warnings = [
        (city_name, ts, 14)
        for ts, is_true in warnings.items() if not is_true
    ]

    return {
        'total_alerts': total_alerts,
        'threat_periods': threat_periods,
        'warnings': warnings,
        'false_positive_warnings': false_positive_warnings,
        'total_warnings': total_warnings,
        'periods_with_headup': periods_with_headup,
        'periods_without_headup': periods_without_headup,
        'total_duration': total_duration,
        'category_counts': dict(category_counts),
        'city_name': city_name,
        'city_display': city_display,
        'actual_alerts': category_counts.get(1, 0) + category_counts.get(2, 0)
    }


def format_duration(seconds: float, t: dict | None = None) -> str:
    """Format seconds, omitting leading zero-valued units.

    With a translation dict supplies the unit labels (keys: dur_h, dur_m, dur_s).
    Falls back to the compact 'XhYmZs' style when no dict is provided.
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    if t:
        lh, lm, ls = t.get('dur_h', 'h'), t.get('dur_m', 'm'), t.get('dur_s', 's')
    else:
        lh, lm, ls = 'h', 'm', 's'
    parts = []
    if hours:
        parts.append(f"{hours}{lh}")
    if minutes or hours:
        parts.append(f"{minutes:02d}{lm}" if hours else f"{minutes}{lm}")
    parts.append(f"{secs:02d}{ls}" if (hours or minutes) else f"{secs}{ls}")
    return ' '.join(parts)


def print_analysis_report(analysis: Dict) -> None:
    """Print formatted analysis report."""

    print("\n=====================")
    print("ALERT ANALYSIS REPORT")
    print("=====================")

    city_display = analysis['city_display']
    actual_count = analysis['actual_alerts']
    period_count = len(analysis['threat_periods'])
    warning_count = analysis['total_warnings']
    false_positive_warnings = analysis['false_positive_warnings']
    false_positive_count = len(false_positive_warnings)
    periods_with_headup = analysis['periods_with_headup']
    periods_without_headup = analysis['periods_without_headup']

    # Calculate false positive ratio
    if warning_count > 0:
        false_positive_ratio = (false_positive_count / warning_count) * 100
    else:
        false_positive_ratio = 0

    # Calculate average warning lead time (only for closed periods with a warning)
    warning_lead_times = [
        (p.start - p.warning_time).total_seconds()
        for p in analysis['threat_periods']
        if p.had_warning and p.warning_time and not p.ongoing
    ]
    avg_warning_str = format_duration(sum(warning_lead_times) / len(warning_lead_times)) if warning_lead_times else "N/A"

    # Calculate average shelter duration (only closed periods)
    closed_durations = [p.duration for p in analysis['threat_periods'] if not p.ongoing]
    avg_shelter_str = format_duration(sum(closed_durations) / len(closed_durations)) if closed_durations else "N/A"

    print(f"\nCity: {city_display}")
    print(f"\n  Actual threat alerts: {actual_count}")
    print(f"    - Rocket fire: {analysis['category_counts'].get(1, 0)}")
    print(f"    - Enemy aircraft: {analysis['category_counts'].get(2, 0)}")
    print(f"\n  Shelter periods: {period_count}")
    print(f"    - With head-up warning: {periods_with_headup}")
    print(f"    - Without warning (surprise): {periods_without_headup}")
    print(f"    - Total time under shelter: {format_duration(analysis['total_duration'])}")
    print(f"    - Max time in shelter: {format_duration(max(closed_durations)) if closed_durations else 'N/A'}")
    print(f"    - Average time in shelter: {avg_shelter_str}")
    print(f"\n  Warning head-ups: {warning_count}")
    print(f"    - True positives (warnings followed by threats): {warning_count - false_positive_count}")
    print(f"    - False positives (warnings not followed by threats): {false_positive_count}")
    print(f"    - False positive ratio: {false_positive_ratio:.1f}%")
    print(f"    - Average warning lead time: {avg_warning_str}")

    # Shelter periods
    if analysis['threat_periods']:
        print(f"\n  Shelter timeline ({period_count} periods):")
        for period in analysis['threat_periods']:
            if period.ongoing:
                end_str = "now"
                duration_str = format_duration(period.duration) + "..."
            else:
                end_str = period.end.strftime('%H:%M:%S')
                duration_str = format_duration(period.duration)

            period_info = f"{period.start.strftime('%Y-%m-%d %H:%M:%S')} -> {end_str} ({duration_str})"

            additional_info = []

            if period.had_warning and period.warning_time:
                warning_to_alert = period.start - period.warning_time
                total_seconds = int(warning_to_alert.total_seconds())
                warning_minutes, warning_secs = divmod(total_seconds, 60)
                additional_info.append(f"+{warning_minutes}m{warning_secs:02d}s warning")
            else:
                additional_info.append("surprise")

            if period.consecutive_count > 1:
                additional_info.append(f"{period.consecutive_count} consecutive alerts")

            period_info += f" [{', '.join(additional_info)}]"
            print(f"    {period_info}")
    
    # Show all warnings with true/false positive labels
    all_warnings = analysis['warnings']
    if all_warnings:
        print(f"\n  Warning head-up log ({len(all_warnings)} total):")
        for ts in sorted(all_warnings):
            is_tp = all_warnings[ts]
            label = "[true positive] " if is_tp else "[false positive]"
            print(f"    {ts.strftime('%Y-%m-%d %H:%M:%S')}  {label}")

    print("")


def main():
    script_name = os.path.basename(__file__)
    parser = argparse.ArgumentParser(
        description='Analyze Red Alert data from the Home Front Command API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Examples:
  python {script_name} --city "תל אביב - מרכז העיר"
  python {script_name} --city "Tel Aviv - City Center" --lang en
  python {script_name} --from-date 01.03.2026 --to-date 10.03.2026 --city "תל אביב - מרכז העיר"
        '''
    )
    parser.add_argument(
        '--from-date',
        default='28.02.2026',
        help='Start date in DD.MM.YYYY format (default: 28.02.2026)'
    )
    parser.add_argument(
        '--to-date',
        default=datetime.now().strftime('%d.%m.%Y'),
        help='End date in DD.MM.YYYY format (default: today)'
    )
    parser.add_argument(
        '--city',
        help='City name in the requested language (by default in Hebrew; use --lang to specify other languages)'
    )
    parser.add_argument(
        '--lang',
        default='he',
        help='Language code for API: \'he\', \'en\', \'ru\', \'ar\' (default: he)'
    )
    parser.add_argument(
        '--raw-output',
        metavar='FILE',
        help='Save fetched alert data as pretty-printed JSON to this file path'
    )
    parser.add_argument(
        '--raw-input',
        metavar='FILE',
        help='Load alert data from a JSON file instead of fetching from the API'
    )

    args = parser.parse_args()

    from_date = args.from_date
    to_date = args.to_date
    city_name = args.city
    lang = args.lang
    raw_output_path = args.raw_output
    raw_input_path = args.raw_input

    if raw_input_path:
        with open(raw_input_path, 'r', encoding='utf-8') as f:
            alerts = json.load(f)
        print(f"Loaded {len(alerts)} alert records from {raw_input_path}.")
        if not city_name and alerts:
            city_name = alerts[0].get('data', '').strip()
            print(f"Auto-detected city: {city_name}")
    else:
        if not city_name:
            print("ERROR: --city is required when not using --raw-input")
            return
        print(f"\nFetching alerts from {from_date} to {to_date} for: {city_name}")
        alerts = fetch_alert_history(from_date, to_date, city_name, lang)
        if not alerts:
            print(f"ERROR: No alerts found. Check city name spelling (must be in {lang.upper()} language)")
            return
        print(f"Retrieved {len(alerts)} alert records.")

    if raw_output_path:
        with open(raw_output_path, 'w', encoding='utf-8') as f:
            json.dump(alerts, f, ensure_ascii=False, indent=4)
        print(f"Alert data saved to {raw_output_path}")

    # Analyze the alerts
    analysis = analyze_alerts(alerts, city_filter=city_name)

    # Display report
    print_analysis_report(analysis)


if __name__ == '__main__':
    main()
