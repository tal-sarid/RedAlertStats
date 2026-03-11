# Red Alert Stats

A small Python project for analyzing **Tzeva Adom (Oref)** alert history by city.

It includes:
- A Flask web app to generate a visual report.
- A CLI analyzer for terminal-based analysis and JSON import/export.

## Features

- Fetches alert history from the Oref alerts-history API.
- Analyzes threat periods (from threat start to all-clear).
- Computes warning quality metrics:
  - true positives
  - false positives
  - false positive ratio
  - average warning lead time
- Tracks shelter duration metrics:
  - total, average, and max duration
  - periods with and without head-up warnings
- Supports multiple API languages: `he`, `en`, `ru`, `ar`.
- Web report with sortable timeline-style output.

## Requirements

- Python 3.11+ recommended
- Dependencies listed in `requirements.txt`

## Setup

### Using scripts

#### Bash

```bash
./setup.sh
```

#### PowerShell (Windows)

```powershell
.\setup.ps1
```

### Manual setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run The Web App

### Using scripts

#### Bash

```bash
./run.sh [--host HOST] [--port PORT] [--debug]
```

#### PowerShell (Windows)

```powershell
.\run.ps1 [--host HOST] [--port PORT] [--debug]
```

### Manual run

```bash
python app.py [--host HOST] [--port PORT] [--debug]
```

### Server options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `localhost` | Host/IP to bind to. Use `0.0.0.0` to expose on all interfaces. |
| `--port` | `5000` | Port to listen on. |
| `--debug` | off | Enable Flask debug mode with auto-reload. |

Examples:

```bash
./run.sh --port 8080
./run.sh --host 0.0.0.0 --debug
```

```powershell
.\run.ps1 --port 8080
.\run.ps1 --host 0.0.0.0 --debug
```

Then open:
- http://localhost:5000

Use the form to choose:
- City name
- Date range
- Language

Notes:
- City name must match the selected language used by the API.
- Default start date is `28.02.2026`.

## CLI Usage

Basic examples:

```bash
python analyzer.py --city "תל אביב - מרכז העיר"
python analyzer.py --city "Tel Aviv - City Center" --lang en
python analyzer.py --from-date 01.03.2026 --to-date 10.03.2026 --city "תל אביב - מרכז העיר"
```

Available options:

- `--city`: city name in the selected language
- `--lang`: API language (`he`, `en`, `ru`, `ar`)
- `--from-date`: start date (`DD.MM.YYYY`)
- `--to-date`: end date (`DD.MM.YYYY`)
- `--raw-output FILE`: save fetched raw API data as pretty JSON
- `--raw-input FILE`: load alerts from local JSON instead of API

Example with local JSON:

```bash
python analyzer.py --raw-input data.json
```

## Project Structure

```text
analyzer.py        CLI analyzer and core analysis logic
app.py             Flask web app
requirements.txt   Python dependencies
data.json          Local/sample alert data
templates/         HTML templates
static/            CSS assets
```

## Data Source

Data is fetched from the public Oref alerts history endpoint:

- https://alerts-history.oref.org.il/Shared/Ajax/GetAlarmsHistory.aspx

## Disclaimer

This project is for informational and analytical purposes. Alert interpretation and safety decisions should always follow official Home Front Command guidance.
