# mini-siem

Minimal SIEM pipeline: **ingest → normalize → detections → CSV/HTML report**.

## Quick start

### download project

    git clone https://github.com/exitsun/mini-siem

### create a virtual environment outside the src folder

    python3 -m venv .venv
    source .venv/bin/activate

### download dependiencies

    pip install -e .

### run

    python3 run.py --path data/raw/ --rules rules --out reports/

## How does it work:

1. Ingests logs from --path
2. Detects and normalizes according to the --rules specified
3. Outputs a CSV and HTML report into the --out reports/<date> folder

## Example report

![image](https://github.com/exitsun/mini-siem/blob/main/assets/example-report-html.png "Example Html Report")

### TODO

- add tests
- add workflow file
- add badges + license
