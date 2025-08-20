# mini-siem

Minimal SIEM pipeline: **ingest → normalize → detections → CSV/HTML report**.

## Quick start

### download project

### create a virtual environment outside the src folder

    python3 -m venv .venv
    source .venv/bin/activate

### download dependiencies

    pip install -e .

### run

    python3 run.py --path data/raw/ --rules rules --out reports/

## Example report

[image]: https://github.com/exitsun/mini-siem/blob/main/assets/example-report-html.png
