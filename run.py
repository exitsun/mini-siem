import argparse
from pathlib import Path
from datetime import datetime
from mini_siem.ingest import load_folder
from mini_siem.normalize import normalize
from mini_siem.engine import run_all
from mini_siem.report import write_reports

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True, help="Folder z plikami logów (json/ndjson/csv/log)")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--out", default="reports")
    args = ap.parse_args()

    raw = load_folder(args.path)
    if raw.empty:
        print("No files in --path"); return

    df = normalize(raw)
    findings = run_all(df, args.rules)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    outdir = Path(args.out) / ts
    write_reports(findings, outdir)
    print("Report →", outdir)

if __name__ == "__main__":
    main()
