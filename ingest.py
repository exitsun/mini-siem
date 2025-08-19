from pathlib import Path
import json, pandas as pd

def _read_jsonlike(p: Path) -> pd.DataFrame:
    txt = p.read_text(encoding="utf-8", errors="ignore")
    # NDJSON (JSON Lines)
    if "\n" in txt.strip():
        return pd.read_json(p, lines=True)
    # Pojedynczy JSON
    return pd.DataFrame([json.loads(txt)])

def read_any(p: Path) -> pd.DataFrame:
    suf = p.suffix.lower()
    if suf in {".json", ".ndjson"}:
        df = _read_jsonlike(p)
    elif suf == ".csv":
        df = pd.read_csv(p)
    else:
        # surowe logi (syslog/journalctl bez -o json) → jedna kolumna
        df = pd.read_csv(p, sep="\n", header=None, names=["raw"])
    df["__sourcefile"] = str(p)
    return df

def load_folder(folder: str) -> pd.DataFrame:
    files = [f for f in Path(folder).glob("*") if f.is_file()]
    frames = [read_any(f) for f in files]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
