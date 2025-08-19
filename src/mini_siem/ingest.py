from pathlib import Path
import json
import pandas as pd

def _read_jsonlike(p: Path) -> pd.DataFrame:
    txt = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not txt:
        return pd.DataFrame()

    # 1)
    try:
        obj = json.loads(txt)
        if isinstance(obj, list):
            return pd.DataFrame(obj)
        if isinstance(obj, dict):
            return pd.DataFrame([obj])
    except Exception:
        pass

    # 2) NDJSON:
    rows = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                return pd.DataFrame()  # nie-JSON → pozwól read_any potraktować jako raw
    return pd.DataFrame(rows)

def read_any(p: Path) -> pd.DataFrame:
    suf = p.suffix.lower()
    if suf in {".json", ".ndjson"}:
        df = _read_jsonlike(p)
        if df.empty:
            df = pd.read_csv(p, sep="\n", header=None, names=["raw"])
    elif suf == ".csv":
        df = pd.read_csv(p)
    else:
        df = pd.read_csv(p, sep="\n", header=None, names=["raw"])
    df["__sourcefile"] = str(p)
    return df

def load_folder(folder: str) -> pd.DataFrame:
    files = [f for f in Path(folder).glob("*") if f.is_file()]
    frames = [read_any(f) for f in files]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
