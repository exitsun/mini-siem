import yaml, pandas as pd
from datetime import timedelta
from pathlib import Path

def parse_window(s: str) -> timedelta:
    n, u = int(s[:-1]), s[-1].lower()
    return timedelta(minutes=n) if u == "m" else timedelta(seconds=n)

def _prepare_group_key(data: pd.DataFrame, grp_spec):
    """Obsłuż group_by jako string LUB lista kolumn (pierwsza niepusta)."""
    df = data.copy()
    if isinstance(grp_spec, list):
        def _first_nonempty(row):
            for c in grp_spec:
                if c in row and pd.notna(row[c]) and str(row[c]).strip():
                    return str(row[c])
            return "n/a"
        df["_grp"] = df.apply(_first_nonempty, axis=1)
        return df, "_grp"
    else:
        col = grp_spec or "user"
        if col not in df.columns:
            df[col] = "n/a"
        else:
            df[col] = df[col].fillna("n/a")
        return df, col

def run_rule(df: pd.DataFrame, rule: dict) -> pd.DataFrame:
    data = df.copy()

    # --- filtr po source i filtrze ---
    src = rule.get("when", {}).get("source")
    if src:
        data = data[data["source"] == src]

    flt = rule.get("when", {}).get("filter", {})
    if "event_id" in flt:
        data = data[data["event_id"] == flt["event_id"]]
    if "pattern" in flt:
        data = data[data["message"].fillna("").str.contains(flt["pattern"], regex=True, na=False)]

    # --- timestamp: nie wycinaj, tylko uzupełnij gdy trzeba ---
    if data["timestamp"].isna().any():
        na_mask = data["timestamp"].isna()
        if "__sourcefile" in data.columns:
            def _mtime_to_ts(p):
                try: return pd.to_datetime(Path(p).stat().st_mtime, unit="s")
                except Exception: return pd.NaT
            fill = data.loc[na_mask, "__sourcefile"].map(_mtime_to_ts)
            data.loc[na_mask, "timestamp"] = fill
        data["timestamp"] = data["timestamp"].fillna(pd.Timestamp.utcnow())

    data = data.sort_values("timestamp")

    # --- grupowanie (string albo lista kolumn) ---
    data, grp_col = _prepare_group_key(data, rule.get("group_by", "user"))

    win = parse_window(rule.get("window", "10m"))
    thr = int(rule.get("threshold", 1))

    findings = []
    for key, g in data.groupby(grp_col, dropna=False):
        if g.empty: 
            continue
        t_end = g["timestamp"].max()
        gwin = g[g["timestamp"] >= t_end - win]
        if len(gwin) >= thr:
            findings.append({
                "SamAccountName": str(key),  # zawsze string, nie tuple
                "Reason":   rule["reason"],
                "Severity": rule["severity"],
                "When":     str(t_end),
                "SourceFile": ";".join(sorted(set(gwin["__sourcefile"])))[-200:]
            })
    return pd.DataFrame(findings)

def run_all(df: pd.DataFrame, rules_dir: str) -> pd.DataFrame:
    outs = []
    for p in Path(rules_dir).glob("*.yml"):
        rule = yaml.safe_load(p.read_text(encoding="utf-8"))
        outs.append(run_rule(df, rule))
    return pd.concat(outs, ignore_index=True) if outs else pd.DataFrame()
