import yaml, pandas as pd
from datetime import timedelta

def parse_window(s: str) -> timedelta:
    n, u = int(s[:-1]), s[-1].lower()
    return timedelta(minutes=n) if u == "m" else timedelta(seconds=n)

def run_rule(df: pd.DataFrame, rule: dict) -> pd.DataFrame:
    data = df.copy()

    src = rule.get("when", {}).get("source")
    if src:
        data = data[data["source"] == src]

    flt = rule.get("when", {}).get("filter", {})
    if "event_id" in flt:
        data = data[data["event_id"] == flt["event_id"]]
    if "pattern" in flt:
        data = data[data["message"].fillna("").str.contains(flt["pattern"], regex=True, na=False)]

    grp = rule.get("group_by", "user")
    if grp not in data.columns:
        data[grp] = "n/a"

    data = data.dropna(subset=["timestamp"]).sort_values("timestamp")

    win = parse_window(rule.get("window", "10m"))
    thr = int(rule.get("threshold", 1))

    findings = []
    for key, g in data.groupby(grp):
        if g.empty: continue
        t_end = g["timestamp"].max()
        gwin = g[g["timestamp"] >= t_end - win]
        if len(gwin) >= thr:
            findings.append({
                "SamAccountName": key,
                "Reason":   rule["reason"],
                "Severity": rule["severity"],
                "When":     str(t_end),
                "SourceFile": ";".join(sorted(set(gwin["__sourcefile"])))[-200:]
            })
    return pd.DataFrame(findings)

def run_all(df: pd.DataFrame, rules_dir: str) -> pd.DataFrame:
    from pathlib import Path
    outs = []
    for p in Path(rules_dir).glob("*.yml"):
        rule = yaml.safe_load(p.read_text(encoding="utf-8"))
        outs.append(run_rule(df, rule))
    return pd.concat(outs, ignore_index=True) if outs else pd.DataFrame()
