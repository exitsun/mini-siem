import pandas as pd
from dateutil import parser
from typing import Iterable
import re

def _to_ts(v):
    try:
        return parser.parse(str(v), ignoretz=True)
    except Exception:
        return pd.NaT

def coalesce_cols(df: pd.DataFrame, cols: Iterable[str], default=pd.NA) -> pd.Series:
    """Zwróć pierwszą niepustą kolumnę z listy `cols` (per wiersz)."""
    cols = [c for c in cols if c in df.columns]
    if cols:
        return df[cols].bfill(axis=1).iloc[:, 0]
    return pd.Series(default, index=df.index)

def _parse_timecreated(series: pd.Series) -> pd.Series:
    """Obsłuż TimeCreated jako dict (SystemTime/Value/Display), '/Date(ms)/' lub ISO."""
    def _norm(x):
        if isinstance(x, dict):
            for k in ("SystemTime", "Value", "Display"):
                v = x.get(k)
                if v:
                    return v
            return None
        return x

    s = series.map(_norm)                 # 1) spłaszcz dict → str/None
    s_str = s.astype(str)

    # 2) JSON.NET: /Date(1755595339563)/
    ms = s_str.str.extract(r"/Date\((\d+)\)/")[0]
    out = pd.to_datetime(ms, unit="ms", errors="coerce")

    # 3) Fallback: ISO / inne formy
    mask = out.isna()
    if mask.any():
        out.loc[mask] = pd.to_datetime(s_str[mask], errors="coerce")

    return out


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)

    # === TIMESTAMP ===
    if "__REALTIME_TIMESTAMP" in df.columns:
        # journald: mikrosekundy od epoki
        us = df["__REALTIME_TIMESTAMP"].astype(str).str.extract(r"(\d+)")[0].astype("Int64")
        out["timestamp"] = pd.to_datetime(us, unit="us", errors="coerce")
    elif "TimeCreated" in df.columns:
        out["timestamp"] = _parse_timecreated(df["TimeCreated"])
    else:
        for col in ("@timestamp", "timestamp", "time", "date"):
            if col in df.columns:
                out["timestamp"] = pd.to_datetime(df[col], errors="coerce")
                break
        if "timestamp" not in out.columns:
            out["timestamp"] = pd.NaT

    # === PODSTAWOWE POLA ===
    if "EventID" in df.columns:
        out["event_id"] = df["EventID"]
    elif "Id" in df.columns:
        out["event_id"] = df["Id"]
    elif "event_id" in df.columns:
        out["event_id"] = df["event_id"]

    if "TargetUserName" in df.columns:
        out["user"] = df["TargetUserName"]

    # host
    for h in ("Computer", "MachineName", "_HOSTNAME", "Hostname", "ComputerName"):
        if h in df.columns:
            out["host"] = df[h]
            break

    # === MESSAGE (pierwsza niepusta z kilku)
    out["message"] = coalesce_cols(df, ["Message", "msg", "MESSAGE", "raw"])

    # === SOURCE (klasyfikacja po event_id)
    if "event_id" in out.columns:
        out.loc[out["event_id"] == 4625, "source"] = "windows.security"
        out.loc[out["event_id"] == 4104, "source"] = "powershell.4104"
        out.loc[out["event_id"] == 1,    "source"] = "sysmon.1"

    # journald → linux.ssh gdy to sshd i mamy "Failed password"
    if "_SYSTEMD_UNIT" in df.columns:
        base   = pd.Series("linux.journald", index=df.index)
        is_ssh = df["_SYSTEMD_UNIT"].fillna("").str.contains("sshd", case=False)
        is_fail = out["message"].fillna("").str.contains("Failed password", case=False)
        src = base.copy()
        src[is_ssh & is_fail] = "linux.ssh"
        if "source" in out.columns:
            out["source"] = out["source"].fillna(src)
        else:
            out["source"] = src

    # === EKSTRAKCJE Z WIADOMOŚCI ===
    msg = out["message"].fillna("")

    # Linux SSH: user + src_ip (IPv4/IPv6)
    m = msg.str.extract(r"Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F:\.]+)")
    if "user" in out.columns:
        out["user"] = out["user"].fillna(m["user"])
    else:
        out["user"] = m["user"]
    out["src_ip"] = m["src_ip"]

    # Windows 4625: nadpisz 'user' wartością z "Account For Which Logon Failed"
    if "event_id" in out.columns:
        is_4625 = out["event_id"].astype("Int64") == 4625
    else:
        is_4625 = pd.Series(False, index=out.index)

    m2 = msg.str.extract(r"(?s)Account For Which Logon Failed:.*?Account Name:\s+(?P<wuser>[^\r\n]+)")
    wuser = m2["wuser"].str.strip()
    mask = is_4625 & wuser.notna()
    if "user" in out.columns:
        out.loc[mask, "user"] = wuser[mask]
    else:
        out["user"] = pd.Series(pd.NA, index=out.index)
        out.loc[mask, "user"] = wuser[mask]

    # === META ===
    out["__sourcefile"] = df["__sourcefile"] if "__sourcefile" in df.columns else pd.NA

    return out
