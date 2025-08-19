import pandas as pd
from dateutil import parser
import re

def _to_ts(v):
    try: return parser.parse(str(v), ignoretz=True)
    except: return pd.NaT

def normalize(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)

    # timestamp
    for col in ("@timestamp","TimeCreated","timestamp","time","date"):
        if col in df:
            out["timestamp"] = df[col].map(_to_ts)
            break
    if "timestamp" not in out: out["timestamp"] = pd.NaT

    # podstawowe pola
    if "EventID" in df: out["event_id"] = df["EventID"]
    elif "Id" in df:    out["event_id"] = df["Id"]
    elif "event_id" in df: out["event_id"] = df["event_id"]

    if "TargetUserName" in df: out["user"] = df["TargetUserName"]
    if "Computer" in df:       out["host"] = df["Computer"]
    if "MachineName" in df:    out["host"] = df["MachineName"]

    # message
    out["message"] = df.get("Message") or df.get("msg") or df.get("MESSAGE") or df.get("raw")

    # ŹRÓDŁA WINDOWS
    if "event_id" in out:
        out.loc[out["event_id"]==4625, "source"] = "windows.security"
        out.loc[out["event_id"]==4104, "source"] = "powershell.4104"
        out.loc[out["event_id"]==1,    "source"] = "sysmon.1"

    # JOUNALD / SSH (gdy mamy kolumnę MESSAGE albo raw)
    msg = out["message"].fillna("")
    # Failed password: wyciągnij user i src_ip
    m = msg.str.extract(r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<src_ip>[\d\.]+).*')
    out.loc[m.index, "user"] = out.get("user", m["user"]).fillna(m["user"])
    out.loc[m.index, "src_ip"] = m["src_ip"]
    out.loc[msg.str.contains(r"Failed password", case=False, na=False).index, "source"] = \
        out.get("source", pd.Series(index=df.index)).fillna("linux.ssh")

    # host z journald
    if "_HOSTNAME" in df: out["host"] = df["_HOSTNAME"]

    out["__sourcefile"] = df["__sourcefile"]
    return out
