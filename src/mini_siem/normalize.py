import pandas as pd
from dateutil import parser
from typing import Iterable
import re

# --- helpers -----------------------------------------------------------------

def _to_ts(v):
    try:
        return parser.parse(str(v), ignoretz=True)
    except Exception:
        return pd.NaT

def coalesce_cols(df: pd.DataFrame, cols: Iterable[str], default=pd.NA) -> pd.Series:
    """Zwróć pierwszą niepustą kolumnę z listy `cols` (per wiersz), bez bfill/Warnings."""
    cols = [c for c in cols if c in df.columns]
    if not cols:
        return pd.Series(default, index=df.index)
    s = df[cols[0]]
    for c in cols[1:]:
        s = s.combine_first(df[c])
    return s

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

    s = series.map(_norm)
    s_str = s.astype(str)

    # JSON.NET: /Date(1755595339563)/
    ms = s_str.str.extract(r"/Date\((\d+)\)/")[0]
    out = pd.to_datetime(ms, unit="ms", errors="coerce")

    # Fallback: ISO / inne formy
    mask = out.isna()
    if mask.any():
        out.loc[mask] = pd.to_datetime(s_str[mask], errors="coerce")
    return out

# --- main --------------------------------------------------------------------

def normalize(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)

    # === TIMESTAMP ===
    if "__REALTIME_TIMESTAMP" in df.columns:
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

    # MESSAGE (pierwsza niepusta)
    out["message"] = coalesce_cols(df, ["Message", "msg", "MESSAGE", "raw"])
    msg = out["message"].fillna("")

    # SOURCE: przygotowanie
    if "source" not in out.columns:
        out["source"] = pd.Series(pd.NA, index=df.index)
    sid  = df["SYSLOG_IDENTIFIER"].astype(str).str.lower() if "SYSLOG_IDENTIFIER" in df.columns else pd.Series("", index=df.index)
    unit = df["_SYSTEMD_UNIT"].astype(str).str.lower()     if "_SYSTEMD_UNIT"     in df.columns else pd.Series("", index=df.index)

    # --- Windows po event_id ---
    if "event_id" in out.columns:
        out.loc[out["event_id"] == 4625, "source"] = "windows.security"
        out.loc[out["event_id"] == 4104, "source"] = "powershell.4104"
        out.loc[out["event_id"] == 1,    "source"] = "sysmon.1"

    # --- Linux: specyficzne najpierw, potem fallback ---
    # SUDO (kilka wariantów; bez grup przechwytujących w contains)
    is_sudo = (
    msg.str.contains(r'(?:pam_unix\(sudo:auth\):\s*(?:authentication failure|conversation failed|auth could not identify password))', case=False, na=False)
    | sid.eq("sudo")
    | msg.str.contains(r'^\s*sudo:\s+.*?(?:authentication failure|incorrect password)', case=False, na=False)
    )
    out.loc[is_sudo, "source"] = "linux.sudo"


    # AppArmor
    is_apparmor = msg.str.contains(r'apparmor="(?:DENIED|ALLOWED)"', case=False, na=False)
    out.loc[is_apparmor, "source"] = "linux.apparmor"

    # SSH
    is_ssh = (unit.str.contains("sshd", na=False) | sid.eq("sshd")) & msg.str.contains(r'Failed password', case=False, na=False)
    out.loc[is_ssh, "source"] = "linux.ssh"

    # Fallback: journald (jeśli jeszcze pusto i to w ogóle journald)
    if "__REALTIME_TIMESTAMP" in df.columns:
        out.loc[out["source"].isna(), "source"] = "linux.journald"

    # === EKSTRAKCJE Z WIADOMOŚCI ===

    # Linux SSH: user + src_ip (IPv4/IPv6)
    m_ssh = msg.str.extract(r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<src_ip>[0-9a-fA-F:\.]+)')
    if "user" in out.columns:
        out["user"] = out["user"].fillna(m_ssh["user"])
    else:
        out["user"] = m_ssh["user"]
    out["src_ip"] = m_ssh["src_ip"]

    # --- SUDO: kto?, na kogo? (target), TTY, COMMAND ---

    # --- SUDO: kto? (actor), na kogo? (target), TTY, COMMAND ---

    sudo_mask = out["source"].eq("linux.sudo")

    # a) kandydat aktora (jak masz w kodzie)
    m_ruser   = msg.str.extract(r'\bruser=(?P<ruser>\S+)', flags=re.IGNORECASE)
    m_logname = msg.str.extract(r'\blogname=(?P<logname>\S+)', flags=re.IGNORECASE)
    m_userkv  = msg.str.extract(r'(?<!r)\buser=(?P<user>\S+)', flags=re.IGNORECASE)  # UWAGA: to zwykle target przy session/opened
    m_prefix  = msg.str.extract(r'^\s*sudo:\s*(?P<prefix>[a-z_][a-z0-9_-]*)\s*:', flags=re.IGNORECASE)
    m_brack   = msg.str.extract(r'for\s*\[(?P<brack>[^\]]+)\]', flags=re.IGNORECASE)

    # b) format syslog sudo: "<lead> : TTY=... ; USER=<target> ; COMMAND=..."
    lead = pd.Series(pd.NA, index=df.index, dtype="string")
    lead_mask = sudo_mask & (sid.eq("SYSLOG_IDENTIFIER","").astype(str).str.lower() == "sudo")
    lead.loc[lead_mask] = msg[lead_mask].str.extract(
        r'^\s*(?P<lead>[a-z_][a-z0-9_-]*)\s*:\s*TTY=',
        flags=re.IGNORECASE
    )["lead"]

    # c) session opened: "session opened for user <target> ... by <actor>(uid=...)"
    m_sess = msg.str.extract(
        r'session opened for user\s+(?P<target_sess>[^\s\(\)]+).*?\sby\s+(?P<actor>[^\s\(\)]+)\(uid=',
        flags=re.IGNORECASE
    )

    # d) target z pola USER= w komunikacie sudo
    m_target_kv = msg.str.extract(r'\bUSER=(?P<target_kv>[a-z_][a-z0-9_-]*)', flags=re.IGNORECASE)

    # e) COMMAND=
    m_cmd = msg.str.extract(r'\bCOMMAND=(?P<command>.+)$', flags=re.IGNORECASE)

    # actor (user): ruser → logname → lead → [brackets] → prefix → session.actor → (fallback) user=
    sudo_actor = (
        m_ruser["ruser"]
        .combine_first(m_logname["logname"])
        .combine_first(lead)
        .combine_first(m_brack["brack"])
        .combine_first(m_prefix["prefix"])
        .combine_first(m_sess["actor"])
        .combine_first(m_userkv["user"])
    ).replace("", pd.NA).astype("string")

    # target_user TYLKO z: session target ORAZ/ALBO USER= (NIE z 'user=' w auth failure)
    sudo_target = (
        m_sess["target_sess"]
        .combine_first(m_target_kv["target_kv"])
    ).replace("", pd.NA).astype("string")

    # TTY (łap 'TTY=' i 'tty=')
    m_tty = msg.str.extract(r'\b(?:TTY|tty)=(?P<tty>\S+)', flags=re.IGNORECASE)["tty"]

    # wpisy do out
    if "user" in out.columns:
        out.loc[sudo_mask, "user"] = out.loc[sudo_mask, "user"].fillna(sudo_actor[sudo_mask])
    else:
        out["user"] = pd.Series(pd.NA, index=df.index, dtype="string")
        out.loc[sudo_mask, "user"] = sudo_actor[sudo_mask]

    out["target_user"] = out.get("target_user", pd.Series(pd.NA, index=df.index, dtype="string"))
    out.loc[sudo_mask, "target_user"] = out.loc[sudo_mask, "target_user"].fillna(sudo_target[sudo_mask])

    out["tty"] = out.get("tty", pd.Series(pd.NA, index=df.index))
    out.loc[sudo_mask, "tty"] = out.loc[sudo_mask, "tty"].fillna(m_tty[sudo_mask])

    out["command"] = out.get("command", pd.Series(pd.NA, index=df.index, dtype="string"))
    out.loc[sudo_mask, "command"] = out.loc[sudo_mask, "command"].fillna(m_cmd["command"][sudo_mask])

    # propagacja usera w obrębie tej samej TTY
    sudo_idx = out.index[sudo_mask]
    if len(sudo_idx):
        tmp = out.loc[sudo_idx, ["timestamp","tty","user"]].sort_values(["tty","timestamp"])
        filled = tmp.groupby("tty", dropna=False)["user"].ffill().bfill()
        out.loc[sudo_idx, "user"] = out.loc[sudo_idx, "user"].fillna(filled)



    # AppArmor: action/profile/process/fsuid/ouid + mapowanie UID→user (jeśli brak)
    # --- AppArmor: detale + uid→user map ---
   # --- AppArmor: klasyfikacja + key=value parser ---
    is_apparmor = msg.str.contains(r'apparmor="(?:DENIED|ALLOWED)"', case=False, na=False)
    out.loc[is_apparmor, "source"] = "linux.apparmor"

    def _aa_parse_line(s: str):
        if not isinstance(s, str):
            return {}
        kv = {}
        # quoted: key="value"
        for k, v in re.findall(r'([A-Za-z_][A-Za-z0-9_]+)="([^"]*)"', s):
            kv[k] = v
        # unquoted: key=value (nie-nawiasowe, bez cudzysłowu)
        for k, v in re.findall(r'([A-Za-z_][A-Za-z0-9_]+)=([^\s"]+)', s):
            kv.setdefault(k, v)  # nie nadpisuj wersji w cudzysłowie
        # zmapuj nazwy na nasze kolumny
        return {
            "aa_action":   kv.get("apparmor"),
            "aa_operation":kv.get("operation"),
            "aa_class":    kv.get("class"),
            "aa_profile":  kv.get("profile"),
            "aa_name":     kv.get("name"),
            "process":     kv.get("comm"),
            "pid":         kv.get("pid"),
            "fsuid":       kv.get("fsuid"),
            "ouid":        kv.get("ouid"),
        }

    # parsuj tylko wiersze apparmor
    aa_rows = msg.where(is_apparmor, None).apply(_aa_parse_line)
    aa_df = pd.DataFrame(list(aa_rows.values), index=msg.index)

    for col in ["aa_action","aa_operation","aa_class","aa_profile","aa_name","process","pid","fsuid","ouid"]:
        if col not in out.columns:
            out[col] = pd.Series(pd.NA, index=df.index)
        out.loc[is_apparmor, col] = aa_df.loc[is_apparmor, col]

    # UID→user (jeśli wciąż brak)
    uid_series = out.loc[is_apparmor, "fsuid"].where(out.loc[is_apparmor, "fsuid"].notna(),
                                                    out.loc[is_apparmor, "ouid"])
    _uid_map = {"0": "root", "33": "www-data", "65534": "nobody"}
    user_guess = uid_series.map(_uid_map)
    need_user = is_apparmor & out["user"].isna()
    out.loc[need_user, "user"] = user_guess[need_user]


    # Windows 4625: user z sekcji "Account For Which Logon Failed"
    if "event_id" in out.columns:
        is_4625 = out["event_id"].astype("Int64") == 4625
        m2 = msg.str.extract(r"(?s)Account For Which Logon Failed:.*?Account Name:\s+(?P<wuser>[^\r\n]+)")
        wuser = m2["wuser"].str.strip()
        mask = is_4625 & wuser.notna()
        if "user" in out.columns:
            out.loc[mask, "user"] = wuser[mask]
        else:
            out["user"] = pd.Series(pd.NA, index=df.index)
            out.loc[mask, "user"] = wuser[mask]

    # === META ===
    out["__sourcefile"] = df["__sourcefile"] if "__sourcefile" in df.columns else pd.NA

    return out
