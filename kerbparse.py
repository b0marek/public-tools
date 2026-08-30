#!/usr/bin/env python3
"""
kerbparse.py - wyciaga hashe Kerberoast (TGS-REP) z surowego outputu GetUserSPNs.py,
dzieli je wg typu szyfrowania i generuje gotowe komendy hashcata.

Uzycie:
    python3 kerbparse.py roast_raw.txt
    python3 kerbparse.py roast_raw.txt -o wyniki/ --csv
    python3 kerbparse.py roast_raw.txt --run --wordlist /usr/share/wordlists/rockyou.txt
    cat roast_raw.txt | python3 kerbparse.py -
"""

import argparse
import codecs
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


def read_text(path):
    """Czyta plik odgadujac kodowanie.

    PowerShell 5.1 przy przekierowaniu '>' zapisuje UTF-16LE, wiec plik ma
    bajty zerowe miedzy znakami - czytany jako UTF-8 nie pasuje do zadnego
    regexa, mimo ze w edytorze wyglada poprawnie.
    """
    data = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()

    boms = [
        (codecs.BOM_UTF32_LE, "utf-32-le"), (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be"),
    ]
    for bom, enc in boms:
        if data.startswith(bom):
            return data.decode(enc, errors="replace"), enc

    # Brak BOM - bajty zerowe zdradzaja UTF-16 zapisany bez naglowka.
    if b"\x00" in data[:4000]:
        head = data[:4000]
        enc = "utf-16-le" if head[1::2].count(0) > head[0::2].count(0) else "utf-16-be"
        return data.decode(enc, errors="replace"), enc + " (bez BOM)"

    return data.decode("utf-8", errors="replace"), "utf-8"


def resolve_hashcat(spec):
    """Zwraca absolutna sciezke do binarki hashcata albo None.

    Obsluguje: nazwe z PATH, sciezke do pliku .exe oraz sciezke do katalogu
    z hashcatem (wtedy sam dobiera hashcat.exe / hashcat.bin / hashcat).
    """
    if os.path.isdir(spec):
        for name in ("hashcat.exe", "hashcat.bin", "hashcat"):
            cand = os.path.join(spec, name)
            if os.path.isfile(cand):
                return os.path.abspath(cand)
        return None
    if os.path.isfile(spec):
        return os.path.abspath(spec)
    found = shutil.which(spec)
    return os.path.abspath(found) if found else None


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
    ap.add_argument("--hashcat", default="hashcat",
                    help="binarka hashcata: nazwa z PATH, sciezka do .exe "
                         "albo katalog, w ktorym lezy hashcat")
    ap.add_argument("--no-cd", action="store_true",
                    help="nie zmieniaj katalogu roboczego na folder hashcata")
    args = ap.parse_args()

    # Sciezki musza byc absolutne - hashcata odpalamy z jego wlasnego katalogu,
    # wiec wszystko relatywne rozjechaloby sie po zmianie cwd.
    args.outdir = os.path.abspath(args.outdir)
    args.wordlist = os.path.abspath(args.wordlist)
    if args.rules:
        args.rules = os.path.abspath(args.rules)

    text, enc = read_text(args.infile)

    entries = parse(text)
    if not entries:
        print("[-] Nie znalazlem zadnego hasha $krb5tgs$ w wejsciu.", file=sys.stderr)
        print(f"    Wykryte kodowanie : {enc}", file=sys.stderr)
        print(f"    Dlugosc tekstu    : {len(text)} znakow", file=sys.stderr)
        clean = text.replace("\x00", "")
        if "krb5tgs" in clean and "krb5tgs" not in text:
            print("    [!] 'krb5tgs' jest w pliku, ale rozdzielony bajtami zerowymi"
                  " - zle odgadniete kodowanie.", file=sys.stderr)
        elif "krb5tgs" in text:
            print("    [!] 'krb5tgs' wystepuje, ale nie pasuje do formatu"
                  " - hash moze byc obciety.", file=sys.stderr)
        else:
            print("    [!] Ciag 'krb5tgs' w ogole nie wystepuje - to chyba nie ten plik"
                  " albo GetUserSPNs uruchomiono bez -request.", file=sys.stderr)
        preview = text[:160].replace("\x00", "\\0").replace("\n", " | ")
        print(f"    Poczatek pliku    : {preview}", file=sys.stderr)
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
        binpath = resolve_hashcat(args.hashcat)
        if not binpath:
            print(f"\n[-] Nie znalazlem hashcata: {args.hashcat}", file=sys.stderr)
            print("    Podaj pelna sciezke, np. --hashcat C:\\tools\\hashcat\\hashcat.exe",
                  file=sys.stderr)
            return 1
        if not os.path.exists(args.wordlist):
            print(f"\n[-] Brak slownika: {args.wordlist}", file=sys.stderr)
            print("    Na Linuksie rockyou bywa spakowany:"
                  " gunzip /usr/share/wordlists/rockyou.txt.gz", file=sys.stderr)
            return 1

        # hashcat szuka OpenCL/, kernels/ i rules/ wzgledem biezacego katalogu,
        # wiec odpalamy go z miejsca, w ktorym lezy binarka.
        workdir = os.path.dirname(binpath) or None
        if args.no_cd:
            workdir = None
        if workdir:
            print(f"\n[*] Katalog roboczy hashcata: {workdir}")

        for cmd in cmds:
            cmd = [binpath] + cmd[1:]
            print(f"\n[*] Uruchamiam: {' '.join(cmd)}\n")
            # Kod 1 = slownik wyczerpany bez trafien, to nie blad.
            rc = subprocess.call(cmd, cwd=workdir)
            if rc not in (0, 1):
                print(f"[!] hashcat zakonczyl sie kodem {rc}", file=sys.stderr)
        if os.path.exists(pot):
            print(f"\n[+] Zlamane hasla: {pot}")
        else:
            print("\n[*] Brak trafien - zadne haslo nie zostalo zlamane.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
