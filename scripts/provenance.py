#!/usr/bin/env python3
"""Justifie la provenance des commits depuis les archives locales de Claude Code.

Claude Code conserve chaque session sous forme de transcription JSON Lines
dans ~/.claude/projects/<dépôt>/<session>.jsonl. Ce script :

  trace <rév>     relie un commit aux sessions qui l'ont créé, ont ouvert ou
                  fusionné sa pull request, ou l'ont seulement mentionné ;
  report [rév…]   fait de même pour une plage (défaut : dev), en tableau ;
  archive         copie les transcriptions dans une archive immuable (objets
                  adressés par SHA-256), écrit un manifeste chaîné au précédent
                  et le fait horodater (RFC 3161) par une TSA tierce ;
  mirror          recopie l'archive vers des supports hors poste, sans rien
                  écraser (aussi fait à chaque `archive` si un miroir est configuré) ;
  verify          revérifie l'archive (ou un miroir, avec --archive) : objets,
                  chaîne des manifestes, jetons.

Les transcriptions contiennent tout ce que la session a lu ou affiché, secrets
compris : l'archive reste privée (droits 0700/0600), elle n'est jamais
commitée ni publiée, et n'est produite qu'à la demande (voir PROVENANCE.md).

Aucune dépendance hors de la bibliothèque standard ; `openssl` et `curl` pour
l'horodatage.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import getpass
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

CLAUDE_PROJECTS = Path(os.environ.get("CLAUDE_CONFIG_DIR", Path.home() / ".claude")) / "projects"
DEFAULT_ARCHIVE = Path(
    os.environ.get("OPENEIDAS_PROVENANCE_DIR", Path.home() / "archives" / "open-eidas" / "provenance")
)
# Copies hors poste (disque externe, NAS, stockage objet monté), séparées par « : ».
DEFAULT_MIRRORS = [m for m in os.environ.get("OPENEIDAS_PROVENANCE_MIRROR", "").split(os.pathsep) if m]
DEFAULT_TSAS = os.environ.get(
    "OPENEIDAS_PROVENANCE_TSA", "https://freetsa.org/tsr,http://timestamp.digicert.com"
).split(",")
AI_TRAILER = "Co-authored-by: Claude <noreply@anthropic.com>"

# Sortie de `git commit` : « [branche 1a2b3c4] objet » (ou « (root-commit) »).
COMMIT_OUT = re.compile(r"^\[([^\]\s]+)(?: \(root-commit\))? ([0-9a-f]{7,40})\] (.+)$", re.M)
PR_URL = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/pull/(\d+)")
PR_MERGE_CMD = re.compile(r"\bgh\s+pr\s+merge\s+(\d+)")
PR_IN_SUBJECT = re.compile(r"\(#(\d+)\)\s*$")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def repo_root() -> Path:
    return Path(git("rev-parse", "--show-toplevel").strip())


def project_slug(path: Path) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", str(path))


def project_slugs() -> set[str]:
    """Dossiers de ~/.claude/projects propres à ce dépôt : un par worktree (le
    dépôt principal compris), Claude Code nommant le dossier d'après le
    répertoire de travail de la session."""
    out = git("worktree", "list", "--porcelain")
    return {project_slug(Path(line[len("worktree "):])) for line in out.splitlines()
            if line.startswith("worktree ")}


# --------------------------------------------------------------------------
# Lecture des transcriptions


@dataclass
class Evidence:
    kind: str  # created | pr_opened | pr_merged | mentioned
    session: str
    file: Path
    timestamp: str
    detail: str


@dataclass
class Transcript:
    session: str
    file: Path
    created: list[tuple[str, str, str, str]] = field(default_factory=list)  # (court, branche, objet, horodatage)
    prs_opened: dict[str, str] = field(default_factory=dict)  # n° → horodatage
    prs_merged: dict[str, str] = field(default_factory=dict)
    # Commandes `git commit` réussies (texte sans échappements, horodatage) :
    # avec `-q`, git n'affiche pas « [branche hash] », seul le message relie
    # alors le commit à la session qui l'a rédigé.
    commit_cmds: list[tuple[str, str]] = field(default_factory=list)
    text: str = ""  # texte brut, pour les simples mentions


def result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
    return ""


def parse_transcript(path: Path) -> Transcript:
    t = Transcript(session=path.stem, file=path)
    commands: dict[str, str] = {}
    raw = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            raw.append(line)
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            t.session = entry.get("sessionId", t.session)
            when = entry.get("timestamp", "")
            content = (entry.get("message") or {}).get("content")
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_use":
                    cmd = (item.get("input") or {}).get("command")
                    if isinstance(cmd, str):
                        commands[item.get("id", "")] = cmd
                elif item.get("type") == "tool_result":
                    cmd = commands.get(item.get("tool_use_id", ""), "")
                    out = result_text(item.get("content"))
                    if "git commit" in cmd and item.get("is_error") is not True:
                        t.commit_cmds.append((cmd.replace("\\", ""), when))
                    if "git commit" in cmd or "git merge" in cmd:
                        for m in COMMIT_OUT.finditer(out):
                            t.created.append((m.group(2), m.group(1), m.group(3).strip(), when))
                    if "gh pr create" in cmd:
                        for m in PR_URL.finditer(out):
                            t.prs_opened.setdefault(m.group(1), when)
                    for m in PR_MERGE_CMD.finditer(cmd):
                        if item.get("is_error") is not True:
                            t.prs_merged.setdefault(m.group(1), when)
    t.text = "".join(raw)
    return t


def transcript_files(root: Path, archive: Path) -> list[Path]:
    slugs = project_slugs()
    files: dict[str, Path] = {}
    if CLAUDE_PROJECTS.is_dir():
        for d in CLAUDE_PROJECTS.iterdir():
            if d.name in slugs or any(d.name.startswith(s + "--claude-worktrees") for s in slugs):
                for p in d.rglob("*.jsonl"):
                    files[str(p.relative_to(CLAUDE_PROJECTS))] = p
    # Sessions archivées que Claude Code a pu purger depuis : la dernière
    # version archivée de chacune, décompressée à la volée.
    for rel, obj in latest_archived(archive).items():
        files.setdefault(rel, obj)
    return sorted(files.values())


def load_transcripts(root: Path, archive: Path) -> list[Transcript]:
    out = []
    for p in transcript_files(root, archive):
        if p.suffix == ".gz":
            with tempfile.NamedTemporaryFile("wb", suffix=".jsonl", delete=False) as tmp, gzip.open(p) as src:
                shutil.copyfileobj(src, tmp)
            t = parse_transcript(Path(tmp.name))
            os.unlink(tmp.name)
            t.file = p
        else:
            t = parse_transcript(p)
        out.append(t)
    return out


# --------------------------------------------------------------------------
# Rapprochement commit ↔ sessions


@dataclass
class Commit:
    sha: str
    subject: str
    author: str
    committer: str
    date: str
    ai_trailer: bool


def commits(revs: list[str]) -> list[Commit]:
    fmt = "%H%x1f%s%x1f%an <%ae>%x1f%cn <%ce>%x1f%aI%x1f%(trailers:key=Co-authored-by,valueonly,separator=%x2c)%x1e"
    out = git("log", f"--format={fmt}", *revs)
    result = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, subject, author, committer, date, trailers = rec.split("\x1f")
        result.append(Commit(sha, subject, author, committer, date,
                             "Claude <noreply@anthropic.com>" in trailers))
    return result


def normalize_subject(s: str) -> str:
    return PR_IN_SUBJECT.sub("", s).strip()


def evidence_for(c: Commit, transcripts: list[Transcript]) -> list[Evidence]:
    ev: list[Evidence] = []
    pr = PR_IN_SUBJECT.search(c.subject)
    subject = normalize_subject(c.subject)
    for t in transcripts:
        strong = False
        for short, branch, subj, when in t.created:
            if c.sha.startswith(short):
                ev.append(Evidence("created", t.session, t.file, when, f"[{branch} {short}] {subj}"))
                strong = True
            elif pr and normalize_subject(subj) == subject:
                ev.append(Evidence("created", t.session, t.file, when,
                                   f"commit de branche de même objet : [{branch} {short}] {subj}"))
                strong = True
        if not strong and len(subject) >= 12:
            for cmd, when in t.commit_cmds:
                if subject in cmd:
                    ev.append(Evidence("created", t.session, t.file, when,
                                       "message du commit rédigé dans une commande git commit réussie"))
                    strong = True
                    break
        if pr:
            n = pr.group(1)
            if n in t.prs_opened:
                ev.append(Evidence("pr_opened", t.session, t.file, t.prs_opened[n], f"PR #{n} ouverte"))
                strong = True
            if n in t.prs_merged:
                ev.append(Evidence("pr_merged", t.session, t.file, t.prs_merged[n], f"PR #{n} fusionnée"))
                strong = True
        if not strong and c.sha[:7] in t.text:
            ev.append(Evidence("mentioned", t.session, t.file, "", "hash cité (lecture seule)"))
    return ev


LABELS = {"created": "créé", "pr_opened": "PR ouverte", "pr_merged": "PR fusionnée", "mentioned": "mentionné"}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_trace(args) -> int:
    root = repo_root()
    sha = git("rev-parse", "--verify", f"{args.rev}^{{commit}}").strip()
    c = commits(["-1", sha])[0]
    print(f"commit      : {c.sha}")
    print(f"objet       : {c.subject}")
    print(f"auteur      : {c.author}")
    print(f"committer   : {c.committer}")
    print(f"date        : {c.date}")
    print(f"remorque IA : {'présente' if c.ai_trailer else 'absente'}")
    ev = evidence_for(c, load_transcripts(root, args.archive))
    if not ev:
        print("\naucune session locale ne se rapporte à ce commit")
        return 1
    print()
    for e in sorted(ev, key=lambda e: (e.kind == "mentioned", e.timestamp)):
        print(f"- {LABELS[e.kind]:<13} session {e.session}  {e.timestamp}")
        print(f"  {e.detail}")
        print(f"  fichier {e.file}")
        print(f"  sha256  {sha256_file(e.file)}")
    return 0


def cmd_report(args) -> int:
    root = repo_root()
    transcripts = load_transcripts(root, args.archive)
    rows = commits(args.revs or ["dev"])
    print("| Commit | Date | Objet | Remorque IA | Preuve la plus forte | Sessions |")
    print("|---|---|---|---|---|---|")
    order = ["created", "pr_opened", "pr_merged", "mentioned"]
    covered = 0
    for c in rows:
        ev = evidence_for(c, transcripts)
        best = min((order.index(e.kind) for e in ev), default=None)
        strong = [e for e in ev if e.kind != "mentioned"]
        sessions = sorted({e.session[:8] for e in (strong or ev)})
        if strong:
            covered += 1
        subject = c.subject.replace("|", "\\|")
        print(f"| `{c.sha[:7]}` | {c.date[:10]} | {subject} | {'oui' if c.ai_trailer else 'non'} | "
              f"{LABELS[order[best]] if best is not None else '—'} | {', '.join(sessions) or '—'} |")
    print(f"\n{covered}/{len(rows)} commits rattachés à une session (création, ouverture ou fusion de PR).",
          file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# Archive immuable, manifestes chaînés, horodatage RFC 3161


def latest_archived(archive: Path) -> dict[str, Path]:
    """Dernière version archivée de chaque transcription (chemin relatif → objet)."""
    manifests = sorted((archive / "manifests").glob("*.txt")) if archive.is_dir() else []
    if not manifests:
        return {}
    out = {}
    for line in manifests[-1].read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        digest, _size, rel = line.split("  ", 2)
        obj = archive / "objects" / f"{digest}.jsonl.gz"
        if obj.exists():
            out[rel] = obj
    return out


def timestamp(manifest: Path, tsas: list[str]) -> Path | None:
    tsq = manifest.with_suffix(".tsq")
    tsr = manifest.with_suffix(".tsr")
    subprocess.run(["openssl", "ts", "-query", "-data", str(manifest), "-sha256", "-cert", "-out", str(tsq)],
                   check=True, capture_output=True)
    for url in tsas:
        r = subprocess.run(["curl", "-sS", "--fail", "--max-time", "30",
                            "-H", "Content-Type: application/timestamp-query",
                            "--data-binary", f"@{tsq}", "-o", str(tsr), url.strip()],
                           capture_output=True, text=True)
        if r.returncode == 0 and tsr.stat().st_size > 0:
            (manifest.with_suffix(".tsa")).write_text(url.strip() + "\n")
            return tsr
        print(f"provenance: TSA {url} injoignable : {r.stderr.strip()}", file=sys.stderr)
    tsr.unlink(missing_ok=True)
    return None


def mirror_to(archive: Path, dest: Path) -> tuple[int, int]:
    """Recopie objets, manifestes et jetons de l'archive vers `dest`, sans jamais
    écraser : un fichier déjà présent doit être identique, sinon c'est une
    anomalie signalée (la copie hors poste ne suit pas une archive réécrite).

    `dest` doit exister : un point de montage absent ne doit pas se remplir en
    silence sur le disque local."""
    if not dest.is_dir():
        print(f"miroir      : {dest} absent (support non monté ?), copie ignorée", file=sys.stderr)
        return 0, 1
    copied = errors = 0
    for sub in ("objects", "manifests"):
        (dest / sub).mkdir(exist_ok=True)
        for src in sorted((archive / sub).iterdir()):
            dst = dest / sub / src.name
            want = hashlib.sha256(src.read_bytes()).hexdigest()
            if dst.exists():
                if hashlib.sha256(dst.read_bytes()).hexdigest() != want:
                    print(f"miroir      : {dst} diffère de l'archive, laissé en l'état", file=sys.stderr)
                    errors += 1
                continue
            tmp = dst.with_name(dst.name + ".part")
            shutil.copyfile(src, tmp)
            if hashlib.sha256(tmp.read_bytes()).hexdigest() != want:
                tmp.unlink()
                print(f"miroir      : copie de {src.name} corrompue, abandonnée", file=sys.stderr)
                errors += 1
                continue
            os.replace(tmp, dst)
            try:
                os.chmod(dst, 0o400)
            except OSError:
                pass  # exFAT, NTFS… : pas de droits POSIX, l'empreinte reste le contrôle
            copied += 1
    return copied, errors


def run_mirrors(archive: Path, mirrors: list[str]) -> int:
    failed = 0
    for m in mirrors:
        copied, errors = mirror_to(archive, Path(m).expanduser())
        if errors == 0:
            print(f"miroir      : {m} ({copied} fichier(s) copié(s))")
        failed += errors > 0
    return failed


def cmd_mirror(args) -> int:
    mirrors = args.mirror or DEFAULT_MIRRORS
    if not mirrors:
        print("aucun miroir : --mirror <répertoire> ou $OPENEIDAS_PROVENANCE_MIRROR", file=sys.stderr)
        return 1
    return 3 if run_mirrors(args.archive, mirrors) else 0


def cmd_archive(args) -> int:
    # Plusieurs sessions peuvent se terminer en même temps (hook de fin de
    # session) : un seul archivage à la fois, sinon deux manifestes citeraient
    # le même précédent et la chaîne se diviserait.
    args.archive.mkdir(parents=True, exist_ok=True)
    with open(args.archive / ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        code = archive_once(args)
    # Le miroir suit l'archive même si l'horodatage a échoué : une copie non
    # horodatée vaut mieux que pas de copie, et le jeton suivra au prochain passage.
    if run_mirrors(args.archive, args.mirror or DEFAULT_MIRRORS):
        return code or 3
    return code


def archive_once(args) -> int:
    root = repo_root()
    archive: Path = args.archive
    for d in ("objects", "manifests"):
        (archive / d).mkdir(parents=True, exist_ok=True)
        os.chmod(archive / d, 0o700)
    os.chmod(archive, 0o700)

    previous = sorted((archive / "manifests").glob("*.txt"))
    prev_digest = sha256_file(previous[-1]) if previous else "0" * 64
    entries = dict((rel, None) for rel in latest_archived(archive))
    added = 0

    sources = transcript_files(root, Path("/nonexistent"))
    current: dict[str, tuple[str, int]] = {}
    for p in sources:
        rel = str(p.relative_to(CLAUDE_PROJECTS))
        digest = sha256_file(p)
        obj = archive / "objects" / f"{digest}.jsonl.gz"
        if not obj.exists():
            with p.open("rb") as src, gzip.open(obj, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.chmod(obj, 0o400)
            added += 1
        current[rel] = (digest, p.stat().st_size)
    # Une transcription purgée par Claude Code reste dans le manifeste, sous sa
    # dernière version archivée : l'archive ne perd jamais une session.
    for rel in entries:
        if rel not in current:
            last = latest_archived(archive)[rel]
            current[rel] = (last.name.split(".")[0], -1)

    # Un manifeste par seconde au plus : sous le verrou, le suivant attend.
    while True:
        now = dt.datetime.now(dt.timezone.utc)
        manifest = archive / "manifests" / f"{now:%Y%m%dT%H%M%SZ}.txt"
        if not manifest.exists():
            break
        time.sleep(0.2)
    head = git("rev-parse", "HEAD").strip()
    lines = [
        "# Manifeste de provenance — open-eidas",
        f"# date        {now.isoformat(timespec='seconds')}",
        f"# précédent   {prev_digest}",
        f"# dépôt       {root} @ {head}",
        f"# poste       {getpass.getuser()}@{socket.gethostname()}",
        "# format      sha256  taille(-1 = purgée localement)  chemin relatif à ~/.claude/projects",
    ]
    lines += [f"{d}  {s}  {rel}" for rel, (d, s) in sorted(current.items())]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(manifest, 0o400)

    print(f"archive     : {archive}")
    print(f"manifeste   : {manifest.name} ({len(current)} transcriptions, {added} nouvel(s) objet(s))")
    print(f"empreinte   : {sha256_file(manifest)}")
    if args.no_timestamp:
        print("horodatage  : désactivé (--no-timestamp)")
        return 0
    tsr = timestamp(manifest, args.tsa or DEFAULT_TSAS)
    if tsr is None:
        print("horodatage  : ÉCHEC, manifeste conservé non horodaté ; relancer `archive` plus tard", file=sys.stderr)
        return 2
    text = subprocess.run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"],
                          capture_output=True, text=True).stdout
    gen = re.search(r"Time stamp: (.+)", text)
    print(f"horodatage  : {manifest.with_suffix('.tsa').read_text().strip()} — {gen.group(1) if gen else '?'}")
    return 0


def token_imprint(tsr: Path) -> str:
    """Empreinte (`messageImprint`) portée par un jeton, lue dans `openssl ts -reply -text`."""
    text = subprocess.run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"],
                          capture_output=True, text=True).stdout
    out = []
    in_dump = False
    for line in text.splitlines():
        if line.strip() == "Message data:":
            in_dump = True
            continue
        if in_dump:
            if " - " not in line:
                break
            # « 0000 - 12 34 … 78-9a bc …   ascii » : 16 octets sur 47 colonnes.
            out += re.findall(r"[0-9a-f]{2}", line.split(" - ", 1)[1][:47].replace("-", " "))
    return "".join(out)


def cmd_verify(args) -> int:
    archive: Path = args.archive
    manifests = sorted((archive / "manifests").glob("*.txt"))
    if not manifests:
        print("aucun manifeste", file=sys.stderr)
        return 1
    errors = 0
    prev = "0" * 64
    for m in manifests:
        header = dict(line[2:].split(None, 1) for line in m.read_text(encoding="utf-8").splitlines()
                      if line.startswith("# ") and len(line[2:].split(None, 1)) == 2)
        if header.get("précédent", "").strip() != prev:
            print(f"{m.name} : chaîne rompue (précédent attendu {prev})")
            errors += 1
        for line in m.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            digest, _size, rel = line.split("  ", 2)
            obj = archive / "objects" / f"{digest}.jsonl.gz"
            if not obj.exists() or sha256_file(obj) != digest:
                print(f"{m.name} : objet absent ou altéré pour {rel}")
                errors += 1
        tsr = m.with_suffix(".tsr")
        if tsr.exists():
            cmd = ["openssl", "ts", "-verify", "-data", str(m), "-in", str(tsr)]
            if args.tsa_ca:
                cmd += ["-CAfile", str(args.tsa_ca)]
                r = subprocess.run(cmd, capture_output=True, text=True)
                state = "jeton vérifié" if r.returncode == 0 else f"JETON INVALIDE {r.stderr.strip()}"
                errors += r.returncode != 0
            else:
                # Sans ancre de confiance, on contrôle au moins que le jeton porte
                # bien l'empreinte de ce manifeste ; la signature reste à vérifier
                # avec --tsa-ca.
                ok = token_imprint(tsr) == sha256_file(m)
                state = ("empreinte du jeton conforme (signature non vérifiée : --tsa-ca absent)" if ok
                         else "EMPREINTE DU JETON DIFFÉRENTE DU MANIFESTE")
                errors += not ok
            print(f"{m.name} : {state}")
        else:
            print(f"{m.name} : non horodaté")
        prev = sha256_file(m)
    print("archive intègre" if errors == 0 else f"{errors} anomalie(s)")
    return 0 if errors == 0 else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE,
                   help=f"répertoire d'archive (défaut : {DEFAULT_ARCHIVE}, ou $OPENEIDAS_PROVENANCE_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("trace", help="sessions liées à un commit")
    s.add_argument("rev")
    s.set_defaults(func=cmd_trace)
    s = sub.add_parser("report", help="tableau de provenance d'une plage de commits (défaut : dev)")
    s.add_argument("revs", nargs="*")
    s.set_defaults(func=cmd_report)
    s = sub.add_parser("archive", help="archive immuable + manifeste horodaté")
    s.add_argument("--tsa", action="append", help="URL de TSA RFC 3161 (répétable)")
    s.add_argument("--no-timestamp", action="store_true")
    s.add_argument("--mirror", action="append",
                   help="répertoire de copie hors poste, déjà existant (répétable ; défaut : $OPENEIDAS_PROVENANCE_MIRROR)")
    s.set_defaults(func=cmd_archive)
    s = sub.add_parser("mirror", help="rattrape les copies hors poste sans créer de manifeste")
    s.add_argument("--mirror", action="append", help="répertoire de copie hors poste (répétable)")
    s.set_defaults(func=cmd_mirror)
    s = sub.add_parser("verify", help="revérifie objets, chaîne des manifestes et jetons")
    s.add_argument("--tsa-ca", type=Path, help="certificat(s) de confiance de la TSA pour vérifier les jetons")
    s.set_defaults(func=cmd_verify)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
