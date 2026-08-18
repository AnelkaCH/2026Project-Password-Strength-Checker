import argparse
import sys
import urllib.request
from pathlib import Path

BASE_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/"

LISTS = {
    "10000": "Pwdb_top-10000.txt",
    "100000": "Pwdb_top-100000.txt",
    "1000000": "Pwdb_top-1000000.txt",
}


def main():
    parser = argparse.ArgumentParser(description="Download a common-password list into data/")
    parser.add_argument(
        "--list",
        choices=LISTS,
        default="1000000",
        help="Size of the list to download (default: 1000000)",
    )
    parser.add_argument(
        "--output",
        default=str(Path(__file__).parent.parent / "data" / "common-passwords.txt"),
        help="Destination file path",
    )
    args = parser.parse_args()

    url = BASE_URL + LISTS[args.list]
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Downloading {url} ...")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            raw = resp.read()
    except Exception as exc:
        print(f"Download failed: {exc}")
        sys.exit(1)

    entries = []
    for line in raw.decode("latin-1").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            entries.append(entry)

    unique = list(dict.fromkeys(entries))

    with open(out_path, "w", encoding="latin-1") as f:
        f.write("\n".join(unique) + "\n")

    print(f"Saved {len(unique):,} unique passwords to {out_path}")


if __name__ == "__main__":
    main()
