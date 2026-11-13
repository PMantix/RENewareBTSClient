#!/usr/bin/env bash
# Rebuild vendor/ (git-ignored): copy Neware BTS binaries + user config, then decompile
# the .NET client assemblies with ILSpy (ilspycmd 7.2.1 runs on the .NET 6 runtime).
# Read-only with respect to the Neware install; safe while tests are running.
set -euo pipefail
R="$(cd "$(dirname "$0")/.." && pwd)"
V="$R/vendor"
C="/c/Program Files (x86)/NEWARE/BTSClient80"
S="/c/Program Files (x86)/NEWARE/BTSServer80/bin"
CFG="/c/Users/user/Documents/NEWARE/BTSClient"
mkdir -p "$V/client" "$V/server" "$V/config" "$V/decompiled" "$V/tools"

cp "$C"/*.dll "$C"/*.exe "$C"/*.config "$C"/*.csv "$C"/*.txt "$C"/*.py "$V/client/" 2>/dev/null || true
cp -r "$C/Specification" "$C/devinfo" "$V/client/" 2>/dev/null || true
cp "$S"/*.dll "$S"/*.exe "$S"/*.pdb "$S"/*.ini "$S"/*.txt "$S"/*.csv "$V/server/" 2>/dev/null || true
cp "$CFG"/*.ini "$CFG"/*.iconf "$CFG"/DefaultStep.xml "$V/config/" 2>/dev/null || true

ILS_DIR="$V/tools/ilspycmd"
if [ ! -f "$ILS_DIR/tools/net6.0/any/ilspycmd.dll" ]; then
  curl -sSL -o "$V/tools/ilspycmd.nupkg" https://www.nuget.org/api/v2/package/ilspycmd/7.2.1.6856
  python -I -c "import sys,zipfile;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
    "$V/tools/ilspycmd.nupkg" "$ILS_DIR"
fi
ILS="$ILS_DIR/tools/net6.0/any/ilspycmd.dll"

for a in BTSAPI BTS BTSLib Common Proto Network NetworkBase Interface Communication \
         Neware.BTS.Service BTSService CommonMySql Step BTSData Regedit; do
  f="$V/client/$a.dll"; [ -f "$f" ] || f="$V/client/$a.exe"
  mkdir -p "$V/decompiled/$a"
  dotnet "$ILS" -p -o "$V/decompiled/$a" -r "$V/client" "$f" >/dev/null 2>"$V/decompiled/$a.err" \
    && echo "ok   $a" || echo "FAIL $a (see vendor/decompiled/$a.err)"
done
