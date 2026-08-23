#!/bin/bash
cd "$1"
MINE="./target/debug/omni-rs-bin"
norm() { sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+\+00:00 //'; }
cmp_help() {
  local desc=$1; shift
  local m o
  m=$($MINE "$@" 2>&1 | norm)
  o=$(docker run --rm --platform linux/amd64 -v "$PWD:/work:ro" debian:stable-slim /work/omni-rs-bin "$@" 2>&1 | norm)
  if [ "$m" = "$o" ]; then echo "MATCH  :: $desc"; else echo "DIFF   :: $desc"; diff <(echo "$m") <(echo "$o") | head -8; fi
}
cmp_cfg() {
  local desc=$1 jsonf=$2
  printf '%s' "$jsonf" > probe/case.json
  local m o
  m=$($MINE --check-config -c "$PWD/probe/case.json" 2>&1 | norm)
  o=$(docker run --rm --platform linux/amd64 -v "$PWD:/work:ro" debian:stable-slim /work/omni-rs-bin --check-config -c /work/probe/case.json 2>&1 | norm)
  if [ "$m" = "$o" ]; then echo "MATCH  :: $desc"; else echo "DIFF   :: $desc"; diff <(echo "$m") <(echo "$o") | head -10; fi
}
cmp_help "main --help"    --help
cmp_help "server --help"  server --help
cmp_help "version"        version
cmp_help "badcmd"         badcmd
cmp_help "missing file"   --check-config -c /nope.json
cmp_cfg "empty json"      '{}'
cmp_cfg "trojan-nopass"   '{"outbounds":[{"tag":"o1","outbound_type":"trojan"}]}'
cmp_cfg "vless-nouuid"    '{"outbounds":[{"tag":"o1","outbound_type":"vless","target":{"server":"a.com","server_port":443}}]}'
cmp_cfg "ss-nomethod"     '{"outbounds":[{"tag":"o1","outbound_type":"shadowsocks","password":"p"}]}'
cmp_cfg "empty-tag"       '{"outbounds":[{"tag":"","outbound_type":"direct"}]}'
cmp_cfg "dup-tag"         '{"outbounds":[{"tag":"a","outbound_type":"x"},{"tag":"a","outbound_type":"y"}]}'
cmp_cfg "bad-json"        '{"nodes": [}'
printf 'nodes = []\nmetrics_port = 9090\n' > probe/case.toml
m=$($MINE --check-config -c "$PWD/probe/case.toml" 2>&1 | norm | tail -1)
echo "toml check mine: $m"
