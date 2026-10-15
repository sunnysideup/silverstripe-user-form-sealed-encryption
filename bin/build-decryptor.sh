#!/usr/bin/env bash
# Rebuilds decryptor/index.html (self-contained, no network) from decryptor/template.html.
# Needs: node, npm. Inlines tweetnacl + blakejs.
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$tmp" && npm init -y >/dev/null && npm i tweetnacl blakejs >/dev/null 2>&1)
python3 - "$tmp" <<'PY'
import sys
t=sys.argv[1]
nacl=open(t+'/node_modules/tweetnacl/nacl-fast.min.js').read()
# nacl-fast.min.js attaches to self.nacl/module.exports; provide a shim
nacl="var module={exports:{}};var self=window;(function(){"+nacl+"})();var nacl=module.exports&&module.exports.box?module.exports:window.nacl;"
util=open(t+'/node_modules/blakejs/util.js').read()
b2=open(t+'/node_modules/blakejs/blake2b.js').read()
b2=b2.replace("require('./util')","modules.util")
blake="def('util',function(module,exports){"+util+"});def('blake2b',function(module,exports){"+b2+"});"
h=open('decryptor/template.html').read()
h=h.replace('/*__NACL__*/',nacl.replace('</script','<\\/script')).replace('/*__BLAKE__*/',blake.replace('</script','<\\/script'))
open('decryptor/index.html','w').write(h)
PY
echo "Built decryptor/index.html"
