#!/usr/bin/env bash
# Exécuté SUR la VM par la CI (user deploy) : installe le binaire du
# connecteur fraîchement uploadé et redémarre le service.
set -euo pipefail
sudo /usr/bin/install -m 755 -o root -g root /opt/yogfile/yogfile-mcp-remote.new /usr/local/bin/yogfile-mcp-remote
sudo /bin/systemctl restart yogfile-mcp-remote
for i in $(seq 1 15); do
  sleep 2
  if curl -sf -o /dev/null http://127.0.0.1:8082/healthz; then
    echo "yogfile-mcp-remote up"
    exit 0
  fi
done
echo "yogfile-mcp-remote ne répond pas sur /healthz" >&2
sudo /bin/systemctl status yogfile-mcp-remote --no-pager | tail -20 >&2
exit 1
