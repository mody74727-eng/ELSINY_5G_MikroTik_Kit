#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/app"
docker build --platform linux/amd64 -t elsiny_5g:1.0 .
docker save -o ../ELSINY_5G_mikrotik.tar elsiny_5g:1.0
echo "Created ../ELSINY_5G_mikrotik.tar"
