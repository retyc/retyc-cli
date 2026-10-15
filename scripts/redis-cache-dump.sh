#!/bin/bash

cd "$(dirname "$0")/.." && exec go run ./scripts/redis-cache-dump "$@"
