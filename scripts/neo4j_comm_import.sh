#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "" ]]; then
  cat <<'EOF'
Usage:
  NEO4J_PASS=<password> ./scripts/neo4j_comm_import.sh <run_dir> [--uri bolt://127.0.0.1:7687] [--user neo4j]

This imports, in order:
  1) communication_graph.schema.cypher
  2) communication_graph.cypher
  3) communication_graph.queries.cypher
EOF
  exit 2
fi

RUN_DIR="$1"
shift

NEO4J_URI="${NEO4J_URI:-bolt://127.0.0.1:7687}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASS="${NEO4J_PASS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uri)
      NEO4J_URI="${2:-}"
      shift 2
      ;;
    --user)
      NEO4J_USER="${2:-}"
      shift 2
      ;;
    --pass)
      NEO4J_PASS="${2:-}"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$NEO4J_PASS" ]]; then
  echo "NEO4J_PASS is required (env or --pass)." >&2
  exit 2
fi

GRAPH_DIR="${RUN_DIR%/}/stages/graph"
SCHEMA_CYPHER="$GRAPH_DIR/communication_graph.schema.cypher"
DATA_CYPHER="$GRAPH_DIR/communication_graph.cypher"
QUERIES_CYPHER="$GRAPH_DIR/communication_graph.queries.cypher"

for file in "$SCHEMA_CYPHER" "$DATA_CYPHER" "$QUERIES_CYPHER"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing expected file: $file" >&2
    exit 2
  fi
done

run_cypher() {
  local cypher_file="$1"
  echo "[neo4j] applying: $cypher_file"
  cat "$cypher_file" | cypher-shell -a "$NEO4J_URI" -u "$NEO4J_USER" -p "$NEO4J_PASS"
}

run_cypher "$SCHEMA_CYPHER"
run_cypher "$DATA_CYPHER"
run_cypher "$QUERIES_CYPHER"

echo "[neo4j] import complete for run_dir=$RUN_DIR"
