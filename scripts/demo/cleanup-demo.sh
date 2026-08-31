#!/bin/sh
set -eu

EXPECTED_DATABASE="guidemate_demo"
EXPECTED_MEDIA_ROOT="${HOME}/.guidemate/guidemate-demo-media"
CONFIRMATION_PHRASE="DELETE_GUIDEMATE_DEMO_ONLY"
MODE="dry-run"
CONFIRMATION=""

usage() {
    cat <<'EOF'
Usage: cleanup-demo.sh [--dry-run] [--execute --confirm DELETE_GUIDEMATE_DEMO_ONLY]

The command can only target the local guidemate_demo database and the fixed
GuideMate demo media directory. Execution is never enabled by default.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --confirm)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            CONFIRMATION="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
done

printf 'database=%s\n' "$EXPECTED_DATABASE"
printf 'media_root=%s\n' "$EXPECTED_MEDIA_ROOT"
printf 'mode=%s\n' "$MODE"

if [ "$MODE" = "dry-run" ]; then
    printf 'No database or media files were changed.\n'
    exit 0
fi

if [ "$CONFIRMATION" != "$CONFIRMATION_PHRASE" ]; then
    printf 'Refusing cleanup: explicit demo-only confirmation is required.\n' >&2
    exit 2
fi

if [ -L "${HOME}/.guidemate" ] || [ -L "$EXPECTED_MEDIA_ROOT" ]; then
    printf 'Refusing cleanup: demo media path must not contain symlinks.\n' >&2
    exit 2
fi

PG_BIN="${PG_BIN:-/Applications/Postgres.app/Contents/Versions/18/bin}"
DROPDB="${PG_BIN}/dropdb"
[ -x "$DROPDB" ] || { printf 'PostgreSQL dropdb tool was not found.\n' >&2; exit 2; }

"$DROPDB" \
    --host=localhost \
    --port=5432 \
    --username="${DEMO_DB_USERNAME:-ahmetkaragunlu}" \
    --maintenance-db=postgres \
    --if-exists \
    --force \
    "$EXPECTED_DATABASE"

if [ -d "$EXPECTED_MEDIA_ROOT" ]; then
    find "$EXPECTED_MEDIA_ROOT" -mindepth 1 -delete
    rmdir "$EXPECTED_MEDIA_ROOT"
fi

printf 'Only isolated GuideMate demo resources were removed.\n'
