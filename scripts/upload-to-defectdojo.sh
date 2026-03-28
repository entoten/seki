#!/usr/bin/env bash
set -euo pipefail

: "${DEFECTDOJO_URL:?DEFECTDOJO_URL is required}"
: "${DEFECTDOJO_API_KEY:?DEFECTDOJO_API_KEY is required}"
: "${DEFECTDOJO_ENGAGEMENT_ID:?DEFECTDOJO_ENGAGEMENT_ID is required}"
: "${SCAN_TYPE:?SCAN_TYPE is required}"
: "${REPORT_FILE:?REPORT_FILE is required}"

if [[ ! -f "$REPORT_FILE" ]]; then
  echo "レポートファイルが見つかりません: $REPORT_FILE" >&2
  exit 1
fi

echo "DefectDojo へ $SCAN_TYPE の結果をアップロードします"

curl -fsSL -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \
  -H "Authorization: Token $DEFECTDOJO_API_KEY" \
  -F "engagement=$DEFECTDOJO_ENGAGEMENT_ID" \
  -F "scan_type=$SCAN_TYPE" \
  -F "active=true" \
  -F "verified=false" \
  -F "close_old_findings=false" \
  -F "minimum_severity=Info" \
  -F "scan_date=$(date +%F)" \
  -F "file=@$REPORT_FILE"

echo "DefectDojo へのアップロードが完了しました"

