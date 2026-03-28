#!/bin/bash

# 參數設定
DB_SRC="/var/lib/rancher/k3s/server/db/state.db"
DB_TMP="/tmp/state.db.backup"
OUTPUT_DIR="/tmp/k3s_export"
RESOURCE_PREFIXES=("/registry/pods/" "/registry/services/specs/")

# 建立輸出資料夾
mkdir -p "$OUTPUT_DIR"

# 備份 SQLite 資料庫
sudo cp "$DB_SRC" "$DB_TMP"

# 讀取並解析資料
for PREFIX in "${RESOURCE_PREFIXES[@]}"; do
    echo "Extracting resources with prefix: $PREFIX"
    
    # 用 sqlite3 查出對應資料
    sqlite3 "$DB_TMP" "SELECT name, value FROM kine WHERE name LIKE '${PREFIX}%';" | while IFS='|' read -r NAME VALUE; do
        SAFE_NAME=$(echo "$NAME" | sed 's|/|_|g')
        OUTPUT_FILE="${OUTPUT_DIR}/${SAFE_NAME}.json"
        
        # 嘗試 base64 decode + pretty json
        if echo "$VALUE" | base64 -d 2>/dev/null | jq . > "$OUTPUT_FILE"; then
            echo "Exported: $OUTPUT_FILE"
        else
            echo "Failed to decode base64 or parse JSON for: $NAME"
            echo "$VALUE" | jq . > "$OUTPUT_FILE"
        fi
        
        echo "Exported: $OUTPUT_FILE"
    done
done

echo "✅ Export finished. Files are in $OUTPUT_DIR"
