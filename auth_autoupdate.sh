#!/bin/bash
# Amphoraxe Auth Auto-Update Script (MAIN branch)
# Checks for new commits and restarts services

REPO_DIR="/Users/amphoraxe/Developer/auth.amphoraxe.ca"
LOG_FILE="/tmp/auth_autoupdate.log"
SELF_SERVICE="com.ampauth.autoupdate"

echo "[$(date "+%Y-%m-%d %H:%M:%S")] Starting auth auto-update check (main)..." >> "$LOG_FILE"

cd "$REPO_DIR" || {
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] Failed to cd into $REPO_DIR" >> "$LOG_FILE"
    exit 1
}

git checkout main >/dev/null 2>&1
git fetch origin main >/dev/null 2>&1

LOCAL_HASH=$(git rev-parse HEAD)
REMOTE_HASH=$(git rev-parse origin/main)

if [ "$LOCAL_HASH" != "$REMOTE_HASH" ]; then
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] New commit detected on MAIN! Pulling changes..." >> "$LOG_FILE"
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] Local: $LOCAL_HASH -> Remote: $REMOTE_HASH" >> "$LOG_FILE"

    git reset --hard origin/main >/dev/null 2>&1

    echo "[$(date "+%Y-%m-%d %H:%M:%S")] Installing dependencies from requirements.txt..." >> "$LOG_FILE"
    "$REPO_DIR/venv/bin/pip" install -r requirements.txt --quiet 2>> "$LOG_FILE" || {
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] pip install had issues, check log" >> "$LOG_FILE"
    }

    # Restart strategy: kill the process, launchd respawns it automatically.
    SERVICES=$(launchctl list | grep "com\.ampauth\." | grep -v "$SELF_SERVICE")

    if [ -z "$SERVICES" ]; then
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] No com.ampauth.* services found running (excluding autoupdate)" >> "$LOG_FILE"
    else
        echo "[$(date "+%Y-%m-%d %H:%M:%S")] Restarting services..." >> "$LOG_FILE"

        echo "$SERVICES" | while read -r line; do
            PID=$(echo "$line" | awk '{print $1}')
            SERVICE=$(echo "$line" | awk '{print $3}')

            if [ -n "$PID" ] && [ "$PID" != "-" ]; then
                echo "[$(date "+%Y-%m-%d %H:%M:%S")] Killing $SERVICE (PID $PID)..." >> "$LOG_FILE"
                kill "$PID" 2>/dev/null
            else
                echo "[$(date "+%Y-%m-%d %H:%M:%S")] $SERVICE has no running PID, skipping kill" >> "$LOG_FILE"
            fi
        done

        sleep 5

        echo "[$(date "+%Y-%m-%d %H:%M:%S")] Final service status..." >> "$LOG_FILE"
        launchctl list | grep "com\.ampauth\." | grep -v "$SELF_SERVICE" | while read -r line; do
            PID=$(echo "$line" | awk '{print $1}')
            SERVICE=$(echo "$line" | awk '{print $3}')
            if [ -n "$PID" ] && [ "$PID" != "-" ]; then
                echo "[$(date "+%Y-%m-%d %H:%M:%S")] $SERVICE running with PID: $PID" >> "$LOG_FILE"
            else
                echo "[$(date "+%Y-%m-%d %H:%M:%S")] $SERVICE not running" >> "$LOG_FILE"
            fi
        done
    fi

    echo "[$(date "+%Y-%m-%d %H:%M:%S")] MAIN update and restart complete." >> "$LOG_FILE"
else
    echo "[$(date "+%Y-%m-%d %H:%M:%S")] No updates found on MAIN branch." >> "$LOG_FILE"
fi

echo "" >> "$LOG_FILE"
