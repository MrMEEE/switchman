#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

COMMAND="${1:-start}"
PORT="${2:-8000}"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    . .venv/bin/activate
    echo "Installing dependencies..."
    pip install -q -r requirements.txt
    python manage.py migrate
    echo "✓ Setup complete."
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
start_redis() {
    if ! redis-cli ping &>/dev/null; then
        echo "Starting Redis..."
        redis-server --daemonize yes --logfile "$PROJECT_DIR/logs/redis.log"
    else
        echo "Redis already running."
    fi
}

start_workers() {
    mkdir -p "$PROJECT_DIR/logs"
    . .venv/bin/activate

    if pgrep -f "celery -A core worker" &>/dev/null; then
        echo "Celery worker already running."
    else
        echo "Starting Celery worker..."
        celery -A core worker -l info \
            --logfile "$PROJECT_DIR/logs/celery-worker.log" \
            --pidfile "$PROJECT_DIR/logs/celery-worker.pid" \
            --detach
    fi

    if pgrep -f "celery -A core beat" &>/dev/null; then
        echo "Celery Beat already running."
    else
        echo "Starting Celery Beat..."
        celery -A core beat -l info \
            --scheduler django_celery_beat.schedulers:DatabaseScheduler \
            --logfile "$PROJECT_DIR/logs/celery-beat.log" \
            --pidfile "$PROJECT_DIR/logs/celery-beat.pid" \
            --detach
    fi
}

stop_workers() {
    echo "Stopping Celery worker and Beat..."
    for pidfile in "$PROJECT_DIR/logs/celery-worker.pid" "$PROJECT_DIR/logs/celery-beat.pid"; do
        if [ -f "$pidfile" ]; then
            kill "$(cat "$pidfile")" 2>/dev/null || true
            rm -f "$pidfile"
        fi
    done
    pkill -f "celery -A core" 2>/dev/null || true
}

case "$COMMAND" in
    start)
        mkdir -p "$PROJECT_DIR/logs"
        echo "Starting Switch Control Center on port $PORT..."
        . .venv/bin/activate
        start_redis
        start_workers
        python manage.py runserver 0.0.0.0:$PORT
        ;;
    stop)
        echo "Stopping Switch Control Center..."
        pkill -f "python manage.py runserver" || echo "No running server found."
        stop_workers
        echo "✓ Server stopped."
        ;;
    restart)
        echo "Restarting Switch Control Center..."
        pkill -f "python manage.py runserver" || true
        stop_workers
        sleep 1
        mkdir -p "$PROJECT_DIR/logs"
        echo "Starting Switch Control Center on port $PORT..."
        . .venv/bin/activate
        start_redis
        start_workers
        python manage.py runserver 0.0.0.0:$PORT
        ;;
    createsuperuser)
        USERNAME="${2:-}"
        PASSWORD="${3:-}"
        if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
            echo "Usage: $0 createsuperuser <username> <password>"
            exit 1
        fi
        . .venv/bin/activate
        echo "Creating superuser: $USERNAME"
        python manage.py bootstrap_admin --username "$USERNAME" --password "$PASSWORD"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|createsuperuser} [options]"
        echo ""
        echo "Commands:"
        echo "  start              - Start the development server (default)"
        echo "  stop               - Stop the running server and workers"
        echo "  restart            - Restart the server and workers"
        echo "  createsuperuser    - Create a superuser (requires username and password)"
        echo ""
        echo "Options:"
        echo "  port               - Port to run on (default: 8000) for start/restart"
        echo ""
        echo "Examples:"
        echo "  $0 start 8000"
        echo "  $0 createsuperuser admin admin123"
        exit 1
        ;;
esac
