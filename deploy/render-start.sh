#!/bin/sh
# The start command of the demo on Render (render.yaml, docs/deploy-render.md). Render's free web
# service has no background worker, no pre-deploy command and no shell, so this one container does
# what docker-compose.yml spreads over three: bring the schema up to date, run the scan worker
# beside the web server, and serve. Compose never runs this file.
set -eu

# The database may be waking up (Neon stops its compute after five idle minutes): ask a few times
# before giving up, so that a deploy does not fail on a sleeping database.
attempt=1
until flask db upgrade; do
    if [ "$attempt" -ge 5 ]; then
        echo "render-start: the schema is not up to date after $attempt attempts; giving up" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    echo "render-start: the database did not take the migration; trying again in 5 seconds" >&2
    sleep 5
done

# The worker lives and dies with the web server. If it stops (a crash, a database that went away),
# start it again; what it left half done is picked up when the lock on it has run out.
(
    while true; do
        flask worker || echo "render-start: the worker stopped (exit $?); restarting in 5 seconds" >&2
        sleep 5
    done
) &

# The same server settings as the Dockerfile's CMD, except for the port, which Render chooses
# (tests/test_render_blueprint.py keeps the two in step). The query string stays out of the access
# log: it can hold the name of a vendor somebody is assessing.
exec gunicorn --bind "0.0.0.0:${PORT:-8000}" --worker-class gthread \
    --timeout 60 --graceful-timeout 30 \
    --max-requests 2000 --max-requests-jitter 200 \
    --worker-tmp-dir /dev/shm --no-control-socket \
    --access-logfile - --error-logfile - \
    --access-logformat '%(h)s %(t)s "%(m)s %(U)s" %(s)s %(b)s %(M)sms' \
    "app:create_app()"
