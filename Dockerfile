FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DJANGO_SETTINGS_MODULE=project.settings DATA_DIR=/data

RUN useradd --create-home --uid 10001 app && mkdir /data && chown app:app /data
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
RUN PUBLIC_BASE_URL=http://build DATA_DIR=/tmp/build python manage.py collectstatic --noinput && rm -rf /tmp/build

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import socket,sys; sys.exit(socket.socket().connect_ex(('127.0.0.1', 8000)))"
# Every boot: migrate, then set the superuser's password from ADMIN_PASSWORD (a change revokes
# every connector token), then serve. One process keeps SQLite and the login throttle simple.
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py ensure_admin && exec gunicorn project.wsgi -b 0.0.0.0:8000 --workers 1 --threads 8 --timeout 240 --no-control-socket --access-logfile -"]
