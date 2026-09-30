import io
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "project.settings")
django_application = get_wsgi_application()


def application(environ, start_response):
    """Django reads a body without Content-Length as empty, but some clients (claude.ai's client
    registration among them) send chunked bodies. gunicorn has already de-chunked the stream, so
    read it (capped) and give Django a Content-Length."""
    if "chunked" in environ.get("HTTP_TRANSFER_ENCODING", "").lower() and not environ.get("CONTENT_LENGTH"):
        body = environ["wsgi.input"].read(1024 * 1024 + 1)
        environ["wsgi.input"], environ["CONTENT_LENGTH"] = io.BytesIO(body), str(len(body))
    return django_application(environ, start_response)
