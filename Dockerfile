FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=5000

WORKDIR /app
RUN addgroup --system app && adduser --system --ingroup app --home /app app
COPY requirements.txt .
RUN python -m pip install --upgrade pip && pip install -r requirements.txt
COPY app ./app
COPY frontend ./frontend
COPY run.py .
COPY scripts ./scripts
RUN mkdir -p /app/instance /app/app/ml/models/artifacts && chown -R app:app /app
USER app
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=3).read()" || exit 1
CMD ["gunicorn", "--worker-class", "gthread", "--threads", "50", "--bind", "0.0.0.0:5000", "run:app"]
