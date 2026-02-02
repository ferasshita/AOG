FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY server /app/server
WORKDIR /app/server

ENV PYTHONPATH=/app

EXPOSE 8080 8443

CMD ["python", "uvicorn_run.py"]