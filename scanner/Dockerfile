FROM python:3.11-slim
WORKDIR /app
COPY scanner/requirements.txt scanner/requirements.txt
RUN pip install --no-cache-dir -r scanner/requirements.txt
COPY scanner/ scanner/
ENTRYPOINT ["python", "-m", "scanner.cli"]
