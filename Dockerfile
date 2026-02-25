FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl dnsutils && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create output directory
RUN mkdir -p /app/output

EXPOSE 8000

ENTRYPOINT ["python", "-m", "godrecon"]
CMD ["--help"]
