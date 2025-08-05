# Use a minimal Python 3.11 image
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy main engine and config files
COPY baseline_engine.py .
COPY config.yaml .
COPY requirements.txt .

# Recursively copy all utils (including baseline.py and helpers)
COPY utils/ utils/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Start the engine when the container runs
CMD ["python", "baseline_engine.py"]

