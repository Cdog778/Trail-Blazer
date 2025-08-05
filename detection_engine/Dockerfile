FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy core detection engine components
COPY detection_engine.py .
COPY config.yaml .
COPY requirements.txt .

# Copy detection rules directory
COPY detection_rules/ detection_rules/

# Copy all utility files
COPY utils/ utils/

# Set PYTHONPATH so absolute imports like 'from utils.x import y' work
ENV PYTHONPATH=/app

# Debug visibility inside image (will show up in CloudWatch logs)
RUN ls -R /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the detection engine
CMD ["python", "detection_engine.py"]

