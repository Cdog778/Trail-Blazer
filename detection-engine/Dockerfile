FROM python:3.11-slim

WORKDIR /app

# Copy core detection engine components
COPY detection_engine.py .
COPY config.yaml .
COPY requirements.txt .

# Copy detection rules directory
COPY detection_rules/ detection_rules/

# Copy only necessary utility files
COPY utils/config_loader.py utils/config_loader.py
COPY utils/suppression.py utils/suppression.py
COPY utils/alert_writer.py utils/alert_writer.py

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run the detection engine
CMD ["python", "detection_engine.py"]

