
FROM python:3.12-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Set environment variables (these should be set via Replit Secrets)
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "main.py"]
