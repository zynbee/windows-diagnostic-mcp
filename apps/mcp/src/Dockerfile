FROM mcr.microsoft.com/devcontainers/python:3.12-bullseye

WORKDIR /workspace

# Copy application files
COPY . /workspace
# Set up Python environment
RUN pip install -r requirements.txt

# Expose ports
EXPOSE 8000

CMD ["python", "server.py", "--mode", "http", "--port", "8000"]
