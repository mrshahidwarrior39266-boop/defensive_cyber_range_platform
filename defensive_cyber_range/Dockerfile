FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    CYBER_RANGE_ISOLATED=1

WORKDIR /app

# Create non-root user for container safety
RUN groupadd -r rangegroup && useradd -r -g rangegroup rangeuser

COPY . /app
RUN mkdir -p /app/simulation_artifacts && chown -R rangeuser:rangegroup /app

USER rangeuser

CMD ["python3", "run_simulation.py", "--rounds", "2", "--output-dir", "/app/simulation_artifacts"]
