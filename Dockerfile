FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY agentic_observatory ./agentic_observatory
RUN pip install --no-cache-dir .
EXPOSE 8780
CMD ["uvicorn", "agentic_observatory.app:app", "--host", "0.0.0.0", "--port", "8780"]
