FROM python:3.12-slim
WORKDIR /app
COPY haproxy_studio ./haproxy_studio
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 STUDIO_CONFIG=/app/config.json
EXPOSE 9130
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9130/haproxy-admin/api/health', timeout=3)"
CMD ["python", "-m", "haproxy_studio"]
