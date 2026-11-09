# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1
COPY swarmpot/egress_proxy.py /opt/egress/egress_proxy.py
ENTRYPOINT ["python", "/opt/egress/egress_proxy.py"]
