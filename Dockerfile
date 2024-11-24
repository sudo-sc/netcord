FROM python:3.12-slim
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping traceroute && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "netcord.py"]