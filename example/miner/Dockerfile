FROM python:3.7-slim

# Install build essentials and Python headers
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        python3-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# RUN git clone https://github.com/xtrinch/stratumv2-python-miner.git

WORKDIR /py-miner

COPY py-miner/ /py-miner

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 2000

CMD ["python", "simulate-pool.py"]