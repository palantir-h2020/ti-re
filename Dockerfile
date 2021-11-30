FROM python:3.11-rc-bullseye
WORKDIR /usr/src/
RUN git clone https://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@github.com/frank7y/Palantir-remediation-module.git
WORKDIR /usr/src/Palantir-remediation-module
RUN apt-get update && apt-get -y install cmake protobuf-compiler
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r requirements.txt
ENV PYTHONUNBUFFERED 1
