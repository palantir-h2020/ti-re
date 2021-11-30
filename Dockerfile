FROM python:3.11-rc-bullseye
WORKDIR /usr/src/
RUN git clone https://gitlab.com/palantir-project/ti-re
WORKDIR /usr/src/scripts
RUN apt-get update && apt-get -y install cmake protobuf-compiler
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r requirements.txt
ENV PYTHONUNBUFFERED 1
