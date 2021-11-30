FROM python:3.11-rc-bullseye
ADD scripts /usr/src/scripts
WORKDIR /usr/src/scripts
RUN apt-get update && apt-get -y install cmake protobuf-compiler
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install -r requirements.txt
ENV PYTHONUNBUFFERED 1
ENTRYPOINT python3 /usr/src/scripts/refinement.py
