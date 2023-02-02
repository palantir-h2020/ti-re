FROM python:3.11-bullseye
RUN apt-get update -y && apt-get -y install cmake protobuf-compiler wget gnupg software-properties-common openjdk-17-jre
RUN python3 -m pip install --upgrade pip
RUN wget -qO - https://packages.confluent.io/deb/7.0/archive.key | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://packages.confluent.io/deb/7.0 stable main"
RUN add-apt-repository "deb https://packages.confluent.io/clients/deb focal main"
RUN apt-get update -y
RUN apt-get install librdkafka-dev python3-pip python-dev -y
RUN pip3 install --no-binary :all: confluent-kafka
ADD requirements.txt /usr/src/
WORKDIR /usr/src
RUN python3 -m pip install -r requirements.txt
RUN git clone https://github.com/MISP/misp-stix.git && cd misp-stix
RUN git submodule update --init
RUN poetry install
ADD . /usr/src/rr-tool
WORKDIR /usr/src/rr-tool
ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["python3", "/usr/src/rr-tool/source/rr_tool.py"]
