FROM python@sha256:85272faa6381458bd2d1a95fd7bb8f66f169b56352c17e09598f6d986639a89f
RUN apt-get update && apt-get -y install cmake protobuf-compiler wget gnupg software-properties-common openjdk-17-jre
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
ADD scripts /usr/src/scripts
WORKDIR /usr/src/scripts
ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["python3", "/usr/src/scripts/kafka_connector.py"]
