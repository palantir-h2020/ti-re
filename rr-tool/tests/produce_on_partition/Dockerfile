#Deriving the python 3.11 base image
FROM python:3.11-bullseye

RUN apt-get -y update

RUN apt-get -y install nano

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . .

#CMD [ "python", "./kafka_partition_producer.py"]

ENTRYPOINT ["bash"]