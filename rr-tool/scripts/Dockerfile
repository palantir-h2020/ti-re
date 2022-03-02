FROM openjdk:11
WORKDIR $HOME/
COPY . . 
RUN apt update && apt install -y
RUN apt install python3-pip -y
### This is needed for installing pycairo with pip
# RUN apt install sox ffmpeg libcairo2 libcairo2-dev -y
ADD scripts /usr/src/scripts
WORKDIR /usr/src/scripts
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install wheel
### This is needed for installing pycairo with pip
# RUN python3 -m pip install manimce
RUN python3 -m pip install -r requirements.txt
ENV PYTHONUNBUFFERED 1
ENTRYPOINT python3 /usr/src/scripts/remediation.py