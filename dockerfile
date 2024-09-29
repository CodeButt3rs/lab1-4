FROM ubuntu:22.04

LABEL maintainer="tekrimon4ever@yandex.ru"
LABEL name="Labs"
LABEL description="Лабы по предмету Разработка серверных приложений"

ENV WEB_APP_HOST="0.0.0.0"
ENV WEB_APP_PORT="80"

ARG DEBIAN_FRONTEND=noninteractive

WORKDIR ~

COPY webapp ./webapp
COPY requirements.txt .

EXPOSE 80/tcp
EXPOSE 80/udp
RUN apt update
RUN apt install software-properties-common -y
RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt update
RUN yes | apt install python3.12
RUN yes | apt install python3-pip
RUN pip install fastapi uvicorn pydantic

ENTRYPOINT uvicorn --host $WEB_APP_HOST --port $WEB_APP_PORT webapp.main:app
