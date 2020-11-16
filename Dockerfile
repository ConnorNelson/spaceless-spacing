FROM tiangolo/uwsgi-nginx-flask

ENV LISTEN_PORT "80 http2"

COPY ./challenge /app
