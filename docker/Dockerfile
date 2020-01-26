FROM ubuntu:bionic
# Add a fake user for Dante to pick up credentials for
RUN useradd -s /sbin/nologin socksio
RUN echo 'socksio:socksio' | chpasswd
RUN apt-get update && apt-get install -y dante-server
COPY danted.conf /etc/
EXPOSE 1080
CMD [ "danted" ]
