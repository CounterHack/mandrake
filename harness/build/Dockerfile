FROM debian:buster-slim
MAINTAINER "Ron Bowes"

# Install all the tools
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install build-essential cargo -y

# We're going to mount the source here
RUN mkdir /src
WORKDIR /src

CMD ["make", "indocker"]
