FROM debian:bullseye-slim
MAINTAINER "Ron Bowes"

# Copy binaries
RUN mkdir /app
COPY ./build/mandrake /app/mandrake
RUN chmod +x /app/mandrake

RUN mkdir -p /app/harness
COPY ./build/harness /app/harness/harness
RUN chmod +x /app/harness/harness

# Set up user
RUN useradd -m mandrake
USER mandrake
WORKDIR /app

# Environment
ENTRYPOINT ["/app/mandrake"]
