# This kicks up docker to build the rest
# (Probably shouldn't be customized)
all:
	docker build . -t build -f Dockerfile.build
	docker run --rm -v ${PWD}:/src --env UID=$(shell id -u) --env GID=$(shell id -g) -ti build

# This runs inside Docker, customize this part!
indocker:
	cargo build --release
	chown -R ${UID}:${GID} .
	strip target/release/mandrake

clean:
	rm -f target
