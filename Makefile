# Use a container name based on the folder name (probably "build-mandrake")
BUILD?=$(shell basename `pwd`)-build
EXECUTE?=$(shell basename `pwd`)-execute

# This kicks up docker to build the rest
# (Probably shouldn't be customized)
all: src/*.rs
	docker build . -t ${BUILD} -f Dockerfile.build
	docker run --rm -v ${PWD}:/src --env UID=$(shell id -u) --env GID=$(shell id -g) -ti ${BUILD}

run: all
	docker build . -t ${EXECUTE}

	@echo ""
	@echo "To execute, run:"
	@echo ""
	@echo "docker run --rm -ti ${EXECUTE} --help"

# This runs inside Docker, customize this part!
indocker:
	# Build the binary
	cargo build --release
	mkdir -p build/
	cp target/release/mandrake build/
	strip build/mandrake

	# Build the harness
	cd harness && make
	cp harness/harness build/
	strip build/harness

	# Fix ownership, because Docker
	chown -R ${UID}:${GID} .

clean:
	rm -rf target build
