# Use a container name based on the folder name (probably "build-mandrake")
C?=build-$(shell basename `pwd`)

# This kicks up docker to build the rest
# (Probably shouldn't be customized)
all:
	docker build . -t ${C} -f Dockerfile.build
	docker run --rm -v ${PWD}:/src --env UID=$(shell id -u) --env GID=$(shell id -g) -ti ${C}

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
	rm -f target
