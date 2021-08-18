.PHONY: all
all: init

init: clean
	meson build
	cd build && ninja
	cd ../

clean:
	rm -rf build
