WINDOWS_TARGET = x86_64-pc-windows-gnu
UNIX_TARGET = i686-unknown-linux-musl

windows:
	cross build --release --target $(WINDOWS_TARGET)

unix:
	cross build --release --target $(UNIX_TARGET)

.PHONY: all
all: windows unix

test-windows:
	cross test --target $(WINDOWS_TARGET)

test-unix:
	cross test --target $(UNIX_TARGET)

test-all: test-windows test-unix

clean:
	cargo clean
