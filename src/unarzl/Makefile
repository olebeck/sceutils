unarzl.wasm: unarzl.c
	clang --target=wasm32 -O3 \
	-nostdlib -fvisibility=hidden \
	-Wl,--no-entry -Wl,--strip-all -Wl,--export-dynamic -Wl,--initial-memory=2097152 \
	-o unarzl.wasm unarzl.c
