from collections.abc import Callable
from wasmer import engine, Store, Module, Instance, Memory

instance: Instance | None = None
memory: Memory | None = None
membuffer: bytearray | None = None
_unarzl: Callable[[int, int, int], int] | None = None

def unarzl(data: bytes) -> bytes:
    global instance
    global memory
    global membuffer
    global _unarzl
    if instance is None:
        store = Store()
        module = Module(store, wasm_bytes)
        instance = Instance(module)
        memory = instance.exports.mem
        membuffer = bytearray(memory.buffer)
        _unarzl = instance.exports.unarzl
    
    if not membuffer or not _unarzl:
        raise ValueError("failed to init")
    
    output = membuffer[:1000000]
    input = membuffer[1000000:2000000]
    output_size = membuffer[2000000:2000004]
    
    membuffer[:len(data)] = data
    
    ret: int = _unarzl(0, len(output), 1000000)
    if ret < 0:
        raise ValueError(f"unarzl: {ret}")
    outlen = ret
    return bytes(output[:outlen])
    