from io import BytesIO
import sys
import pup_info


if __name__ == "__main__":
    filename = sys.argv[1]
    output = sys.argv[2]

    with open(filename, "rb") as f:
        data = f.read()
        print(f"count: {data.count(b'SCEUF')}")
        i = data.index(b"SCEUF")
        with BytesIO(data[i:]) as pup:
            info = pup_info.SCEUF.read(pup)
            print(info)
        pup = data[i:info.data_len]
        with open(output, "wb") as fo:
            fo.write(pup)
