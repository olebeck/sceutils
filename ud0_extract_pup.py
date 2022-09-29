import sys, os
import pup_info


BLOCKSIZE = int(10e6)

if __name__ == "__main__":
    filename = sys.argv[1]
    print(filename)

    with open(filename, "rb") as f:
        while True:
            data = f.read(BLOCKSIZE)
            if len(data) == 0 or data is None:
                break

            if data.count(b"SCEUF"):
                print("Found a pup")
                index = data.index(b"SCEUF")

                before = f.tell()
                real_index = before - BLOCKSIZE + index
                print(f"at 0x{real_index:x}")

                f.seek(real_index)
                info = pup_info.SCEUF.read(f)
                print(info)
                info.print()
                yn = "y" #input("extract?")
                if yn != "y":
                    f.seek(before)
                    continue
                else:
                    f.seek(real_index)
                    pup = f.read(info.data_len+info.header_len)
                    with open(f"{os.path.basename(filename)}_PSP2_{info.version:x}_{info.build_no}_{real_index:x}.PUP", "wb") as fo:
                        fo.write(pup)
                    print("written pup")
