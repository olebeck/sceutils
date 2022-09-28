import axfs


def test_axfs(benchmark):
    f = open("test/fsimage0.img", "rb")
    benchmark(axfs.AXFS, f)
