import shutil
from Cryptodome.Hash import SHA1
from tempfile import TemporaryDirectory, NamedTemporaryFile

import scetypes
import sceutils
import self2elf
import pup_fiction


def test_self2elf():
    known_hash = "1cabf35bab1cfc8b9eb4607ee0c3244d7eb2520f"

    class args:
        inputfile = "test/eboot.bin"
        outputfile = "eboot.elf"
        zrif = "KO5ifR1dg/J5YXzPAEtDiGpPkPGGIPsDgn2DQv1CPH1dIZbi89+nS4wpR/vWpWUGfu9bZv26YzTGBzcAACA6FcUA"
        keyriffile = None
        keys = "keys_external.py"

    with NamedTemporaryFile("rb") as tf:
        args.outputfile = tf.name
        self2elf.main(args)
        file_hash = SHA1.new(tf.read()).hexdigest()
        assert file_hash == known_hash, "hash check failure"


def _test_pup_fiction(input_file, output, keys):
    pup_fiction.main([None, input_file, output, keys])


def _test_wm(fname, known_hash):
    dec_wm = open(fname + "/PUP_dec/package_scewm.wm", "rb")
    wm_hash = SHA1.new(dec_wm.read()).hexdigest()
    assert wm_hash == known_hash, "scewm decrypted wrong"


# TODO: check for hashes of files
class Test_pup_fiction:
    @staticmethod
    def test_368():
        input_file = "test/PSP2UPDAT_368.PUP"
        keys = "keys_external.py"
        with TemporaryDirectory() as tempdir:
            shutil.rmtree(tempdir)
            _test_pup_fiction(input_file, tempdir, keys)

    @staticmethod
    def test_proto():
        input_file = "test/PSP2UPDAT_100.PUP"
        keys = "keys_proto.py"
        with TemporaryDirectory() as tempdir:
            shutil.rmtree(tempdir)
            _test_pup_fiction(input_file, tempdir, keys)

    @staticmethod
    def test_internal():
        known_wm_hash = "18b3d8eddbe557531bbf48d141a0f30222eb2df7"
        input_file = "test/PSP2UPDAT-0_995_Internal.PUP"
        keys = "keys_internal.py"
        with TemporaryDirectory() as tempdir:
            shutil.rmtree(tempdir)
            _test_pup_fiction(input_file, tempdir, keys)
            _test_wm(tempdir, known_wm_hash)


def test_zrif():
    rif_data = sceutils.zrif_decode("KO5ifR1dQ+d7BRgYGphBbbG0MAfZ7xTk4urn7urtGeLh6utqYIjPfwmdPwseyB0sSbfTn/9oip3YaIwPbgAANDMUlgAA")
    rif = scetypes.SceRIF(rif_data)
    print(rif)

test_zrif()