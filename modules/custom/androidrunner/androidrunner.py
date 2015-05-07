from lockfile import LockFile, LockTimeout
import os
import tempfile
from os.path import dirname, abspath
import zipfile
import logging
import subprocess
import json
import time
import signal

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class AndroidRunner(object):
    """ Run an Android application in DroidBox

    All the tools required by DroidBox must be installed on
    the server. Make sure that the user running the probe can
    use these tools.
    See https://github.com/pjlantz/droidbox for more details
    """

    # The number of devices should at least be equal to the number of
    # max concurrent job
    _max_device_ = 4
    _duration_ = "60"

    def analyze(self, path):
        # We check that path is a valid APK
        # - It is a valid ZIP
        # - It contains at least classes.dex and AndroidManifest.xml
        if (not zipfile.is_zipfile(path)):
            return (-1, {"filename": path, "Error": "It is not a valid APK"})
        namelist = zipfile.ZipFile(path, "r").namelist()
        if (not ("classes.dex" in namelist and
                 "AndroidManifest.xml" in namelist)):
            return (-1, {"filename": path, "Error": "It is not a valid APK"})

        apk = abspath(path)
        lock = None
        dev = None
        port = 0
        emu_ports = []
        i = 0
        while (i < (self._max_device_ * 2)):
            emu_ports.append(5554 + i)
            i += 2
        for tmp_port in emu_ports:
            lock = LockFile("/tmp/irma-emu-{0}".format(tmp_port))
            try:
                lock.acquire(2)
                port = tmp_port
                dev = "emulator-{0}".format(port)
                break
            except LockTimeout:
                logger.debug("Emulator-{0} is already used".format(tmp_port))
                continue

        if dev is None:
            raise Exception("dev is None")
        if lock is None:
            raise Exception("No lock aquired")

        # cmdarray = ["{0}/DroidBox_4.1.1/startemu.sh".format(
        #    dirname(abspath(__file__))), "droidbox", str(port)]
        img_dir = "{0}/DroidBox_4.1.1/images".format(
                  dirname(abspath(__file__)))
        cmdarray = ["emulator",
                    "-avd", "droidbox",
                    "-system", "{0}/system.img".format(img_dir),
                    "-ramdisk", "{0}/ramdisk.img".format(img_dir),
                    "-wipe-data",
                    "-prop", "dalvik.vm.execution-mode=int:portable",
                    "-port", str(port)]
        emulator = subprocess.Popen(cmdarray)
        time.sleep(50)
        out, out_name = tempfile.mkstemp(suffix=".json")
        logger.debug
        # cmdarray = ["{0}/DroidBox_4.1.1/droidbox.sh".format(
        #    dirname(abspath(__file__))), apk, self._duration_, dev, out_name]
        cmdarray = ["{0}/DroidBox_4.1.1/scripts/droidbox.py".format(
                    dirname(abspath(__file__))),
                    apk, self._duration_, dev, out_name]
        subprocess.call(cmdarray)
        logger.debug("Loading JSON in dictionary {0}".format(out_name))
        res = json.load(open(out_name, "r"))
        os.remove(out_name)
        lock.release()
        os.kill(emulator.pid, signal.SIGKILL)
        return (1, res)
