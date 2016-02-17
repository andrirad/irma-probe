from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *

from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.core.analysis.risk import *
from androguard.decompiler.decompiler import *

from androguard.util import *
from androguard.misc import *

import zipfile

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class AndroidStatic(object):
    """ IRMA module to extract statically data from APK.


    This class mainly use what is proposed in Androguard.
    """

    @staticmethod
    def used_permissions(d, dx):
        """
        Return a dictionnary of the permissions used by the application
        and where it is used. This method is based on the show_Permissions
        method from Androguard
        """
        res = {}
        p = dx.get_permissions([])
        for perm in p.keys():
            res2 = []
            for path in p[perm]:
                path2 = get_Path(d, path)
                res2.append({"src": path2["src"], "dest": path2["dst"],
                             "idx": path2["idx"]})
            res[perm] = res2
        return res

    def analyze(self, path):
        res = {}
        # We check that path is a valid APK
        # - It is a valid ZIP
        # - It contains at least classes.dex and AndroidManifest.xml
        if (not zipfile.is_zipfile(path)):
            return (-1, {"filename": path, "Error": "It is not a valid APK"})
        namelist = zipfile.ZipFile(path, "r").namelist()
        if (not ("classes.dex" in namelist and
                 "AndroidManifest.xml" in namelist)):
            return (-1, {"filename": path, "Error": "It is not a valid APK"})
        a, d, dx = AnalyzeAPK(path, decompiler="dad")
        res["minsdk"] = a.get_min_sdk_version()
        res["maxsdk"] = a.get_max_sdk_version()
        res["targetsdk"] = a.get_target_sdk_version()
        res["package"] = a.get_package()
        res["libraries"] = a.get_libraries()

        # Declared permissions
        res["permissions"] = a.get_permissions()
        # Permissions used by the code
        res["usedpermissions"] = self.used_permissions(d, dx)

        # Android components
        # Improvements : check if a receiver is dynamically created in the code
        res["mainactivity"] = a.get_main_activity()
        res["activities"] = a.get_activities()
        res["providers"] = a.get_providers()
        res["receivers"] = a.get_receivers()
        res["services"] = a.get_services()

        # Native, dynamic and reflection
        res["native"] = analysis.is_native_code(dx)
        if (not res["native"]):
            ftypes = a.get_files_types()
            for key in ftypes:
                if (ftypes[key].find("ELF") >= 0):
                    res["native"] = True
                    break

        res["dynamic"] = analysis.is_dyn_code(dx)
        res["reflection"] = analysis.is_reflection_code(dx)

        res["asciiobf"] = analysis.is_ascii_obfuscation(d)
        res["crypto"] = analysis.is_crypto_code(dx)

        # Find URLs or IPv4 address in strings
        tmp = []
        for s in d.get_strings():
            start = s.find("http://")
            if (start < 0):
                start = s.find("https://")
            if (start >= 0):
                end = s.find(" ", start)
                if (end < 0):
                    tmp.append(s[start:])
                else:
                    tmp.append(s[start:end])
                continue
            ip_reg = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            for ip in ip_reg.findall(s):
                tmp.append(ip)

        if (len(tmp) > 0):
            res["urls"] = tmp

        return (1, res)
