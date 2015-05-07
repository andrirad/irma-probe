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


class AndroidMetadata(object):
    """ IRMA module to extract metadata from APK.


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
            val = []
            for path in p[perm]:
                path2 = get_Path(d, path)
                val.extend((path2["src"], path2["dst"], path2["idx"]))
            res[perm] = val
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
        res["min-sdk"] = a.get_min_sdk_version()
        res["max-sdk"] = a.get_max_sdk_version()
        res["target-sdk"] = a.get_target_sdk_version()
        res["package"] = a.get_package()
        res["libraries"] = a.get_libraries()

        # Declared permissions
        res["permissions"] = a.get_permissions()
        # Permissions used by the code
        res["used-permissions"] = self.used_permissions(d, dx)

        # Android components
        # Improvements : check if a receiver is dynamically created in the code
        res["main-activity"] = a.get_main_activity()
        res["activities"] = a.get_activities()
        res["providers"] = a.get_providers()
        res["receivers"] = a.get_receivers()
        res["services"] = a.get_services()

        # Native, dynamic and reflection
        res["native"] = analysis.is_native_code(dx)
        res["dynamic"] = analysis.is_dyn_code(dx)
        res["reflection"] = analysis.is_reflection_code(dx)

        return (1, res)
