#
# Copyright (c) 2013-2014 QuarksLab.
# This file is part of IRMA project.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the top-level directory
# of this distribution and at:
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# No part of the project, including this file, may be copied,
# modified, propagated, or distributed except according to the
# terms contained in the LICENSE file.

import sys

from datetime import datetime

from lib.common.utils import timestamp
from lib.plugins import PluginBase
from lib.plugin_result import PluginResult
from lib.irma.common.utils import IrmaProbeType
from lib.plugins import ModuleDependency


class AndroidMetadataPlugin(PluginBase):

    class AndroidMetadataResult:
        ERROR = -1
        FAILURE = 0
        SUCCESS = 1

    # =================
    #  plugin metadata
    # =================
    _plugin_name_ = "AndroidMetadata"
    _plugin_author_ = "Radoniaina Andriatsimandefitra Ratsisahanana"
    _plugin_version_ = "0.1"
    _plugin_category_ = IrmaProbeType.unknown
    _plugin_description_ = "Static analysis of APK"
    _plugin_dependencies_ = [
        ModuleDependency(
            "androguard",
            help="Need Androguard to extract metadata. "
                 "See https://github.com/androguard/androguard or "
                 "https://code.google.com/p/androguard/wiki/Installation "
                 "for more details about the installation"
        )
    ]

    # =============
    #  constructor
    # =============

    def __init__(self):
        module = sys.modules["modules.metadata.android-meta."
                             "androidmetadata"].AndroidMetadata
        self.module = module()

    @classmethod
    def verify(cls):
        pass

    # ==================
    #  probe interfaces
    # ==================
    def run(self, paths):
        results = PluginResult(name=type(self).plugin_name,
                               type=type(self).plugin_category,
                               version=type(self).plugin_version)
        try:
            started = timestamp(datetime.utcnow())
            results.status, results.results = self.module.analyze(paths)
            stopped = timestamp(datetime.utcnow())
            results.duration = stopped - started
            results.status = self.AndroidMetadataResult.SUCCESS
        except Exception as e:
            results.status = self.AndroidMetadataResult.ERROR
            results.results = str(e)
        return results
