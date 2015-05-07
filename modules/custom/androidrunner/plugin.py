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

from datetime import datetime

from lib.common.utils import timestamp
import sys
from lib.plugins import PluginBase
from lib.plugin_result import PluginResult
from lib.plugins import ModuleDependency


class AndroidRunnerPlugin(PluginBase):

    class AndroidRunnerResult:
        ERROR = -1
        FAILURE = 0
        SUCCESS = 1

    # =================
    #  plugin metadata
    # =================
    _plugin_name_ = "AndroidRunner"
    _plugin_author_ = "Radoniaina Andriatsimandefitra"
    _plugin_version_ = "0.1"
    _plugin_category_ = "custom"
    _plugin_description_ = "Dynamic analysis of Android applications"
    _plugin_dependencies_ = [
        ModuleDependency(
            "lockfile",
            help="Enable us to manage the use of virtual machine"
        )
    ]

    # =============
    #  constructor
    # =============

    def __init__(self):
        module = sys.modules["modules.custom.androidrunner."
                             "androidrunner"].AndroidRunner
        self.module = module()
        pass

    @classmethod
    def verify(cls):
        pass

    # ==================
    #  probe interfaces
    # ==================
    def run(self, paths):
        response = PluginResult(name=type(self).plugin_name,
                                type=type(self).plugin_category,
                                version=None)
        try:
            started = timestamp(datetime.utcnow())
            response.results = self.module.analyze(paths)
            stopped = timestamp(datetime.utcnow())
            response.duration = stopped - started
            response.status = self.AndroidRunnerResult.SUCCESS
        except Exception as e:
            response.status = self.AndroidRunnerResult.ERROR
            response.results = str(e)
        return response
