#!/usr/bin/env python

# Copyright (C) 2018:
#     Sonia Bogos, sonia.bogos@elca.ch
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import subprocess

author = "Sonia Bogos"
maintainer = "Sonia Bogos"
version = "0.0.1"


def get_fuzzed_value(logger, param):

    proc = subprocess.Popen(
        ["echo '{param}' | radamsa".format(param=param)],
        stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    #logger.debug("echo {param} | radamsa".format(param=param))
    return out[:-1]