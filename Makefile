# Copyright (c) 2016 Kewin Rausch <kewin.rausch@create-net.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# You can personalize these variables if you want a sandboxed installation.
#
export INSTDIR=/usr/lib
export INCLDIR=/usr/include/emage

all:
	cd agent && make
	
clean:
	cd agent && make clean

debug:
	cd agent && make debug

install:
	cd agent && make install

uninstall:
	cd agent && make uninstall
