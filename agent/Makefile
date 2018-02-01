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
# Makefile to compile the EMAge agent as a library.
#

CC=gcc

AGENTP=.

LIBS=-lpthread -lemproto
INCLUDES=-I../include

all:
	$(CC) $(INCLUDES) -c -fpic                                      \
		$(AGENTP)/net.c                                         \
		$(AGENTP)/sched.c                                       \
		$(AGENTP)/triggers.c                                    \
		$(AGENTP)/core.c
	$(CC) -shared -o libemagent.so *.o

clean:
	rm -f ./*.o
	rm -f ./*.a
	rm -f ./*.so

debug:
	$(CC) $(INCLUDES) -c -fpic -DEM_DEBUG                           \
		$(AGENTP)/net.c                                         \
		$(AGENTP)/sched.c                                       \
		$(AGENTP)/triggers.c                                    \
		$(AGENTP)/core.c
	$(CC) -shared -o libemagent.so *.o

install:
	cp ./libemagent.so $(INSTDIR)
	mkdir -p $(INCLDIR)
	cp -r ../include/emage.h $(INCLDIR)/
	cp -r ../include/emlog.h $(INCLDIR)/

uninstall:
	rm $(INSTDIR)/libemagent.so
	rm -f $(INCLDIR)/emage.h
	rm -f $(INCLDIR)/emlog.h
