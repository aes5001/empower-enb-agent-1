/* Copyright (c) 2018 Kewin Rausch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *  Logging subsystem for the agent core.
 *
 *  This element is common for every agent present in the core, and dump all the
 *  logs inside a common file.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "agent.h"

/* The file descriptor used for logging operations */
INTERNAL FILE * log_fd = 0;

/* Initializes the logging core subsystem */
INTERNAL
int
em_log_init()
{
	char lp[256] = {0};

	/* Unique log per process */
	sprintf(lp, "./emage.%d.log", getpid());
	log_fd = fopen(lp, "w");

	return 0;
}

/* Releases the logging core subsystem */
INTERNAL
void
em_log_release()
{
	fflush(log_fd);
	fclose(log_fd);
}

/* Log the message with a printf-like functionality */
INTERNAL
void
em_log_message(char * msg, ...)
{
	va_list vl;

	va_start(vl, msg);

	/* If the file descriptor has not been set then silently return */
	if (!log_fd) {
		return;
	}

	/* Prints and flush the file... */
	vfprintf(log_fd, msg, vl);
	fflush(log_fd);

	va_end(vl);

	return;
}
