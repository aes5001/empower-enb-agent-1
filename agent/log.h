/* Copyright (c) 2016 Kewin Rausch
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
 *  Empower Agent messages handling procedures.
 */

#ifndef __EMAGE_LOG_H
#define __EMAGE_LOG_H

#include <stdio.h>
#include "visibility.h"

#define LOG_NAME_SPACE "16"

/* Log routine for out-of-agent context case */
#define EMCLOG(x, ...) \
	em_log_message("CORE     > " x, ##__VA_ARGS__)

/* Log routine for every feedback */
#define EMLOG(a, x, ...) \
	em_log_message("AGENT[%d] > " x, a->enb_id, ##__VA_ARGS__)

#ifdef EBUG

/* Debugging routine; valid only when EBUG symbol is defined  */
#define EMDBG(a, x, ...) \
	em_log_message("AGENT[%d] > " x, a->enb_id, ##__VA_ARGS__)

#else /* EBUG */
#define EMDBG(id, x, ...)
#endif /* EBUG */

/* Prepare to use logging functionalities */
INTERNAL int  em_log_init();

/* Releases the logging subsystem and close any existing resource */
INTERNAL void em_log_release();

/* Log a message with a printf-like style inside a previously initialized file
 * on he file-system. This procedure should be called after 'log_init', but
 * eventually fails without generating exceptions if called before.
 */
INTERNAL void em_log_message(char * msg, ...);

#endif /* __EMAGE_LOG_H */
