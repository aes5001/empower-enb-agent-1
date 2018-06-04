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
 * Empower Agent internal triggers logic.
 */

#ifndef __EMAGE_TRIGGERS_H
#define __EMAGE_TRIGGERS_H

#include "emlist.h"
#include "visibility.h"

/* Possible type of triggers which can be created */
enum trigger_type {
	TR_TYPE_UE_REP,   /* UE report */
	TR_TYPE_UE_MEAS,  /* UE measurement */
	TR_TYPE_MAC_REP   /* MAC reporting */
};

/* Definition for a single trigger. */
struct trigger {
	/* Member of a list. */
	struct list_head next;

	/* Id of this trigger. */
	int id;
	/* Type of trigger */
	int type;
	/* Module bound with this trigger. */
	int mod;
	/* Id bound to the instance for this trigger; this is useful to
	 * distinguish between IDs of the same module.
	 */
	int instance;

	/* Original request message. */
	char * req;
	/* Size of the original request */
	unsigned int size;
};

/* Triggering context for an agent. */
struct tr_context {
	/* List of triggers. */
	struct list_head ts;

	/* Id for the next trigger*/
	int next;

	/* Lock for this context. */
	pthread_spinlock_t lock;
};

/* Add a new trigger in the agent triggering context.
 *
 * By adding a trigger you make it valid, since disabled triggers are just
 * removed from the list.
 */
struct trigger * em_tr_add(
	struct tr_context * tc,
	int                 id,
	int                 mod,
	int                 typ,
	int                 instance,
	char *              req,
	unsigned char       size);

/* Find, remove and free a trigger */
INTERNAL int em_tr_del(struct tr_context * tc, int mod, int type, int instance);

/* Find an trigger with given id */
INTERNAL struct trigger * em_tr_find(struct tr_context * tc, int id);

/* Peek the context to see if it has trigger with specific keys */
INTERNAL struct trigger * em_tr_find_ext(
	struct tr_context * tc, int mod, int type, int instance);

/* Flush everything and clean the context. */
INTERNAL int em_tr_flush(struct tr_context * tc);

/* Free the resources of a trigger */
INTERNAL void em_tr_free(struct trigger * tc);

/* Acquires the next usable trigger id */
INTERNAL int em_tr_next_id(struct tr_context * tc);

#endif
