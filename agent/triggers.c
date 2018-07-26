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

#include <stdlib.h>
#include <string.h>

#include <pthread.h>

#include <emage/emproto.h>

#include "agent.h"

/******************************************************************************
 * Locking and atomic context                                                 *
 ******************************************************************************/

/* Holds the lock to access critical part of a network context */
#define trig_lock_ctx(t)        pthread_spin_lock(&t->lock)

/* Relinquishes the lock to access critical part of a network context */
#define trig_unlock_ctx(t)      pthread_spin_unlock(&t->lock)

/******************************************************************************
 * Procedures                                                                 *
 ******************************************************************************/

/* Add a new trigger with given characteristics in the given context */
INTERNAL
struct trigger *
em_tr_add(
	struct tr_context * tc,
	int                 id,
	int                 mod,
	int                 type,
	int                 instance,
	char *              req,
	unsigned char       size)
{
	struct agent *   a = container_of(tc, struct agent, trig);
	struct trigger * t = em_tr_find_ext(tc, mod, type, instance);

	if(t) {
		EMDBG(a, "Trigger id %d, type %d already exists\n", id, type);
		return t;
	}

	t = malloc(sizeof(struct trigger));

	if(!t) {
		EMLOG(a, "Not enough memory for new trigger!\n");
		return 0;
	}

	memset(t, 0, sizeof(struct trigger));

	if(req) {
		t->req = malloc(sizeof(char) * size);

		if(!t->req) {
			EMLOG(a, "Not enough memory for new buffer!\n");
			free(t);
			return 0;
		}

		memcpy(t->req, req, size);
		t->size = size;
	}

	INIT_LIST_HEAD(&t->next);
	t->id       = id;
	t->mod      = mod;
	t->type     = type;
	t->instance = instance;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_add(&t->next, &tc->ts);

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	//EMDBG("New trigger enabled, id=%d, type=%d", id, type);

	return t;
}

/* Delete a trigger with given characteristics from the context */
INTERNAL
int
em_tr_del(struct tr_context * tc, int id)
{
#ifdef EBUG
	struct agent *   a = container_of(tc, struct agent, trig);
#endif
	struct trigger * t = 0;
	struct trigger * u = 0;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry_safe(t, u, &tc->ts, next) {
		if(t->id == id) {
			list_del(&t->next);
			trig_unlock_ctx(tc);

			EMDBG(a, "Removing trigger %d, type=%d, mod=%d\n",
				t->id, t->type, t->mod);

			em_tr_free(t);

			return 0;
		}
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	EMDBG(a, "Trigger doesn't exists, id=%d, type=%d, mod=%d \n",
		t->id, t->type, t->mod);

	return -1;
}

/* Delete a trigger with given characteristics from the context */
INTERNAL
int
em_tr_del_ext(struct tr_context * tc, int mod, int type, int instance)
{
#ifdef EBUG
	struct agent *   a = container_of(tc, struct agent, trig);
#endif
	struct trigger * t = 0;
	struct trigger * u = 0;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry_safe(t, u, &tc->ts, next) {
		if(t->type == type &&
			t->mod == mod &&
			t->instance == instance) {

			list_del(&t->next);
			trig_unlock_ctx(tc);

			EMDBG(a, "Removing trigger %d, type=%d, mod=%d\n",
				t->id, t->type, t->mod);

			em_tr_free(t);

			return 0;
		}
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	EMDBG(a, "Trigger doesn't exists, id=%d, type=%d, mod=%d \n",
		t->id, t->type, t->mod);

	return -1;
}

/* Find a trigger using its id */
INTERNAL
struct trigger *
em_tr_find(struct tr_context * tc, int id)
{
	struct trigger * t = 0;
	int              f = 0;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry(t, &tc->ts, next) {
		if(t->id == id) {
			f = 1;
			break;
		}
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	if(f) {
		return t;
	}

	return 0;
}

/* Find a trigger using multiple keys; a very specific task */
INTERNAL
struct trigger *
em_tr_find_ext(
	struct tr_context * tc, int mod, int type, int instance)
{
	struct trigger * t = 0;
	int              f = 0;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry(t, &tc->ts, next) {
		if(t->mod == mod &&
			t->type == type &&
			t->instance == instance) {

			f = 1;
			break;
		}
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	if(f) {
		return t;
	}

	return 0;
}

/* Remove any trigger from this context */
INTERNAL
int
em_tr_flush(struct tr_context * tc)
{
#ifdef EBUG
	struct agent *   a = container_of(tc, struct agent, trig);
#endif
	struct trigger * t = 0;
	struct trigger * u = 0;

	EMDBG(a, "Starting to clean triggers\n");

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry_safe(t, u, &tc->ts, next) {
		EMDBG(a, "Flushing out trigger %d, mod=%d\n", t->id, t->mod);

		list_del(&t->next);
		em_tr_free(t);
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	return 0;
}

/* Free a single trigger releasing all its resources */
INTERNAL
void
em_tr_free(struct trigger * t)
{
	if(t) {
		if(t->req) {
			free(t->req);
			t->req = 0;
		}

		free(t);
	}
}

/* Acquire the next valid id for a trigger */
INTERNAL
int
em_tr_next_id(struct tr_context * tc)
{
	struct trigger * t = 0;
	int              n = 0;

	/* Select a random trigger ID which is not already present */
	do {
		/* Rand generate values from 0 to RAND_MAX */
		n = rand();

		if(!n) {
			n++;
		}

/****** Start of the critical section *****************************************/
		trig_lock_ctx(tc);

		list_for_each_entry(t, &tc->ts, next) {
			if(n == t->id) {
				n = 0;
				break;
			}
		}

		trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/
	} while(!n);

	return n;
}

/* Remove a trigger from the given context  */
INTERNAL
int
em_tr_rem(struct tr_context * tc, int id, int type)
{
#ifdef EBUG
	struct agent *   a = container_of(tc, struct agent, trig);
#endif
	struct trigger * t = 0;
	struct trigger * u = 0;

/****** Start of the critical section *****************************************/
	trig_lock_ctx(tc);

	list_for_each_entry_safe(t, u, &tc->ts, next) {
		if(t->id == id) {
			EMDBG(a, "Removing trigger %d, mod=%d", t->id, t->mod);

			list_del(&t->next);
			em_tr_free(t);

			break;
		}
	}

	trig_unlock_ctx(tc);
/****** End of the critical section *******************************************/

	return 0;
}
