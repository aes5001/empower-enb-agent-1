/* Copyright (c) 2019 @ FBK - Fondazione Bruno Kessler
 * Author: Kewin Rausch
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
 * Empower Agent.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>

#include <emage.h>

#include "agent.h"
#include "visibility.h"

/* Agents which are actually active. */
INTERNAL LIST_HEAD(em_agents);

INTERNAL int em_core_initialize(void);
INTERNAL int em_core_send(struct agent * a, char * msg, unsigned int size);
INTERNAL int em_core_release_agent(struct agent * a);

/******************************************************************************
 * Atomic access for critical sections                                        *
 ******************************************************************************/

/* Lock used for ONLY initialization */
INTERNAL pthread_mutex_t    em_init_lock = PTHREAD_MUTEX_INITIALIZER;

/* Holds the lock to access initialization procedure. */
#define em_lock_init        pthread_mutex_lock(&em_init_lock)

/* Relinquishes the lock to access initialization procedure */
#define em_unlock_init      pthread_mutex_unlock(&em_init_lock)

/* Lock protecting critical sections between agents. This is used only when
 * calling procedures that needs to iterate between different instances of
 * agents.
 */
INTERNAL pthread_spinlock_t em_agents_lock;

/* Identifies if the core has been initialized or not */
INTERNAL int                em_initialized = 0;

/* Holds the lock to access agent. This procedure may sleep while waiting for
 * lock to be released.
 */
#define em_lock_agents      pthread_spin_lock(&em_agents_lock)

/* Relinquishes the lock to access agent */
#define em_unlock_agents    pthread_spin_unlock(&em_agents_lock)

/******************************************************************************
 * Misc.                                                                      *
 ******************************************************************************/

/* Schedule a job in the agent scheduling subsystem that has to send some data
 * to the connected controller. This allows to be coherent with the existing
 * message handling architecture
 */
INTERNAL
int
em_core_send(struct agent * a, char * msg, unsigned int size)
{
	char *             buf;
	struct sched_job * s      = 0;
	int                status = -1;

	s = malloc(sizeof(struct sched_job));

	if(!s) {
		EMLOG(a, "No more memory for new jobs!\n");
		return -1;
	}

	buf = malloc(sizeof(char) * size);

	if(!buf) {
		EMLOG(a, "No more memory for new buffers!\n");

		free(s);
		return -1;
	}

	memcpy(buf, msg, sizeof(char) * size);

	INIT_LIST_HEAD(&s->next);
	s->args       = buf;
	s->size       = size;
	s->elapse     = 1;
	s->type       = JOB_TYPE_SEND;
	s->reschedule = 0;

	status = em_sched_add_job(s, &a->sched);

	/* Some error occurs?*/
	if(status) {
		EMLOG(a, "Cannot schedule send, error %d\n", status);

		free(buf);
		free(s);
	}

	EMDBG(a, "Core queued new send job\n");

	return status;
}


/* Perform 'one-time only' duties that are necessary before allocate, use or
 * remove agents instances into the core system. Such duties can be
 * initialization, allocation or ordering of specific resources.
 */
INTERNAL
int
__critical
em_core_initialize(void)
{
	if(em_initialized) {
		return 0;
	}

	/*
	 *
	 * Add here initialization/allocation that MUST be done before using the
	 * core system. This will be run just once.
	 *
	 */

	/* Initialize the logging subsystem */
	em_log_init();

	/* Initialize ONCE the agents lock! */
	pthread_spin_init(&em_agents_lock, 0);

	em_initialized = 1;

	EMCLOG("Core initialized; starting operations...\n");

	return 0;
}

/* Releases the resources of an agent AFTER the agent subsystems have been
 * finalized and released.
 */
INTERNAL
int
em_core_release_agent(struct agent * a)
{
	em_sched_stop(&a->sched);
	em_net_stop(&a->net);

	em_tr_flush(&a->trig);
	pthread_spin_destroy(&a->trig.lock);

	EMDBG(a, "Agent released\n");

	free(a);

	return 0;
}

/******************************************************************************
 * Public API implementation                                                  *
 ******************************************************************************/

/* Returns [true/false] depending on the presence of a certain trigger id inside
 * the trigger context of that agent.
 */
EMAGE_API
int
em_has_trigger(uint64_t enb_id, int tid)
{
	struct agent *   a = 0;
	struct trigger * t = 0;

/****** Start of the critical section *****************************************/
	em_lock_agents;

	list_for_each_entry(a, &em_agents, next) {
		if(a->enb_id == enb_id) {
			t = em_tr_find(&a->trig, tid);
			break;
		}
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	return t ? 1 : 0;
}

/* Returns [0/1] depending if a trigger with a certain ID has been removed by
 * the subsystem of the desired agent.
 */
EMAGE_API
int
em_del_trigger(uint64_t enb_id, int tid)
{
	struct agent *   a = 0;
	struct trigger * t = 0;

/****** Start of the critical section *****************************************/
	em_lock_agents;

	list_for_each_entry(a, &em_agents, next) {
		if(a->enb_id == enb_id) {
			em_tr_del(&a->trig, tid);
			break;
		}
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	return t ? 1 : 0;
}

/* Returns [true/false] depending on the state of the agent network context */
EMAGE_API
int
em_is_connected(uint64_t enb_id)
{
	struct agent * a = 0;
	int            f = 0; /* Found? */

/****** Start of the critical section *****************************************/
	em_lock_agents;

	list_for_each_entry(a, &em_agents, next) {
		if(a->enb_id == enb_id) {
			f = (a->net.status == EM_STATUS_CONNECTED);
			break;
		}
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	return f;
}

/* Send a single message to the agent controller */
EMAGE_API
int
em_send(uint64_t enb_id, char * msg, unsigned int size)
{
	struct agent *  a      = 0;
	int             status = -1; /* Failed by default */

	/* Don't accept invalid buffers! */
	if(!msg) {
		EMCLOG("ERROR: Trying to send buffer %p\n", msg);
		return -1;
	}

	/* Don't accept 0 length messages! */
	if(!size) {
		EMCLOG("ERROR: Trying to send buffer with size %d\n", size);
		return -1;
	}

/****** Start of the critical section *****************************************/
	em_lock_agents;

	list_for_each_entry(a, &em_agents, next) {
		if(a->enb_id == enb_id) {
			status = em_core_send(a, msg, size);
			break;
		}
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	return status;
}

/* Find and terminate a single agent, releasing all its resources */
EMAGE_API
int
em_terminate_agent(uint64_t enb_id)
{
	struct agent * a = 0;
	struct agent * b = 0;

	int            f = 0;	/* Found? */
	int            s = 0;	/* Status */

/****** Start of the critical section *****************************************/
	em_lock_agents;

	list_for_each_entry_safe(a, b, &em_agents, next) {
		if(a->enb_id == enb_id) {
			list_del(&a->next);
			f = 1;
			break;
		}
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	if(f) {
		if(a->ops && a->ops->release) {
			s = a->ops->release();
		}

		EMDBG(a, "Releasing agent\n");

		em_core_release_agent(a);
	}

	return s;
}

/* Create and starts a new agent instance, by feeding operations and controller
 * endpoint to contact.
 */
EMAGE_API
int
em_start(
	uint64_t              enb_id,
	struct em_agent_ops * ops,
	char *                ctrl_addr,
	unsigned short        ctrl_port)
{
	struct agent * a = 0;
	struct agent * f = 0;

	int            s  = 0;  /* Status */
	int            r  = 0;  /* Already running? */
	int            nm = 0;  /* No mem? */

/****** Start of the critical section *****************************************/
	em_lock_init;
	em_core_initialize();
	em_unlock_init;
/****** End of the critical section *******************************************/

	/* Any check for necessary call-backs here. For the moment you can also
	 * implement no call-backs: your agent will simply do nothing.
	 */
	if(!ops) {
		EMCLOG("Invalid set of operations for agent, ops=%p\n", ops);
		return -1;
	}

	a = malloc(sizeof(struct agent));

	if(!a) {
		EMCLOG("Not enough memory for new agent!\n");
		return -1;
	}

	/* Initialize the initial agent resources */
	memset(a, 0, sizeof(struct agent));

	INIT_LIST_HEAD(&a->next);

	a->enb_id = enb_id;
	a->init   = 1;          /* The agent is initializing... */

/****** Start of the critical section *****************************************/
	em_lock_agents;

	/* Find if an agent with the same id is already there */
	list_for_each_entry(f, &em_agents, next) {
		if(f->enb_id == enb_id) {
			r = 1;
			break;
		}
	}

	/* If not present, add to the list to avoid insertion of copies while
	 * initializing the agent subsystems.
	 */
	if(!r) {
		list_add(&a->next, &em_agents);
	}

	em_unlock_agents;
/****** End of the critical section *******************************************/

	if(r) {
		EMCLOG("Agent for eNB %d is already running...\n", enb_id);
		return -1;
	}

	memcpy(a->net.addr, ctrl_addr, strlen(ctrl_addr));
	a->net.port  = ctrl_port;
	a->ops       = ops;

	/* Trigger initialization... Not in em_tr_init? */
	a->trig.next = 1;

	pthread_spin_init(&a->trig.lock, 0);
	INIT_LIST_HEAD(&a->trig.ts);

	/*
	 * Start this agent scheduler subsystem:
	 */

	if(em_sched_start(&a->sched)) {
		EMCLOG("Failed to start agent %d scheduler context\n", enb_id);
		s = -1;

		goto err;
	}

	/*
	 * Start this agent network subsystem:
	 */

	if(em_net_start(&a->net)) {
		EMCLOG("Failed to start agent %d network context\n", enb_id);
		s = -1;

		goto err;
	}

	/* Initialization steps finished, and agent ready to be used! */
	a->init = 0;

	/* Custom initialization when everything seems ready */
	if (a->ops && a->ops->init) {
		/* Invoke custom initialization */
		s = a->ops->init();

		/* On error, do not launch the agent */
		if (s < 0) {
			EMCLOG("Custom initialization for agent %d failed with "
				"error %d", enb_id, s);

			goto err;
		}
	}

	EMDBG(a, "Agent initialization finished\n");

	return 0;

/* Remove the agent from the list and destroy it in case of error */
err:
/****** Start of the critical section *****************************************/
	em_lock_agents;
	list_del(&a->next);
	em_unlock_agents;
/****** End of the critical section *******************************************/

	em_core_release_agent(a);

	return s;
}

/* Stop the entire core, destroying all the running agents */
EMAGE_API
int
em_stop(void)
{
	struct agent * a = 0;

	/* Loop until all the agents are released... */
	while(!list_empty(&em_agents)) {
/****** Start of the critical section *****************************************/
		em_lock_agents;

		a = list_first_entry(&em_agents, struct agent, next);
		list_del(&a->next);

		em_unlock_agents;
/****** End of the critical section *******************************************/

		if(a->ops && a->ops->release) {
			a->ops->release();
		}

		em_core_release_agent(a);
	}

	EMCLOG("Shut down...");

	/* Close the logging utilities */
	em_log_release();

	return 0;
}
