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

/* The agent header.
 *
 * The header contains the definition of an "agent" in the as logic organization
 * of different contexts that works together to accomplish their jobs.
 */

#ifndef __EMAGE_AGENT_H
#define __EMAGE_AGENT_H

#include <stdint.h>

#include "decor.h"
#include "err.h"
#include "emlist.h"
#include "log.h"
#include "net.h"
#include "sched.h"
#include "triggers.h"

/* Agent operations are defined in emage.h, the public header */
struct em_agent_ops;

/* This is ultimately an agent. */
struct agent {
	/* Member of a list (there are more than one agent) */
	struct list_head      next;

	/* eNB ID  bound to this agent context */
	uint64_t              enb_id;
	/* If set informs that the agent subsystem are not ready yet */
	int                   init;

	/* Operations related to the agent */
	struct em_agent_ops * ops;

	/* Context containing the active triggers of this agent */
	struct tr_context     trig;
	/* Context containing the network state machine */
	struct net_context    net;
	/* Context containing the state machine to run tasks in time */
	struct sched_context  sched;
};

#endif /* __EMAGE_AGENT_H */
