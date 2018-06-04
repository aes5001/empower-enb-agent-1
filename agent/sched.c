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
 * Empower Agent internal scheduler logic.
 */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <emage.h>
#include <emage/emproto.h>

#include "agent.h"

/*
 * Some states when processing jobs
 */

#define JOB_NET_ERROR                          -1
#define JOB_CONSUMED                            0
#define JOB_NOT_ELAPSED                         1
#define JOB_RESCHEDULE                          2

/* Dif "b-a" two timespec structs and return such value in ms*/
#define ts_diff_to_ms(a, b)                     \
	(((b->tv_sec - a->tv_sec) * 1000) +     \
	 ((b->tv_nsec - a->tv_nsec) / 1000000))

/******************************************************************************
 * Locking and atomic context                                                 *
 ******************************************************************************/

/* Holds the lock to access critical part of a network context */
#define sched_lock_ctx(s)       pthread_spin_lock(&s->lock)

/* Relinquishes the lock to access critical part of a network context */
#define sched_unlock_ctx(s)     pthread_spin_unlock(&s->lock)

/******************************************************************************
 * Utilities                                                                  *
 ******************************************************************************/

/* Fix the last details and send the message */
INTERNAL
int
em_sched_send_msg(struct agent * a, char * msg, unsigned int size)
{
	if(size > EM_BUF_SIZE) {
		EMLOG(a, "Message too long, msg=%lu, limit=%d!\n",
			size + sizeof(uint32_t), EM_BUF_SIZE);

		return JOB_CONSUMED;
	}

	/* Insert the correct sequence number before sending */
	epf_seq(msg, size, em_net_next_seq(&a->net));

	EMDBG(a, "Sending a message of %d bytes...\n", size);

	if(em_net_send(&a->net, msg, size) < 0) {
		return JOB_NET_ERROR; /* On error */
	} else {
		return JOB_CONSUMED;  /* On success */
	}
}

/******************************************************************************
 * Jobs                                                                       *
 ******************************************************************************/

/* Execute a Send job */
INTERNAL
int
em_sched_perform_send(struct agent * a, struct sched_job * job)
{
	return em_sched_send_msg(a, job->args, job->size);
}

/* Execute a Cell Capability job */
INTERNAL
int
em_sched_perform_cell_setup(struct agent * a, struct sched_job * job)
{
	uint16_t pci = 0;
	uint32_t mod = 0;

	if(epp_head((char *)job->args, job->size, 0, 0, &pci, &mod)) {
		return 0;
	}

	EMDBG(a, "Performing a cell Capability job\n");

	if(a->ops && a->ops->cell_setup_request) {
		a->ops->cell_setup_request(mod, pci);
	}

	return JOB_CONSUMED;
}

/* Execute a eNB Capability job */
INTERNAL
int
em_sched_perform_enb_setup(struct agent * a, struct sched_job * job)
{
	uint32_t mod = 0;

	if(epp_head((char *)job->args, job->size, 0, 0, 0, &mod)) {
		EMLOG(a, "Cannot parse cell id in Cell setup\n");
		return 0;
	}

	EMDBG(a, "Performing an eNB Capability job\n");

	if(a->ops && a->ops->enb_setup_request) {
		a->ops->enb_setup_request(mod);
	}

	return JOB_CONSUMED;
}

/* Execute an Handover job */
INTERNAL
int
em_sched_perform_ho(struct agent * a, struct sched_job * job)
{
	uint32_t mod   = 0;
	uint16_t scell = 0;
	uint16_t rnti  = 0;
	uint32_t tenb  = 0;
	uint16_t tcell = 0;
	uint8_t  cause = 0;

	if(epp_head((char *)job->args, job->size, 0, 0, &scell, &mod)) {
		return 0;
	}

	if(epp_single_ho_req(
		(char *)job->args, job->size, &rnti, &tenb, &tcell, &cause)) {
		return 0;
	}

	EMDBG(a, "Performing a Handover job\n");

	if(a->ops && a->ops->handover_UE) {
		a->ops->handover_UE(mod, scell, rnti, tenb, tcell, cause);
	}

	return JOB_CONSUMED;
}

/* Execute an UE measurement job */
INTERNAL
int
em_sched_perform_ue_measure(struct agent * a, struct sched_job * job)
{
	struct trigger * t     = (struct trigger *)job->args;

	uint8_t          mid   = 0;
	uint16_t         rnti  = 0;
	uint16_t         freq  = 0;
	uint16_t         intv  = 0;
	uint16_t         max_c = 0;
	uint16_t         max_m = 0;

	EMDBG(a, "Performing an UE measurements job\n");

	if(a->ops && a->ops->ue_measure) {
		/* Find the real trigger; the given one just an empty copy... */
		t = em_tr_find(&a->trig, t->id);

		if(t) {
			epp_trigger_uemeas_req(
				t->req,
				t->size,
				&mid,
				&rnti,
				&freq,
				&intv,
				&max_c,
				&max_m);

			a->ops->ue_measure(
				t->mod,
				t->id,
				mid,
				rnti,
				freq,
				intv,
				max_c,
				max_m);
		}
	}

	return JOB_CONSUMED;
}

/* Execute a MAC report job */
INTERNAL
int
em_sched_perform_mac_report(struct agent * a, struct sched_job * job)
{
	uint32_t         mod = 0;
	int16_t          intv;
	struct trigger * t   = (struct trigger *)job->args;

	EMDBG(a, "Performing a MAC report job\n");

	if(a->ops && a->ops->mac_report) {
		t = em_tr_find(&a->trig, t->id);

		if(t) {
			epp_trigger_macrep_req(t->req, t->size, &intv);

			a->ops->mac_report(t->mod, intv, t->id);
		}
	}

	return JOB_CONSUMED;
}

/* Execute an UE report job */
INTERNAL
int
em_sched_perform_ue_report(struct agent * a, struct sched_job * job)
{
	uint32_t         mod = 0;
	struct trigger * t   = (struct trigger *)job->args;

	EMDBG(a, "Performing an UE report job\n");

	if(a->ops && a->ops->ue_report) {
		a->ops->ue_report(t->mod, t->id);
	}

	return JOB_CONSUMED;
}

/* Execute a Hello job */
INTERNAL
int
em_sched_perform_hello(struct agent * a, struct sched_job * job)
{
	char buf[EM_BUF_SIZE];
	int blen = 0;
	int sent = 0;
	int ret  = JOB_CONSUMED;

	blen = epf_sched_hello_req(
		buf, EM_BUF_SIZE, a->enb_id, 0, 0, job->elapse ,0);

	EMDBG(a, "Performing an Hello job\n");

	ret  = em_sched_send_msg(a, buf, blen);

	return ret;
}

/* Execute a RAN Setup job */
INTERNAL
int
em_sched_perform_ran_setup(struct agent * a, struct sched_job * job)
{
	uint32_t mod = 0;
	
	epp_head(job->args, job->size, 0, 0, 0, &mod);

	EMDBG(a, "Performing a RAN Setup job\n");

	if (a->ops && a->ops->ran_setup_request) {
		a->ops->ran_setup_request(mod);
	}

	return JOB_CONSUMED;
}

/* Execute a RAN User job  */
INTERNAL
int
em_sched_perform_ran_user(struct agent * a, struct sched_job * job)
{
	ep_msg_type     type = 0;
	ep_act_type     act  = 0;
	ep_op_type      op   = 0;
	uint32_t        mod  = 0;

	ep_ran_user_det udet;

	/* If no operations are there, don't perform any other operation */
	if (!a->ops) {
		return JOB_CONSUMED;
	}

	epp_head(job->args, job->size, &type, 0, 0, &mod);
	act = epp_single_type(job->args, job->size);
	op  = epp_single_op(job->args, job->size);

	EMDBG(a, "Performing a RAN User job\n");

	/* Depending on the operation requested, call the correct callback */
	switch (op) {
	/* A request */
	case EP_OPERATION_UNSPECIFIED:
		if (a->ops->ran_user_request) {
			epp_single_ran_usr_req(job->args, job->size, &udet.id);
			a->ops->ran_user_request(mod, udet.id);
		}
		break;
	/* An addition */
	case EP_OPERATION_ADD:
		if (a->ops->ran_user_add) {
			epp_single_ran_usr_add(job->args, job->size, &udet);
			a->ops->ran_user_add(mod, udet.id, udet.tenant);
		}
		break;
	/* A remove */
	case EP_OPERATION_REM:
		if (a->ops->ran_user_rem) {
			epp_single_ran_usr_rem(job->args, job->size, &udet);
			a->ops->ran_user_rem(mod, udet.id);
		}
		break;
	}

	return JOB_CONSUMED;
}

/* Execute a RAN Tenant job */
INTERNAL
int
em_sched_perform_ran_tenant(struct agent * a, struct sched_job * job)
{
	ep_msg_type       type = 0;
	ep_act_type       act  = 0;
	ep_op_type        op   = 0;
	uint32_t          mod  = 0;

	ep_ran_tenant_det tdet;

	/* If no operations are there, dont perform any other job. */
	if (!a->ops) {
		return JOB_CONSUMED;
	}

	epp_head(job->args, job->size, &type, 0, 0, &mod);
	act = epp_single_type(job->args, job->size);
	op  = epp_single_op(job->args, job->size);

	EMDBG(a, "Performing a RAN Tenant job\n");

	/* Depending on the operation requested, call the correct callback */
	switch (op) {
		/* A request */
	case EP_OPERATION_UNSPECIFIED:
		if (a->ops->ran_tenant_request) {
			epp_single_ran_ten_req(job->args, job->size, &tdet);
			a->ops->ran_tenant_request(mod, tdet.id);
		}
		break;
	/* An addition */
	case EP_OPERATION_ADD:
		if (a->ops->ran_tenant_add) {
			epp_single_ran_ten_add(job->args, job->size, &tdet);
			a->ops->ran_tenant_add(mod, tdet.id, tdet.sched);
		}
		break;
	/* A remove */
	case EP_OPERATION_REM:
		if (a->ops->ran_tenant_rem) {
			epp_single_ran_ten_rem(job->args, job->size, &tdet);
			a->ops->ran_tenant_rem(mod, tdet.id);
		}
		break;
	}

	return JOB_CONSUMED;
}

/* Perform a RAN Scheduler job */
INTERNAL
int
em_sched_perform_ran_scheduler(struct agent * a, struct sched_job * job)
{
	ep_msg_type       type = 0;
	ep_act_type       act  = 0;
	ep_op_type        op   = 0;
	uint32_t          mod  = 0;

	uint32_t          id   = 0;
	uint64_t          ten  = 0;
	ep_ran_sparam_det par;

	/* If no operations are there, dont perform any other job. */
	if (!a->ops) {
		return JOB_CONSUMED;
	}

	epp_head(job->args, job->size, &type, 0, 0, &mod);
	act = epp_single_type(job->args, job->size);
	op  = epp_single_op(job->args, job->size);

	EMDBG(a, "Performing a RAN Scheduler job\n");

	/* Depending on the operation requested, call the correct callback */
	switch (op) {
	/* A request of parameter status */
	case EP_OPERATION_UNSPECIFIED:
		if (a->ops->ran_sched_get_parameter) {
			epp_single_ran_sch_req(
				job->args, job->size, &id, &ten, &par);

			a->ops->ran_sched_get_parameter(
				mod, 
				id, 
				ten == 0 ? 
					EP_RAN_SCHED_TENANT_TYPE :
					EP_RAN_SCHED_USER_TYPE,
				ten,
				&par);
		}
		break;
	/* A set of parameter status */
	case EP_OPERATION_SET:
		if (a->ops->ran_sched_set_parameter) {
			epp_single_ran_sch_set(
				job->args, job->size, &id, &ten, &par);

			a->ops->ran_sched_set_parameter(
				mod,
				id,
				ten == 0 ?
					EP_RAN_SCHED_TENANT_TYPE :
					EP_RAN_SCHED_USER_TYPE,
				ten,
				&par);
		}
		break;
		break;
	}

	return JOB_CONSUMED;
}

/* Release a job which is no more useful.
 * This procedure assumes the job has already be removed from the tasks list.
 */
INTERNAL
int
em_sched_release_job(struct sched_job * job)
{
	/* If 'size' is set, 'args' contains a mallocated buffer that needs to
	 * be released too.
	 */
	if(job->args && job->size > 0) {
		free(job->args);
		job->args = 0;
	}

	free(job);
	return 0;
}

/******************************************************************************
 * Generic procedures:                                                        *
 ******************************************************************************/

/* Add a generic job into the scheduler 'todo' list */
INTERNAL
int
em_sched_add_job(struct sched_job * job, struct sched_context * sched)
{
	int status = 0;
#ifdef EBUG
	struct agent * a = container_of(sched, struct agent, sched);
#endif

	clock_gettime(CLOCK_REALTIME, &job->issued);

/****** Start of the critical section *****************************************/
	sched_lock_ctx(sched);

	/* Perform the job if the context is not stopped. */
	if(!sched->stop) {
		list_add(&job->next, &sched->jobs);
	} else {
		status = -1;
	}

	sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/

	EMDBG(a, "Job %d added to scheduler\n", job->type);

	return status;
}

/* Find a job from the scheduler 'todo' job list */
INTERNAL
struct sched_job *
em_sched_find_job(
	struct sched_context * sched, unsigned int id, int type)
{
	struct sched_job * job = 0;

/****** Start of the critical section *****************************************/
	sched_lock_ctx(sched);

	list_for_each_entry(job, &sched->jobs, next) {
		if(job->id == id && job->type == type) {
			sched_unlock_ctx(sched);
			return job;
		}
	}

	sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/

	return 0;
}

/* Performs a given job depending on how it is classified */
INTERNAL
int
em_sched_perform_job(
	struct agent * a, struct sched_job * job, struct timespec * now)
{
	int               s  = JOB_CONSUMED;
	struct timespec * is = &job->issued;

	/* Job not to be performed now. */
	if(ts_diff_to_ms(is, now) < job->elapse) {
		return JOB_NOT_ELAPSED;
	}

	EMDBG(a, "Selected job %d, type=%d\n", job->id, job->type);

	switch(job->type) {
	case JOB_TYPE_SEND:
		s = em_sched_perform_send(a, job);
		break;
	case JOB_TYPE_HELLO:
		s = em_sched_perform_hello(a, job);
		break;
	case JOB_TYPE_ENB_SETUP:
		s = em_sched_perform_enb_setup(a, job);
		break;
	case JOB_TYPE_CELL_SETUP:
		s = em_sched_perform_cell_setup(a, job);
		break;
	case JOB_TYPE_UE_REPORT:
		s = em_sched_perform_ue_report(a, job);
		break;
	case JOB_TYPE_UE_MEASURE:
		s = em_sched_perform_ue_measure(a, job);
		break;
	case JOB_TYPE_MAC_REPORT:
		s = em_sched_perform_mac_report(a, job);
		break;
	case JOB_TYPE_HO:
		s = em_sched_perform_ho(a, job);
		break;
	case JOB_TYPE_RAN_SETUP:
		s = em_sched_perform_ran_setup(a, job);
		break;
	case JOB_TYPE_RAN_TENANT:
		s = em_sched_perform_ran_tenant(a, job);
		break;
	case JOB_TYPE_RAN_USER:
		s = em_sched_perform_ran_user(a, job);
		break;
	case JOB_TYPE_RAN_SCHEDULER:
		s = em_sched_perform_ran_scheduler(a, job);
		break;
	default:
		EMDBG(a, "Unknown job cannot be performed, type=%d", job->type);
	}

	/* The job has to be rescheduled? */
	if(s == 0 && job->reschedule != 0) {
		EMDBG(a, "The job will be rescheduled!\n");
		return JOB_RESCHEDULE;
	}

	return s;
}

/* Consumed all the jobs scheduled inside the context lists.
 *
 * This procedure is the one which signal eventual network errors to the network
 * context. Network context is a passive listener and can realize that the
 * connection is down with high latency.
 */
INTERNAL
int
em_sched_consume(struct sched_context * sched)
{
	struct agent *       a   = container_of(sched, struct agent, sched);
	struct net_context * net = &a->net;
	struct sched_job *   job = 0;
	struct sched_job *   tmp = 0;
	struct timespec      now;
	int                  op = 0;
	int                  nj = 1;  /* New job to consume. */
	int                  ne = 0;  /* Network error. */

	while(nj) {
/****** Start of the critical section *****************************************/
		sched_lock_ctx(sched);

		/* Nothing to to? Go to sleep. */
		if(list_empty(&sched->jobs)) {
			nj = 0;
		}

		if(nj) {
			job = list_first_entry(
				&sched->jobs,
				struct sched_job,
				next);

			list_del(&job->next);
		}

		sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/

		/* Nothing to do... out! */
		if(!nj) {
			break;
		}

		clock_gettime(CLOCK_REALTIME, &now);

		op = em_sched_perform_job(a, job, &now);

/****** Start of the critical section *****************************************/
		sched_lock_ctx(sched);

		/* Possible outcomes. */
		switch(op) {
		case JOB_NOT_ELAPSED:
			list_add(&job->next, &sched->todo);
			break;
		case JOB_RESCHEDULE:
			job->issued.tv_sec  = now.tv_sec;
			job->issued.tv_nsec = now.tv_nsec;
			list_add(&job->next, &sched->todo);

			/* Consume one reschedule credit */
			if(job->reschedule > 0) {
				job->reschedule--;
			}

			break;
		case JOB_CONSUMED:
			em_sched_release_job(job);
			break;
		case JOB_NET_ERROR:
			em_sched_release_job(job);
			ne = 1;
			break;
		}

		/* Network error happened? */
		if(ne) {
			/* Dump jobs to process at next run */
			list_for_each_entry_safe(job, tmp, &sched->todo, next) {
				list_del(&job->next);
				em_sched_release_job(job);
			}

			/* Free ANY remaining job still to process */
			list_for_each_entry_safe(job, tmp, &sched->jobs, next) {
				list_del(&job->next);
				em_sched_release_job(job);
			}

			sched_unlock_ctx(sched);

			em_tr_flush(&a->trig);

			/* Alert wrapper about controller disconnection */
			if(a->ops->disconnected) {
				a->ops->disconnected();
			}

			/* Signal the network that the connection is now down */
			em_net_not_connected(net);

			return 0;
		}

		sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/
	}

	/* All the jobs marked as to process again are moved to the official
	 * job queue.
	 */

/****** Start of the critical section *****************************************/
	sched_lock_ctx(sched);

	list_for_each_entry_safe(job, tmp, &sched->todo, next) {
		list_del(&job->next);
		list_add(&job->next, &sched->jobs);
	}

	sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/

	return 0;
}

/* Remove a well identified job from ANY queue of the scheduling context */
INTERNAL
int
em_sched_remove_job(unsigned int id, int type, struct sched_context * sched)
{
	int                found = 0;
	struct sched_job * job   = 0;
	struct sched_job * tmp   = 0;
#ifdef EBUG
	struct agent *     a     = container_of(sched, struct agent, sched);
#endif

	/* Dump the job from wherever it could be listed. */
/****** Start of the critical section *****************************************/
	sched_lock_ctx(sched);

	list_for_each_entry_safe(job, tmp, &sched->jobs, next) {
		if(job->id == id && job->type == type) {
			EMDBG(a, "Removing job to process %u, type %d\n",
				id, type);

			found = 1;
			list_del(&job->next);

			/* Free its resources */
			em_sched_release_job(job);

			/* There can be multiple jobs with the same id in case
			 * of cancellation events, so remove everything.
			 */
		}
	}

	/* Where is it? Already performed? */
	if(!found) {
		list_for_each_entry_safe(job, tmp, &sched->todo, next) {
			if(job->id == id && job->type == type) {
				EMDBG(a, "Removing performed job %u, type %d\n",
					id, type);

				found = 1;
				list_del(&job->next);

				/* Free its resources */
				em_sched_release_job(job);

				/* There can be multiple jobs with the same id
				 * in case of cancellation events, so remove
				 * everything.
				 */
			}
		}
	}

	sched_unlock_ctx(sched);
/****** End of the critical section *******************************************/

	if(!found) {
		return -1;
	}

	return 0;
}

/******************************************************************************
 * Scheduler procedures.                                                      *
 ******************************************************************************/

/* Loop executed by the scheduling context thread */
INTERNAL
void *
em_sched_loop(void * args)
{
	struct sched_context * s   = (struct sched_context *)args;
#ifdef EBUG
	struct agent *         a   = container_of(s, struct agent, sched);
#endif
	unsigned int           wi  = s->interval;
	struct timespec        wt  = {0};
	struct timespec        td  = {0};
	struct sched_job *     job = 0;
	struct sched_job *     tmp = 0;

	/* Convert the wait interval in a timespec struct. */
	while(wi >= 1000) {
		wi -= 1000;
		wt.tv_sec += 1;
	}
	wt.tv_nsec = wi * 1000000;

	EMDBG(a, "Scheduling loop starting, interval=%d ms\n", s->interval);

	while(!s->stop) {
		/* Job scheduling logic. */
		em_sched_consume(s);

		/* Relax the CPU. */
		nanosleep(&wt, &td);
	}

	EMDBG(a, "Dumping remaining jobs due shutdown\n");

/****** Start of the critical section *****************************************/
	sched_lock_ctx(s);

	/* Dump job to process again. */
	list_for_each_entry_safe(job, tmp, &s->todo, next) {
		EMDBG(a, "Removing processed job %u, type %d\n",
			job->id, job->type);

		list_del(&job->next);
		em_sched_release_job(job);
	}

	/* Free ANY remaining job still to process. */
	list_for_each_entry_safe(job, tmp, &s->jobs, next) {
		EMDBG(a, "Removing job to process %u, type %d\n",
			job->id, job->type);

		list_del(&job->next);
		em_sched_release_job(job);
	}

	sched_unlock_ctx(s);
/****** End of the critical section *******************************************/

	/*
	 * If execution arrives here, then a stop has been issued.
	 */

out:
	EMDBG(a, "Scheduling loop exiting...\n");

	return 0;
}

/* Start a scheduling context, initializing its variables and creating the
 * assigned thread.
 */
INTERNAL
int
em_sched_start(struct sched_context * sched)
{
#ifdef EBUG
	struct agent * a = container_of(sched, struct agent, sched);
#endif

	EMDBG(a, "Initializing scheduling context\n");

	sched->interval = 1000;

	INIT_LIST_HEAD(&sched->jobs);
	INIT_LIST_HEAD(&sched->todo);

	pthread_spin_init(&sched->lock, 0);

	/* Create the context where the agent scheduler will run on */
	if(pthread_create(&sched->thread, NULL, em_sched_loop, sched)) {
		return -1;
	}

	return 0;
}

/* Stops a scheduling context by issuing a signal to the relative thread */
INTERNAL
int
em_sched_stop(struct sched_context * sched)
{
#ifdef EBUG
	struct agent * a = container_of(sched, struct agent, sched);
#endif

	EMDBG(a, "Stopping scheduling context\n");

	/* Stop and wait for it... */
	sched->stop = 1;

	pthread_join(sched->thread, 0);
	pthread_spin_destroy(&sched->lock);

	return 0;
}
