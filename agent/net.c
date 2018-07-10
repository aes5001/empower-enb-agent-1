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
 * Empower Agent internal network listener logic.
 */

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <emage.h>
#include <emage/emproto.h>

#include "agent.h"

#define NET_WAIT_TIME           300      /* 300ms in usec */

/******************************************************************************
 * Network procedures.                                                        *
 ******************************************************************************/

/* Common operations done when it successfully connects again */
INTERNAL
int
em_net_connected(struct net_context * net)
{
	struct agent *     a = container_of(net, struct agent, net);
	struct sched_job * h = 0;

	EMDBG(a, "Connected to controller %s:%d\n", net->addr, net->port);

	net->status = EM_STATUS_CONNECTED;

	h = malloc(sizeof(struct sched_job));

	if(!h) {
		//EMLOG("No more memory!");
		return -1;
	}

	INIT_LIST_HEAD(&h->next);
	h->id         = 0;
	h->elapse     = 2000;
	h->type       = JOB_TYPE_HELLO;
	h->reschedule = -1;

	/* Schedule the Hello task, which sends hello messages at a well defined
	 * time interval.
	 */
	em_sched_add_job(h, &a->sched);

	return 0;
}

/* Select the next sequence number relative to a network context */
INTERNAL
unsigned int
em_net_next_seq(struct net_context * net)
{
	int ret = 0;

	pthread_spin_lock(&net->lock);
	ret = net->seq++;
	pthread_spin_unlock(&net->lock);

	return ret;
}

/* Turn the socket in an non-blocking one */
INTERNAL
int
em_net_noblock_socket(int sockfd)
{
	int flags = fcntl(sockfd, F_GETFL, 0);

	if(flags < 0) {
		return -1;
	}

	return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/* Set the socket to immediately send the data and do not accumulate it in big
 * chunks.
 */
INTERNAL
int
em_net_nodelay_socket(int sockfd)
{
	int flag = 1; /* Enable no delay... */

	int result = setsockopt(
		sockfd,
		SOL_TCP,
		TCP_NODELAY,
		(char *) &flag,
		sizeof(int));

	if (result < 0) {
		return -1;
	}

	return 0;
}

/* Perform disconnection operation to reset part of the network context */
INTERNAL
int
em_net_not_connected(struct net_context * net)
{
	if(net->sockfd > 0) {
		close(net->sockfd);
		net->sockfd = -1;
	}

	net->status = EM_STATUS_NOT_CONNECTED;
	net->seq    = 0;

	return 0;
}

/* Connect to the controller. Returns the open socket file descriptor if a
 * socket for the controller has been open, otherwise loop until a connection
 * has been established.
 *
 * Returns a negative number on error.
 */
INTERNAL
int
em_net_connect_to_controller(struct net_context * net)
{
	struct agent *     a       = container_of(net, struct agent, net);
	int                flags   = 0;
	int                status  = 0;
	struct sockaddr_in srvaddr = {0};
	struct hostent *   ctrli   = 0;

	if(net->sockfd < 0) {
		net->sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if(net->sockfd) {
			em_net_noblock_socket(net->sockfd);
			em_net_nodelay_socket(net->sockfd);
		} else {
			EMLOG(a, "ERROR: Can't create a socket, %d\n",
				net->sockfd);

			return -1;
		}
	}
#if 0
	if(status < 0) {
		//EMLOG("Could not create the socket, error=%d", net->sockfd);
		perror("socket");

		return -1;
	}
	/* Socket has been created now. */
	else if (status > 0) {
		net->sockfd = status;
		em_net_nodelay_socket(net->sockfd);
	}
#endif

	ctrli = gethostbyname(net->addr);

	if(!ctrli) {
		EMLOG(a, "ERROR: Resolve controller address %.16s\n",
			net->addr);

		return -1;
	}

	srvaddr.sin_family = AF_INET;
	memcpy(
		&srvaddr.sin_addr.s_addr,
		ctrli->h_addr,
		ctrli->h_length);
	srvaddr.sin_port = htons(net->port);

again:
	if(net->stop) {
		return -1;
	}

	status = connect(
		net->sockfd,
		(struct sockaddr *)&srvaddr,
		sizeof(struct sockaddr));

	if(status < 0) {
		/* Since it's a non-blocking call, in case the connection is
		 * in progress we just try again */
		if(errno == EALREADY) {
			usleep(1000000);
			goto again;
		}

		EMDBG(a, "Error while connecting to %.16s, error=%d\n",
			net->addr,
			status);

		return -1;
	}

	return 0;
}

/* Receive data. */
INTERNAL
int
em_net_recv(struct net_context * context, char * buf, unsigned int size)
{
	return recv(context->sockfd, buf, size, MSG_DONTWAIT | MSG_NOSIGNAL);
}

/* Send data. */
INTERNAL
int
em_net_send(struct net_context * context, char * buf, unsigned int size)
{
	/* NOTE:
	 * Since sending on a dead socket can cause a signal to be issued to the
	 * application (SIGPIPE), we don't want that the host get disturbed by
	 * this, and so we ask not to notify the error.
	 */
	return send(context->sockfd, buf, size, MSG_DONTWAIT | MSG_NOSIGNAL);
}

/* Schedule a generic job into the agent scheduler.
 *
 * NOTE: 
 *	Depending on the size argument, different strategies are taken; if this
 *	value is 0, then args pointer is copied into the job (reference). If 
 *	size is different than 0 (unsigned force to positive values only), then
 *	the 'args' parameter is coped into the job arguments field (using size 
 *	to know the amount of new allocation).
 */
INTERNAL
int
em_net_sched_job(
	struct agent * a,
	unsigned int   id,
	int            type,
	int            interval,
	int            res,
	void *         args,
	unsigned int   size)
{
	struct sched_job * job = malloc(sizeof(struct sched_job));

	if(!job) {
		EMLOG(a, "ERROR: Not enough memory to create new job\n");
		return -1;
	}

	memset(job, 0, sizeof(struct sched_job));

	/* Depending on the size you decide if the given arguments are passed 
	 * by reference of by copy.
	 */
	if(size > 0) {
		job->args = malloc(sizeof(char) * size);

		if(!job->args) {
			free(job);
			EMLOG(a, "ERROR: Not enough memory for new buffer\n");
			return -1;
		}

		memcpy(job->args, args, sizeof(char) * size);
	} 
	/* Size equals to zero perform pointer copy only */
	else {
		job->args = args;
	}

	INIT_LIST_HEAD(&job->next);
	job->type       = type;
	job->size       = size;
	job->id         = id;
	job->elapse     = interval;
	job->reschedule = res;

	EMDBG(a, "Network scheduling new job type %d\n", type);

	em_sched_add_job(job, &a->sched);

	return 0;
}

/******************************************************************************
 * Message specific procedures.                                               *
 ******************************************************************************/

/* Handle a scheduled event Hello message */
INTERNAL
int
em_net_sc_hello(struct net_context * net, char * msg, int size)
{
	struct sched_job * j;
	struct agent *     a = container_of(net, struct agent, net);
	uint32_t           intv;

	EMDBG(a, "Network processing Hello\n");

	/* Find the Hello job and change its interval.
	 *
	 * WARNING:
	 * We are handling a reference here, and there could be problem is the
	 * job is removed from the list. Luckily here Hello is always maintained
	 * into the queue, but this can be false for other type of messages.
	 */
	j = em_sched_find_job(&a->sched, 0, JOB_TYPE_HELLO);

	if(j) {
		intv      = epp_sched_interval(msg, size);
		j->elapse = intv;
	}

	return 0;
}

/* Handle a single event Cell capabilities message */
INTERNAL
int
em_net_se_cell_setup(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG(a, "Network processing Cell Capabilities, seq=%u\n", seq);

	return em_net_sched_job(a, seq, JOB_TYPE_CELL_SETUP, 1, 0, msg, size);
}

/* Handle a single event eNB capabilities message */
INTERNAL
int
em_net_se_enb_setup(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG(a, "Network processing eNB Capabilities, seq=%u\n", seq);

	return em_net_sched_job(a, seq, JOB_TYPE_ENB_SETUP, 1, 0, msg, size);
}

/* handle a single event Handover message */
INTERNAL
int
em_net_se_ho(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG(a, "Network processing Handover, seq=%u\n", seq);

	return em_net_sched_job(a, seq, JOB_TYPE_HO, 1, 0, msg, size);
}

/* Handle a single event RAN Setup message */
INTERNAL
int
em_net_se_rans(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG(a, "Network processing RAN Setup, seq=%u\n", seq);

        return em_net_sched_job(a, seq, JOB_TYPE_RAN_SETUP, 1, 0, msg, size);
}

/* Handle a single event RAN Tenant message */
INTERNAL
int
em_net_se_rant(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG(a, "Network processing RAN Tenant, seq=%u\n", seq);

        return em_net_sched_job(a, seq, JOB_TYPE_RAN_TENANT, 1, 0, msg, size);
}

/* Handle a single event RAN User message */
INTERNAL
int
em_net_se_ranu(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG(a, "Network processing RAN User, seq=%u\n", seq);

        return em_net_sched_job(a, seq, JOB_TYPE_RAN_USER, 1, 0, msg, size);
}

/* Handle a single event RAN Scheduler */
INTERNAL
int
em_net_se_ranc(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG(a, "Network processing RAN Scheduler, seq=%u\n", seq);

        return em_net_sched_job(a, seq, JOB_TYPE_RAN_SCHEDULER, 1, 0, msg, size);
}

/* Handle a trigger event RAN Measurement message */
INTERNAL
int
em_net_te_ue_measure(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;
	uint8_t          m_id = 0;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod, 0);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	epp_trigger_uemeas_req(msg, size, &m_id, 0, 0, 0, 0, 0);

	EMDBG(a, "Network processing UE Measurement, seq=%u, meas=%u, mod=%u\n",
		seq, m_id, mod);

	if(op == EP_OPERATION_ADD) {
		t = em_tr_add(
			&a->trig,
			em_tr_next_id(&a->trig),
			mod,
			TR_TYPE_UE_MEAS,
			(int)m_id,
			msg,
			size);
	} else {
		return em_tr_del(&a->trig, mod, TR_TYPE_UE_MEAS, (int)m_id);
	}

	return em_net_sched_job(
		a, seq, JOB_TYPE_UE_MEASURE, 1, 0, t, sizeof(struct trigger));
}

/* Handle a trigger event UE Report message */
INTERNAL
int
em_net_te_ue_report(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod, 0);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	EMDBG(a, "Network processing UE Report, seq=%u, mod=%u\n", seq, mod);

	if(op == EP_OPERATION_ADD) {
		t = em_tr_add(
			&a->trig,
			em_tr_next_id(&a->trig),
			mod,
			TR_TYPE_UE_REP,
			0,
			msg,
			size);
	} else {
		return em_tr_del(&a->trig, mod, TR_TYPE_UE_REP, 0);
	}

	return em_net_sched_job(
		a, seq, JOB_TYPE_UE_REPORT, 1, 0, t, sizeof(struct trigger));
}

/* Handle a trigger event MAC report message */
INTERNAL
int
em_net_te_mac_report(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod, 0);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	EMDBG(a, "Network processing MAC Report, seq=%u, mod=%u\n", seq, mod);

	if(op == EP_OPERATION_ADD) {
		t = em_tr_add(
			&a->trig,
			em_tr_next_id(&a->trig),
			mod,
			TR_TYPE_MAC_REP,
			0,
			msg,
			size);
	} else {
		return em_tr_del(&a->trig, mod, TR_TYPE_MAC_REP, 0);
	}

	return em_net_sched_job(
		a, seq, JOB_TYPE_MAC_REPORT, 1, 0, t, sizeof(struct trigger));
}

/******************************************************************************
 * Top-level message handlers.                                                *
 ******************************************************************************/

/* Handle a generic Schedule Event message */
INTERNAL
int
em_net_process_sched_event(
	struct net_context * net, char * msg, unsigned int size)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif
	ep_act_type s = epp_schedule_type(msg, size);

	if(s == EP_ACT_INVALID) {
		EMDBG(a, "Malformed schedule-event message received!\n");
		return -1;
	}

	switch(s) {
	case EP_ACT_HELLO:
		if(epp_dir(msg, size) == EP_HDR_FLAG_DIR_REP) {
			return em_net_sc_hello(net, msg, size);
		}
		break;
	default:
		EMDBG(a, "Unknown schedule-event message received, type=%d\n",
			s);
		break;
	}

	return 0;
}

/* Handle a generic Single Event message */
INTERNAL
int
em_net_process_single_event(
	struct net_context * net, char * msg, unsigned int size)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif
	ep_act_type s = epp_single_type(msg, size);

	if(s == EP_ACT_INVALID) {
		EMDBG(a, "Malformed single-event message received!\n");
		return -1;
	}

	switch(s) {
	case EP_ACT_HELLO:
		/* Do nothing */
		break;
	case EP_ACT_ECAP:
		if(epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
			return em_net_se_enb_setup(net, msg, size);
		}
		break;
	case EP_ACT_CCAP:
		if(epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
			return em_net_se_cell_setup(net, msg, size);
		}
		break;
	case EP_ACT_HANDOVER:
		if(epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
			return em_net_se_ho(net, msg, size);
		}
		break;
        case EP_ACT_RAN_SETUP:
                if (epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
                        return em_net_se_rans(net, msg, size);
                }
                break;
        case EP_ACT_RAN_TENANT:
                if (epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
                        return em_net_se_rant(net, msg, size);
                }
                break;
        case EP_ACT_RAN_USER:
                if (epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
                        return em_net_se_ranu(net, msg, size);
                }
                break;
        case EP_ACT_RAN_SCHED:
                if (epp_dir(msg, size) == EP_HDR_FLAG_DIR_REQ) {
                        return em_net_se_ranc(net, msg, size);
                }
                break;
	default:
		EMDBG(a, "Unknown single-event message received, type=%d\n",
			s);
		break;
	}

	return 0;
}

/* Handle a generic trigger-event message */
INTERNAL
int
em_net_process_trigger_event(
	struct net_context * net, char * msg, unsigned int size)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif
	ep_act_type t = epp_trigger_type(msg, size);

	if(t == EP_ACT_INVALID) {
		EMDBG(a, "Malformed trigger-event message received!\n");
		return -1;
	}

	switch(t) {
	case EP_ACT_UE_REPORT:
		return em_net_te_ue_report(net, msg, size);
	case EP_ACT_UE_MEASURE:
		return em_net_te_ue_measure(net, msg, size);
	case EP_ACT_MAC_REPORT:
		return em_net_te_mac_report(net, msg, size);
	default:
		EMDBG(a, "Unknown trigger-event message received, type=%d\n",
			t);
		break;
	}

	return 0;
}

/* Process incoming messages. */
INTERNAL
int
em_net_process_message(struct net_context * net, char * msg, unsigned int size)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif
	ep_msg_type mt = epp_msg_type(msg, size);

	switch(mt) {
	/* Single events messages. */
	case EP_TYPE_SINGLE_MSG:
		return em_net_process_single_event(net, msg, size);
	/* Scheduled events messages. */
	case EP_TYPE_SCHEDULE_MSG:
		return em_net_process_sched_event(net, msg, size);
	/* Triggered events messages. */
	case EP_TYPE_TRIGGER_MSG:
		return em_net_process_trigger_event(net, msg, size);
	default:
		EMDBG(a, "Unknown message received, type=%d\n", mt);
		break;
	}

	return 0;
}

/******************************************************************************
 * Network listener logic.                                                    *
 ******************************************************************************/

/* Loop executed by the network context. When started the net_context thread
 * will be running this piece of code.
 */
INTERNAL
void *
em_net_loop(void * args)
{
	struct net_context * net = (struct net_context *)args;
#ifdef EBUG
	struct agent *       a = container_of(net, struct agent, net);
#endif
	int                  op;
	int                  bread;
	int                  mlen  = 0;
	unsigned int         wi = net->interval;
	struct timespec      wt = {0};	/* Wait time. */
	struct timespec      wc = {0};	/* Wait time for reconnection. */
	struct timespec      td = {0};

	/* Convert the wait interval in a timespec struct. */
	while(wi >= 1000) {
		wi -= 1000;
		wt.tv_sec += 1;
	}
	wt.tv_nsec = wi * 1000000;

	/* At least 1 second between re-connection attempts */
	wc.tv_sec  = 1 + wt.tv_sec;
	wc.tv_nsec = wt.tv_nsec;

	EMDBG(a, "Network loop starting, interval=%d ms\n", net->interval);

	while(1) {
next:
		if(net->status == EM_STATUS_NOT_CONNECTED) {
			if(net->stop) {
				goto stop;
			}

			if(em_net_connect_to_controller(net)) {
				/* Relax the CPU and retry connection */
				nanosleep(&wc, &td);
				continue;
			}

			em_net_connected(net);
		}

		bread = 0;

		/* Continue until EP_HEADER_SIZE bytes have been collected */
		while(bread < EP_HEADER_SIZE) {
			if(net->stop) {
				goto stop;
			}

			op = em_net_recv(
				net, net->buf + bread, EP_HEADER_SIZE - bread);

			if(op <= 0) {
				if(errno == EAGAIN) {
					/* Relax the CPU. */
					nanosleep(&wt, &td);
					continue;
				}

				em_net_not_connected(net);
				goto next;
			}

			bread += op;
		}

		if(bread != EP_HEADER_SIZE) {
			EMDBG(a, "Read %d bytes, but %ld to process!\n",
				bread, EP_HEADER_SIZE);

			em_net_not_connected(net);
			continue;
		}

		mlen = epp_msg_length(net->buf, bread);

		EMDBG(a, "Collecting a message of size %d\n", mlen);

		//bread = 0;

		/* Continue until the entire message has been collected */
		while(bread < mlen) {
			if(net->stop) {
				goto stop;
			}

			op = em_net_recv(net, net->buf + bread, mlen - bread);

			if(op <= 0) {
				if(errno == EAGAIN) {
					/* Relax the CPU. */
					nanosleep(&wt, &td);
					continue;
				}

				em_net_not_connected(net);
				goto next;
				continue;
			}

			bread += op;
		}

		if(bread != mlen) {
			EMDBG(a, "Read %d bytes out of %d\n",
				bread, mlen);

			em_net_not_connected(net);
			//goto next;
			continue;
		}

		/* Finally we collected the entire message; process it! */
		em_net_process_message(net, net->buf, bread);
	}

stop:
	EMDBG(a, "Network loop exiting...\n");

	/*
	 * If you need to release 'net' specific resources, do it here!
	 */

	return 0;
}

/* Start a network context in its own thread context */
INTERNAL
int
em_net_start(struct net_context * net)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif

	EMDBG(a, "Initializing networking context\n");

	net->interval = NET_WAIT_TIME;
	net->sockfd   = -1;

	pthread_spin_init(&net->lock, 0);

	/* Create the context where the agent scheduler will run on. */
	if(pthread_create(
		(pthread_t *)&net->thread, NULL, em_net_loop, net))
	{
		return -1;
	}

	return 0;
}

/* Stop a network context by terminating its thread */
INTERNAL
int
em_net_stop(struct net_context * net)
{
#ifdef EBUG
	struct agent * a = container_of(net, struct agent, net);
#endif

	EMDBG(a, "Stopping networking context\n");

	/* Stop and wait for it... */
	net->stop = 1;
	pthread_join(net->thread, 0);

	pthread_spin_destroy(&net->lock);

	return 0;
}
