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
#include <emlog.h>
#include <emage/emproto.h>

#include "agent.h"
#include "net.h"
#include "sched.h"

#include "emlist.h"
#include "sched.h"

#define NET_WAIT_TIME           300      /* 300ms in usec */

/******************************************************************************
 * Network procedures.                                                        *
 ******************************************************************************/

/* Common operations done when it successfully connects again. */
int net_connected(struct net_context * net) {
	struct agent * a = container_of(net, struct agent, net);
	struct sched_job * h = 0;

	EMDBG("Connected to controller %s:%d", net->addr, net->port);
	net->status = EM_STATUS_CONNECTED;

	h = malloc(sizeof(struct sched_job));

	if(!h) {
		EMLOG("No more memory!");
		return -1;
	}

	INIT_LIST_HEAD(&h->next);
	h->id         = 0;
	h->elapse     = 2000;
	h->type       = JOB_TYPE_HELLO;
	h->reschedule = -1;

	/* Add the Hello message. */
	sched_add_job(h, &a->sched);

	return 0;
}

unsigned int net_next_seq(struct net_context * net) {
	int ret = 0;

	pthread_spin_lock(&net->lock);
	ret = net->seq++;
	pthread_spin_unlock(&net->lock);

	return ret;
}

/* Turn the socket in an non-blocking one. */
int net_noblock_socket(int sockfd) {
	int flags = fcntl(sockfd, F_GETFL, 0);

	if(flags < 0) {
		return -1;
	}

	return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/* Apply the desired personalization to the socket. */
int net_nodelay_socket(int sockfd) {
	int flag = 1; /* Enable no delay... */
	int result = setsockopt(
		sockfd,
		SOL_TCP,
		TCP_NODELAY,
		(char *) &flag,
		sizeof(int));

	if (result < 0) {
		EMLOG("Could not personalize the socket!");
		perror("setsockopt");

		return -1;
	}

	return 0;
}

int net_not_connected(struct net_context * net) {
	EMDBG("No more connected with controller!");

	if(net->sockfd > 0) {
		close(net->sockfd);
		net->sockfd = -1;
	}

	net->status = EM_STATUS_NOT_CONNECTED;
	net->seq = 0;

	return 0;
}

/* Connect to the controller. Returns the open socket file descriptor if a
 * socket for the controller has been open, otherwise loop until a connection
 * has been established.
 *
 * Returns a negative number on error.
 */
int net_connect_to_controller(struct net_context * net) {
	int flags  = 0;
	int status = 0;

	struct sockaddr_in srvaddr = {0};
	struct hostent * ctrli = 0;

	if(net->sockfd < 0) {
		status = socket(AF_INET, SOCK_STREAM, 0);

		flags = fcntl(status, F_GETFL, 0);

		if(flags >= 0) {
			flags = flags | O_NONBLOCK;

			if(fcntl(status, F_SETFL, flags)) {
				EMLOG("Cannot mark socket as NONBLOCK!");
			}
		} else {
			EMLOG("Cannot mark socket as NONBLOCK!");
		}
	}

	if(status < 0) {
		EMLOG("Could not create the socket, error=%d", net->sockfd);
		perror("socket");

		return -1;
	}
	/* Socket has been created now. */
	else if (status > 0) {
		net->sockfd = status;
		net_nodelay_socket(net->sockfd);
	}

	EMDBG("Connecting to %s:%d...", net->addr, net->port);

	ctrli = gethostbyname(net->addr);

	if(!ctrli) {
		EMLOG("Could not resolve controller!");
		perror("gethostbyname");

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

		EMDBG("Error while connecting to %s, error=%d",
			net->addr,
			status);

		return -1;
	}

	return 0;
}

/* Receive data. */
int net_recv(struct net_context * context, char * buf, unsigned int size) {
	return recv(context->sockfd, buf, size, MSG_DONTWAIT | MSG_NOSIGNAL);
}

/* Send data. */
int net_send(struct net_context * context, char * buf, unsigned int size) {
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
int net_sched_job(
	struct agent * a,
	unsigned int id,
	int type,
	int interval,
	int res,
	void * args,
	unsigned int size) {

	struct sched_job * job = malloc(sizeof(struct sched_job));

	if(!job) {
		EMLOG("Not enough memory!");
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
			EMLOG("Not enough memory!");
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

	sched_add_job(job, &a->sched);

	return 0;
}

/******************************************************************************
 * Message specific procedures.                                               *
 ******************************************************************************/

int net_sc_hello(struct net_context * net, char * msg, int size)
{
	struct sched_job * j;
	struct agent *     a = container_of(net, struct agent, net);
	uint32_t           intv;

	EMDBG("Schedule message Hello");

	/* Find the Hello job and change its interval */
	j = sched_find_job(&a->sched, 0, JOB_TYPE_HELLO);

	if(j) {
		intv      = epp_sched_interval(msg, size);
		j->elapse = intv;
	}

	return 0;
}

int net_se_cell_setup(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG("Single message cell setup");

	return net_sched_job(a, seq, JOB_TYPE_CELL_SETUP, 1, 0, msg, size);
}

int net_se_enb_setup(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG("Single message eNB setup");

	return net_sched_job(a, seq, JOB_TYPE_ENB_SETUP, 1, 0, msg, size);
}

int net_se_ho(struct net_context * net, char * msg, int size)
{
	uint32_t       seq;
	struct agent * a = container_of(net, struct agent, net);

	seq = epp_seq(msg, size);

	EMDBG("Single message Handover");

	return net_sched_job(a, seq, JOB_TYPE_HO, 1, 0, msg, size);
}

/* RAN setup */
int net_se_rans(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG("Single message RAN setup");

        return net_sched_job(a, seq, JOB_TYPE_RAN_SETUP, 1, 0, msg, size);
}

/* RAN tenant */
int net_se_rant(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG("Single message RAN tenant");

        return net_sched_job(a, seq, JOB_TYPE_RAN_TENANT, 1, 0, msg, size);
}

/* RAN user */
int net_se_ranu(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG("Single message RAN user");

        return net_sched_job(a, seq, JOB_TYPE_RAN_USER, 1, 0, msg, size);
}

/* RAN scheduler */
int net_se_ranc(struct net_context * net, char * msg, int size)
{
        uint32_t       seq;
        struct agent * a = container_of(net, struct agent, net);

        seq = epp_seq(msg, size);

        EMDBG("Single message RAN scheduler");

        return net_sched_job(a, seq, JOB_TYPE_RAN_SCHEDULER, 1, 0, msg, size);
}

int net_te_ue_measure(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;
	uint8_t          m_id = 0;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	epp_trigger_uemeas_req(msg, size, &m_id, 0, 0, 0, 0, 0);

	EMDBG("Trigger message UE measure, mod=%d, op=%d", mod, op);

	if(op == EP_OPERATION_ADD) {
		t = tr_add(
			&a->trig,
			tr_next_id(&a->trig),
			mod,
			TR_TYPE_UE_MEAS,
			(int)m_id,
			msg,
			size);
	} else {
		return tr_del(&a->trig, mod, TR_TYPE_UE_MEAS, (int)m_id);
	}

	return net_sched_job(
		a, seq, JOB_TYPE_UE_MEASURE, 1, 0, t, sizeof(struct trigger));
}

int net_te_ue_report(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	EMDBG("Trigger message UE report, mod=%d, op=%d", mod, op);

	if(op == EP_OPERATION_ADD) {
		t = tr_add(
			&a->trig,
			tr_next_id(&a->trig),
			mod,
			TR_TYPE_UE_REP,
			0,
			msg,
			size);
	} else {
		return tr_del(&a->trig, mod, TR_TYPE_UE_REP, 0);
	}

	return net_sched_job(
		a, seq, JOB_TYPE_UE_REPORT, 1, 0, t, sizeof(struct trigger));
}

int net_te_mac_report(struct net_context * net, char * msg, int size)
{
	uint32_t         mod;
	uint32_t         seq;
	uint32_t         op;

	struct trigger * t;
	struct agent *   a = container_of(net, struct agent, net);

	epp_head(msg, size, 0, 0, 0, &mod);

	seq = epp_seq(msg, size);
	op  = epp_trigger_op(msg, size);

	EMDBG("Trigger message MAC report, mod=%d, op=%d", mod, op);

	if(op == EP_OPERATION_ADD) {
		t = tr_add(
			&a->trig,
			tr_next_id(&a->trig),
			mod,
			TR_TYPE_MAC_REP,
			0,
			msg,
			size);
	} else {
		return tr_del(&a->trig, mod, TR_TYPE_MAC_REP, 0);
	}

	return net_sched_job(
		a, seq, JOB_TYPE_MAC_REPORT, 1, 0, t, sizeof(struct trigger));
}

/******************************************************************************
 * Top-level message handlers.                                                *
 ******************************************************************************/

int net_process_sched_event(
	struct net_context * net, char * msg, unsigned int size)
{
	ep_act_type s = epp_schedule_type(msg, size);

	if(s == EP_ACT_INVALID) {
		EMDBG("Malformed schedule-event message received!\n");
		return -1;
	}

	switch(s) {
	case EP_ACT_HELLO:
		if(epp_schedule_dir(msg, size) == EP_DIR_REPLY) {
			EMDBG("Hello reply received!");
			return net_sc_hello(net, msg, size);
		}
		break;
	default:
		EMDBG("Unknown scheduled event, type=%d", s);
		break;
	}

	return 0;
}

int net_process_single_event(
	struct net_context * net, char * msg, unsigned int size)
{
	ep_act_type s = epp_single_type(msg, size);

	if(s == EP_ACT_INVALID) {
		EMDBG("Malformed single-event message received!\n");
		return -1;
	}

	switch(s) {
	case EP_ACT_HELLO:
		/* Do nothing */
		break;
	case EP_ACT_ECAP:
		if(epp_single_dir(msg, size) == EP_DIR_REQUEST) {
			EMDBG("eNB capabilities request received!");
			return net_se_enb_setup(net, msg, size);
		}
		break;
	case EP_ACT_CCAP:
		if(epp_single_dir(msg, size) == EP_DIR_REQUEST) {
			EMDBG("Cell capabilities request received!");
			return net_se_cell_setup(net, msg, size);
		}
		break;
	case EP_ACT_HANDOVER:
		if(epp_single_dir(msg, size) == EP_DIR_REQUEST) {
			EMDBG("Handover request received!");
			return net_se_ho(net, msg, size);
		}
		break;
        case EP_ACT_RAN_SETUP:
                if (epp_single_dir(msg, size) == EP_DIR_REQUEST) {
                        EMDBG("RAN setup request received!");
                        return net_se_rans(net, msg, size);
                }
                break;
        case EP_ACT_RAN_TENANT:
                if (epp_single_dir(msg, size) == EP_DIR_REQUEST) {
                        EMDBG("RAN Tenants request received!");
                        return net_se_rant(net, msg, size);
                }
                break;
        case EP_ACT_RAN_USER:
                if (epp_single_dir(msg, size) == EP_DIR_REQUEST) {
                        EMDBG("RAN Users request received!");
                        return net_se_ranu(net, msg, size);
                }
                break;
        case EP_ACT_RAN_SCHED:
                if (epp_single_dir(msg, size) == EP_DIR_REQUEST) {
                        EMDBG("RAN Schedulers request received!");
                        return net_se_ranc(net, msg, size);
                }
                break;
	default:
		EMDBG("Unknown single event, type=%d", s);
		break;
	}

	return 0;
}

int net_process_trigger_event(
	struct net_context * net, char * msg, unsigned int size)
{
	ep_act_type t = epp_trigger_type(msg, size);

	if(t == EP_ACT_INVALID) {
		EMDBG("Malformed trigger-event message received!\n");
		return -1;
	}

	switch(t) {
	case EP_ACT_HELLO:
		/* Don't really care about the hello reply now */
		break;
	case EP_ACT_UE_REPORT:
		return net_te_ue_report(net, msg, size);
	case EP_ACT_UE_MEASURE:
		return net_te_ue_measure(net, msg, size);
	case EP_ACT_MAC_REPORT:
		return net_te_mac_report(net, msg, size);
	default:
		EMDBG("Unknown trigger event, type=%d", t);
		break;
	}

	return 0;
}

/* Process incoming messages. */
int net_process_message(struct net_context * net, char * msg, unsigned int size)
{
	ep_msg_type mt = epp_msg_type(msg, size);

	switch(mt) {
	/* Single events messages. */
	case EP_TYPE_SINGLE_MSG:
		return net_process_single_event(net, msg, size);
	/* Scheduled events messages. */
	case EP_TYPE_SCHEDULE_MSG:
		return net_process_sched_event(net, msg, size);
	/* Triggered events messages. */
	case EP_TYPE_TRIGGER_MSG:
		return net_process_trigger_event(net, msg, size);
	default:
		EMDBG("Unknown message received, size=%d", size);
		break;
	}

	return 0;
}

/******************************************************************************
 * Network listener logic.                                                    *
 ******************************************************************************/

void * net_loop(void * args)
{
	struct net_context * net = (struct net_context *)args;

	int op;
	int bread;
	int mlen  = 0;

	char buf[EM_BUF_SIZE] = {0};

	unsigned int wi = net->interval;
	struct timespec wt = {0};	/* Wait time. */
	struct timespec wc = {0};	/* Wait time for reconnection. */
	struct timespec td = {0};

	/* Convert the wait interval in a timespec struct. */
	while(wi >= 1000) {
		wi -= 1000;
		wt.tv_sec += 1;
	}
	wt.tv_nsec = wi * 1000000;

	/* At least 1 second between re-connection attempts */
	wc.tv_sec  = 1 + wt.tv_sec;
	wc.tv_nsec = wt.tv_nsec;

	while(1) {
next:
		if(net->status == EM_STATUS_NOT_CONNECTED) {
			if(net->stop) {
				goto stop;
			}

			if(net_connect_to_controller(net) == 0) {
				net_connected(net);
			}

			/* Relax the CPU. */
			nanosleep(&wc, &td);
			continue;
		}

		bread = 0;

		/* Continue until EP_HEADER_SIZE bytes have been collected */
		while(bread < EP_HEADER_SIZE) {
			if(net->stop) {
				goto stop;
			}

			op = net_recv(
				net, buf + bread, EP_HEADER_SIZE - bread);

			if(op <= 0) {
				if(errno == EAGAIN) {
					/* Relax the CPU. */
					nanosleep(&wt, &td);
					continue;
				}

				net_not_connected(net);
				goto next;
			}

			bread += op;
		}

		if(bread != EP_HEADER_SIZE) {
			EMDBG("Read %d bytes, but only %ld to process!",
				bread, EP_HEADER_SIZE);

			net_not_connected(net);
			goto next;
		}

		mlen = epp_msg_length(buf, bread);

		EMDBG("Receiving a message of size %d", mlen);

		//bread = 0;

		/* Continue until the entire message has been collected */
		while(bread < mlen) {
			if(net->stop) {
				goto stop;
			}

			op = net_recv(net, buf + bread, mlen - bread);

			if(op <= 0) {
				if(errno == EAGAIN) {
					/* Relax the CPU. */
					nanosleep(&wt, &td);
					continue;
				}

				net_not_connected(net);
				goto next;
			}

			bread += op;
		}

		if(bread != mlen) {
			EMDBG("Read %d bytes, but only %d to process!",
				bread, mlen);

			net_not_connected(net);
			goto next;
		}

		/* Finally we collected the entire message; process it! */
		net_process_message(net, buf, bread);
	}

stop:
	EMDBG("Listening loop is terminating...");

	/*
	 * If you need to release 'net' specific resources, do it here!
	 */

	return 0;
}

int net_start(struct net_context * net)
{
	net->interval = NET_WAIT_TIME;
	net->sockfd   = -1;

	pthread_spin_init(&net->lock, 0);

	/* Create the context where the agent scheduler will run on. */
	if(pthread_create(
		(pthread_t *)&net->thread, NULL, net_loop, net)) {

		EMLOG("Failed to create the listener agent thread.");
		return -1;
	}

	return 0;
}

int net_stop(struct net_context * net)
{
	/* Stop and wait for it... */
	net->stop = 1;
	pthread_join(net->thread, 0);

	pthread_spin_destroy(&net->lock);

	return 0;
}
