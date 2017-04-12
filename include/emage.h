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
 * Empower Agent.
 */

#ifndef __EMAGE_H
#define __EMAGE_H

/* Emage message generated by protocol buffers. */
typedef struct _EmageMsg EmageMsg;

/* Possible triggers which can be installed in the agent. */
enum EM_TRIGGER_TYPE {
	EM_NONE_TRIGGER = 0,
	/* UE state transaction. */
	EM_UEs_ID_REPORT_TRIGGER,
	/* RRC measurements trigger. */
	EM_RRC_MEAS_TRIGGER,
	/* RRC measurements configuration trigger. */
	EM_RRC_MEAS_CONF_TRIGGER,
	/* Cell statistics trigger. */
	EM_CELL_STATS_TRIGGER,
};

/* Defines the operations that can be customized depending on the technology
 * where you want to embed the agent to. Such procedures will be called by the
 * agent main logic while responding to the controller orders of event triggered
 * by the local system.
 */
struct em_agent_ops {
	/* Perform custom initialization for the technology abstraction layer.
	 *
	 * Reporting an error during initialization stages cause the agent to
	 * fail.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* init) (void);

	/* Perform custom initialization for the technology abstraction layer.
	 * Regardless of error returns codes, the agent will be stopped.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* release) (void);

	/*
	 * Generic stuff.
	 */

	/* The controller informs this base station that an UE hand-over must be
	 * done. The request message contains the information about the targets
	 * of such operations.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* handover_request) (
			EmageMsg * request, EmageMsg ** reply);

	/* Informs the stack that a log for UE activity has been required by the
	 * controller. The wrap decide what kind of activity needs to be logged,
	 * now. The id given has to be used to check for its existence later.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* UEs_ID_report) (
		EmageMsg * request, EmageMsg ** reply, unsigned int trigger_id);

	/*
	 * RRC stuff.
	 */

	/* Informs the stack that a RRC measurement request has been issued by
	 * the controller for this base station.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* RRC_measurements) (
		EmageMsg * request, EmageMsg ** reply, unsigned int trigger_id);

	/* Informs the stack that a RRC measurement configuration request has
	 * been issued by the controller for this base station.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* RRC_meas_conf) (
		EmageMsg * request, EmageMsg ** reply, unsigned int trigger_id);

	/*
	 * Cell-specific stuff.
	 */

	/* Informs that the controller issued a request to report the actual
	 * cell statistics. Negative trigger id identifies such operation as
	 * once-only or agent scheduled.
	 *
	 * Returns 0 on success, a negative error code otherwise.
	 */
	int (* cell_statistics_report) (
		EmageMsg * request, EmageMsg ** reply, unsigned int trigger_id);


	/* Informs that the controller required to report about some kind of
	 * information regarding the eNB cells.
	 *
	 * Return 0 on success, a negative error code otherwise.
	 */
	int (* eNB_cells_report) (EmageMsg * request, EmageMsg ** reply);
};

/* Peek the triggers of the given agent and check if a trigger is enabled or
 * not. This is useful to avoid doing some heavy operation and just being denied
 * at the end.
 *
 * Returns 1 if the trigger is enabled, 0 otherwise.
 */
int em_has_trigger(int enb_id, int tid, int ttype);

/* Send a message to the connected controller, if any controller is attached.
 * This operations is only possible if the agent for that particular id has
 * already been created.
 *
 * Returns 0 if the message is successfully sent, a negative error code
 * otherwise.
 */
int em_send(int enb_id, EmageMsg * msg);

/* Start the Empower Agent logic. This will cause the agent to start interacting
 * with a remote controller or to local events. You need to pass the technology
 * dependant callbacks and the base station identifier.
 *
 * Information about controller address and characteristics are taken by the
 * configuration file which must be present in your machine.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int em_start(struct em_agent_ops * ops, int enb_id);

/* Stop the Empower Agent logic. This will cause the agent to stop to all the
 * controller commands and local events.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int em_stop(void);

/* Terminate a single agent instance using it's id.
 *
 * Always returns 0.
 */
int em_terminate_agent(int b_id);

#endif
