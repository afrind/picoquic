/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "picoquic_bbr.h"
#include "qlog.h"
#include "h3zero_common.h"

/* Flow control test:
* 
* Simulate a data receiver that can only process data slowly, and must
* buffer whatever excess data is delivered. The test verifies that the
* amount of data that the application must queue does not exceed a
* preset limit, and fails the connection if it does.
*/
#define FCTEST_TEST_ALPN "fctest"

typedef struct st_fctest_spec_t {
	uint8_t test_id;
	picoquic_congestion_algorithm_t* ccalgo;
	uint64_t loss_mask;
	uint64_t transfer_size;
	uint64_t microsecs_per_byte;
	uint64_t credit_quantum;
	uint64_t initial_credit;
	uint64_t bytes_buffered_max;
	uint64_t completion_target;
} fctest_spec_t;

typedef struct st_fctest_ctx_t {
	uint64_t transfer_size;
	uint64_t microsecs_per_byte;
	uint64_t credit_quantum;

	uint64_t simulated_time;
	uint64_t loss_mask;
	uint64_t stream_id;
	uint64_t bytes_sent;

	uint64_t bytes_received;
	uint64_t bytes_buffered;
	uint64_t buffered_time;
	uint64_t microsec_rounding_error;

	uint64_t credits_pending;

	uint64_t bytes_buffered_max;

	int is_started;
	int fin_sent;
	int fin_received;
	int is_closed;
	int error_detected;
} fctest_ctx_t;

void fctest_ctx_init(fctest_ctx_t* fctest_ctx, fctest_spec_t* spec)
{
	memset(fctest_ctx, 0, sizeof(fctest_ctx_t));
	fctest_ctx->transfer_size = spec->transfer_size;
	fctest_ctx->microsecs_per_byte = spec->microsecs_per_byte;
	fctest_ctx->credit_quantum = spec->credit_quantum;
	fctest_ctx->loss_mask = spec->loss_mask;
}

int fctest_start_stream(fctest_ctx_t* fctest_ctx, picoquic_cnx_t* cnx)
{
	int ret = 0;

	if (cnx->client_mode && !fctest_ctx->is_started) {
		uint8_t start[] = { 0xff, 0xfe, 0xfd, 0xfc };
		fctest_ctx->is_started = 1;
		fctest_ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 0);
		ret = picoquic_add_to_stream(cnx, fctest_ctx->stream_id, start, sizeof(start), 1);
		if (ret == 0) {
			ret = picoquic_set_app_flow_control(cnx, fctest_ctx->stream_id, 1);
		}
	}
	return ret;
}

int fctest_receive_data(fctest_ctx_t* fctest_ctx, picoquic_cnx_t* cnx, uint64_t current_time, size_t length)
{
	int ret = 0;
	uint64_t delta_t = current_time - fctest_ctx->buffered_time + fctest_ctx->microsec_rounding_error;
	uint64_t processed_bytes = delta_t / fctest_ctx->microsecs_per_byte;

	if (processed_bytes >= fctest_ctx->bytes_buffered) {
		processed_bytes = fctest_ctx->bytes_buffered;
		fctest_ctx->bytes_buffered = 0;
		fctest_ctx->microsec_rounding_error = 0;
	}
	else {
		fctest_ctx->bytes_buffered -= processed_bytes;
		fctest_ctx->microsec_rounding_error = delta_t % fctest_ctx->microsecs_per_byte;
	}
	fctest_ctx->buffered_time = current_time;
	fctest_ctx->credits_pending += processed_bytes;

	if (length > 0) {
		fctest_ctx->bytes_buffered += length;
		fctest_ctx->bytes_received += length;
		if (fctest_ctx->bytes_buffered > fctest_ctx->bytes_buffered_max) {
			fctest_ctx->bytes_buffered_max = fctest_ctx->bytes_buffered;
		}
	}
	/* Enforcing a quantum, because dripping credits in small number will lead to
	 * silly packet syndrome */
	if (fctest_ctx->credits_pending >= fctest_ctx->credit_quantum) {
		fctest_ctx->credits_pending -= fctest_ctx->credit_quantum;
		ret = picoquic_open_flow_control(cnx, fctest_ctx->stream_id, fctest_ctx->credit_quantum);
	}
	return ret;
}

static int fctest_prepare_to_send(fctest_ctx_t* fctest_ctx, uint8_t* context, size_t space)
{
	int ret = 0;
	uint8_t* buffer;
	int is_fin = 0;

	if (fctest_ctx->bytes_sent + space >= fctest_ctx->transfer_size) {
		space = (size_t)(fctest_ctx->transfer_size - fctest_ctx->bytes_sent);
		is_fin = 1;
		fctest_ctx->fin_sent = 1;
	}

	buffer = picoquic_provide_stream_data_buffer(context, space, is_fin, !is_fin);
	if (buffer != NULL) {
		memset(buffer, 0xFC, space);
		fctest_ctx->bytes_sent += space;
	}
	else {
		ret = -1;
	}
	return ret;
}

/* Slow receiver call back */
int fctest_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	fctest_ctx_t* fctest_ctx = (fctest_ctx_t*)callback_ctx;
	uint64_t current_time = picoquic_get_quic_time(cnx->quic);
	/* TODO: decide what to do with the stream context */

	if (fctest_ctx == NULL) {
		return -1;
	}

	if (ret == 0) {
		switch (fin_or_event) {
		case picoquic_callback_stream_data:
		case picoquic_callback_stream_fin:
			/* data arrival on stream x. 
			* On server: Simulate dequeuing based on the receiver rate,
			* then increase queue by provided amount. Monitor maximum
			* queue length. Mark complete if stream fin.
			*/
			if (bytes == NULL && length != 0 && v_stream_ctx != NULL) {
				ret = -1;
			}
			else if (cnx->client_mode) {
				if (stream_id == fctest_ctx->stream_id) {
					ret = fctest_receive_data(fctest_ctx, cnx, current_time, length);
					fctest_ctx->fin_received = (fin_or_event == picoquic_callback_stream_fin);
				}
			}
			else {
				if (stream_id == fctest_ctx->stream_id && fin_or_event == picoquic_callback_stream_fin) {
					picoquic_mark_active_stream(cnx, stream_id, 1, NULL);
				}
			}
			break;
		case picoquic_callback_stream_reset: /* Peer reset stream #x */
		case picoquic_callback_stop_sending: /* Peer asks server to reset stream #x */
			/* Not expected in this test. Failure. */
			break;
		case picoquic_callback_stateless_reset:
		case picoquic_callback_close: /* Received connection close */
		case picoquic_callback_application_close: /* Received application close */
			fctest_ctx->is_closed = 1;
			break;
		case picoquic_callback_version_negotiation:
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_stream_gap:
			/* Gap indication, when unreliable streams are supported */
			ret = -1;
			break;
		case picoquic_callback_prepare_to_send:
			/* On the client, prepare the expected amount of data. Mark
			* active until the expected amount is received. */
			if (!cnx->client_mode) {
				ret = fctest_prepare_to_send(fctest_ctx, bytes, length);
			}
			break;
		case picoquic_callback_datagram: /* Datagram frame has been received */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_prepare_datagram: /* Prepare the next datagram */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_datagram_acked: /* Ack for packet carrying datagram-frame received from peer */
		case picoquic_callback_datagram_lost: /* Packet carrying datagram-frame probably lost */
		case picoquic_callback_datagram_spurious: /* Packet carrying datagram-frame was not really lost */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_almost_ready:
		case picoquic_callback_ready:
			/* On the client, open a "bidir" stream and mark it active */
			ret = fctest_start_stream(fctest_ctx, cnx);
			break;
		default:
			/* unexpected -- just ignore. */
			break;
		}
	}

	return ret;
}

int fctest_one(fctest_spec_t* spec)
{
	int nb_trials = 0;
	int nb_inactive = 0;
	int was_active = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	fctest_ctx_t fctest_ctx;
	picoquic_connection_id_t initial_cid = { {0xfc, 0x4e, 0x54, 0, 0, 0, 0, 0}, 8 };
	int ret = 0;
	uint64_t timeout = 10000;

	initial_cid.id[7] = spec->test_id;

	fctest_ctx_init(&fctest_ctx, spec);

	if (ret == 0) {
		ret = tls_api_init_ctx_ex2(&test_ctx,
			PICOQUIC_INTERNAL_TEST_VERSION_1,
			PICOQUIC_TEST_SNI, FCTEST_TEST_ALPN, &fctest_ctx.simulated_time, NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

		if (ret == 0) {
			picoquic_tp_t * client_tp = (picoquic_tp_t *) picoquic_get_transport_parameters(test_ctx->cnx_client, 1);

			client_tp->initial_max_stream_data_bidi_local = spec->initial_credit;

			picoquic_set_default_congestion_algorithm(test_ctx->qserver, spec->ccalgo);
			picoquic_set_congestion_algorithm(test_ctx->cnx_client, spec->ccalgo);

			picoquic_set_qlog(test_ctx->qserver, ".");
			test_ctx->qserver->use_long_log = 1;
			picoquic_set_qlog(test_ctx->qclient, ".");
		}
	}

	/* The default procedure creates connections using the test callback.
	* We want to replace that by the fctest callback */

	if (ret == 0) {
		/* TODO: proper call back context */
		picoquic_set_default_callback(test_ctx->qserver, fctest_callback, &fctest_ctx);
		picoquic_set_callback(test_ctx->cnx_client, fctest_callback, &fctest_ctx);
		if (ret == 0) {
			ret = picoquic_start_client_cnx(test_ctx->cnx_client);
		}
	}

	if (ret == 0) {
		ret = tls_api_connection_loop(test_ctx, &fctest_ctx.loss_mask, 0, &fctest_ctx.simulated_time);
	}

	while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
		/* May need to set a timeout per flow control. */
		if (fctest_ctx.bytes_buffered > 0 &&
			fctest_ctx.simulated_time >= fctest_ctx.buffered_time + timeout) {
			ret = fctest_receive_data(&fctest_ctx, test_ctx->cnx_client, fctest_ctx.simulated_time, 0);
		}
		/* Progress. */
		if ((ret = tls_api_one_sim_round(test_ctx, &fctest_ctx.simulated_time, fctest_ctx.simulated_time + timeout, &was_active)) != 0) {
			break;
		}

		/* TODO: test based on fctest context. */
		if (fctest_ctx.fin_received || fctest_ctx.is_closed || fctest_ctx.error_detected) {
			break;
		}
		
		if (was_active) {
			nb_inactive = 0;
		}
		else {
			nb_inactive++;
			if (nb_inactive > 256) {
				break;
			}
		}

		if (++nb_trials > 1000000) {
			ret = -1;
			break;
		}
	}

	/* check that the transfer is complete */
	if (ret == 0 &&(!fctest_ctx.fin_received || fctest_ctx.bytes_received < spec->transfer_size)) {
		DBG_PRINTF("Test received %" PRIu64 " bytes instead of %" PRIu64, fctest_ctx.bytes_received, spec->transfer_size);
		ret = -1;
	}

	/* TODO: check that the buffers remained within specified limits */
	if (ret == 0 && fctest_ctx.bytes_buffered_max > spec->initial_credit + spec->credit_quantum) {
		DBG_PRINTF("Test buffer max %" PRIu64 " bytes instead of %" PRIu64, fctest_ctx.bytes_buffered_max, spec->bytes_buffered_max);
		ret = -1;
	}

	/* Also check completion time */
	if (ret == 0 && spec->completion_target != 0 && fctest_ctx.simulated_time > spec->completion_target) {
		DBG_PRINTF("Test uses %llu microsec instead of %llu", fctest_ctx.simulated_time, spec->completion_target);
		ret = -1;
	}

	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}

int flow_control_test(void)
{
	fctest_spec_t spec = { 0 };
	spec.test_id = 1;
	spec.transfer_size = 1000000;
	spec.microsecs_per_byte = 10;
	spec.credit_quantum = 0x4000;
	spec.initial_credit = 0x10000;
	spec.bytes_buffered_max = 0x4000;
	spec.completion_target = 11000000;
	spec.ccalgo = picoquic_bbr_algorithm;

	return fctest_one(&spec);
}

/*
 * FC callback test: verifies that picoquic_callback_stream_fc_updated and
 * picoquic_callback_conn_fc_updated are delivered to the application when
 * MAX_STREAM_DATA and MAX_DATA frames are received.
 *
 * Setup: client opens a bidi stream with a small receive window. Server sends
 * data via JIT callback. Client receives data and manually advances its stream
 * window via picoquic_open_flow_control, triggering MAX_STREAM_DATA frames back
 * to the server. We verify the server callback fires with the expected events.
 */

#define FCCB_STREAM_WINDOW  0x1000u  /* 4 KB — small enough to require updates */
#define FCCB_CONN_WINDOW    0x4000u  /* 16 KB */
#define FCCB_TRANSFER_SIZE  0x8000u  /* 32 KB — large enough to need several updates */
#define FCCB_CREDIT_QUANTUM 0x800u   /* 2 KB quantum */

typedef struct {
	uint64_t simulated_time;
	uint64_t loss_mask;
	uint64_t stream_id;
	uint64_t bytes_sent;
	uint64_t bytes_received;
	uint64_t credits_pending;
	int is_started;
	int fin_sent;
	int fin_received;
	int is_closed;
	/* Counters for the new FC callback events (set in server/sender callback) */
	int stream_fc_cb_count;
	uint64_t last_stream_fc_stream_id;
	uint64_t last_stream_fc_maxdata;
	int conn_fc_cb_count;
	uint64_t last_conn_fc_maxdata;
} fccb_ctx_t;

static int fccb_prepare_to_send(fccb_ctx_t* ctx, uint8_t* context, size_t space)
{
	uint8_t* buffer;
	int is_fin = 0;

	if (ctx->bytes_sent + space >= FCCB_TRANSFER_SIZE) {
		space = (size_t)(FCCB_TRANSFER_SIZE - ctx->bytes_sent);
		is_fin = 1;
		ctx->fin_sent = 1;
	}

	buffer = picoquic_provide_stream_data_buffer(context, space, is_fin, !is_fin);
	if (buffer != NULL) {
		memset(buffer, 0xCB, space);
		ctx->bytes_sent += space;
		return 0;
	}
	return -1;
}

int fccb_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	fccb_ctx_t* ctx = (fccb_ctx_t*)callback_ctx;
	(void)bytes;
	(void)v_stream_ctx;

	if (ctx == NULL) {
		return -1;
	}

	switch (fin_or_event) {
	case picoquic_callback_stream_data:
	case picoquic_callback_stream_fin:
		if (cnx->client_mode && stream_id == ctx->stream_id) {
			ctx->bytes_received += length;
			ctx->credits_pending += length;
			ctx->fin_received = (fin_or_event == picoquic_callback_stream_fin);
			/* Advance receive window in quantums to trigger MAX_STREAM_DATA */
			if (ctx->credits_pending >= FCCB_CREDIT_QUANTUM) {
				ret = picoquic_open_flow_control(cnx, ctx->stream_id,
					ctx->credits_pending);
				ctx->credits_pending = 0;
			}
		} else if (!cnx->client_mode &&
			fin_or_event == picoquic_callback_stream_fin) {
			/* Client sent its FIN — start server response on the same bidi stream */
			picoquic_mark_active_stream(cnx, stream_id, 1, NULL);
		}
		break;
	case picoquic_callback_ready:
		if (cnx->client_mode && !ctx->is_started) {
			/* Open a bidi stream and enable app-controlled receive FC */
			uint8_t start[] = { 0xff };
			ctx->is_started = 1;
			ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 0);
			ret = picoquic_add_to_stream(cnx, ctx->stream_id, start, sizeof(start), 1);
			if (ret == 0) {
				ret = picoquic_set_app_flow_control(cnx, ctx->stream_id, 1);
			}
		}
		break;
	case picoquic_callback_prepare_to_send:
		if (!cnx->client_mode) {
			ret = fccb_prepare_to_send(ctx, bytes, length);
		}
		break;
	case picoquic_callback_stream_fc_updated:
		/* Fired when server receives MAX_STREAM_DATA from the client */
		ctx->stream_fc_cb_count++;
		ctx->last_stream_fc_stream_id = stream_id;
		ctx->last_stream_fc_maxdata = (uint64_t)length;
		break;
	case picoquic_callback_conn_fc_updated:
		/* Fired when server receives MAX_DATA from the client */
		ctx->conn_fc_cb_count++;
		ctx->last_conn_fc_maxdata = (uint64_t)length;
		break;
	case picoquic_callback_close:
	case picoquic_callback_application_close:
	case picoquic_callback_stateless_reset:
		ctx->is_closed = 1;
		break;
	default:
		break;
	}
	return ret;
}

int fc_callback_test(void)
{
	int nb_trials = 0;
	int nb_inactive = 0;
	int was_active = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	fccb_ctx_t ctx;
	picoquic_connection_id_t initial_cid = { {0xfc, 0xcb, 0x00, 0, 0, 0, 0, 0x02}, 8 };
	int ret = 0;

	memset(&ctx, 0, sizeof(ctx));

	ret = tls_api_init_ctx_ex2(&test_ctx,
		PICOQUIC_INTERNAL_TEST_VERSION_1,
		PICOQUIC_TEST_SNI, FCTEST_TEST_ALPN, &ctx.simulated_time,
		NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

	if (ret == 0) {
		/* Set small initial stream and conn receive windows on the client so that
		 * it will need to send MAX_STREAM_DATA and MAX_DATA updates to the server */
		picoquic_tp_t* client_tp =
			(picoquic_tp_t*)picoquic_get_transport_parameters(test_ctx->cnx_client, 1);
		client_tp->initial_max_stream_data_bidi_local = FCCB_STREAM_WINDOW;
		client_tp->initial_max_data = FCCB_CONN_WINDOW;

		picoquic_set_default_callback(test_ctx->qserver, fccb_callback, &ctx);
		picoquic_set_callback(test_ctx->cnx_client, fccb_callback, &ctx);
		ret = picoquic_start_client_cnx(test_ctx->cnx_client);
	}

	if (ret == 0) {
		ret = tls_api_connection_loop(test_ctx, &ctx.loss_mask, 0, &ctx.simulated_time);
	}

	while (ret == 0 &&
		picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
		if ((ret = tls_api_one_sim_round(test_ctx, &ctx.simulated_time,
			ctx.simulated_time + 10000, &was_active)) != 0) {
			break;
		}
		if (ctx.fin_received || ctx.is_closed) {
			break;
		}
		if (was_active) {
			nb_inactive = 0;
		} else {
			nb_inactive++;
			if (nb_inactive > 256) {
				break;
			}
		}
		if (++nb_trials > 1000000) {
			ret = -1;
			break;
		}
	}

	/* Verify transfer completed */
	if (ret == 0 && (!ctx.fin_received || ctx.bytes_received < FCCB_TRANSFER_SIZE)) {
		DBG_PRINTF("fc_callback_test: received %" PRIu64 " of %" PRIu64 " bytes",
			ctx.bytes_received, (uint64_t)FCCB_TRANSFER_SIZE);
		ret = -1;
	}

	/* Verify stream FC callback fired at least once with a window larger than initial */
	if (ret == 0 && ctx.stream_fc_cb_count == 0) {
		DBG_PRINTF("%s", "fc_callback_test: stream_fc_updated never fired");
		ret = -1;
	}
	if (ret == 0 && ctx.last_stream_fc_maxdata <= FCCB_STREAM_WINDOW) {
		DBG_PRINTF("fc_callback_test: stream_fc maxdata=%" PRIu64 " not > initial %" PRIu64,
			ctx.last_stream_fc_maxdata, (uint64_t)FCCB_STREAM_WINDOW);
		ret = -1;
	}
	if (ret == 0 && ctx.last_stream_fc_stream_id != ctx.stream_id) {
		DBG_PRINTF("fc_callback_test: stream_fc stream_id=%" PRIu64 " expected %" PRIu64,
			ctx.last_stream_fc_stream_id, ctx.stream_id);
		ret = -1;
	}

	/* Verify conn FC callback fired at least once */
	if (ret == 0 && ctx.conn_fc_cb_count == 0) {
		DBG_PRINTF("%s", "fc_callback_test: conn_fc_updated never fired");
		ret = -1;
	}
	if (ret == 0 && ctx.last_conn_fc_maxdata <= FCCB_CONN_WINDOW) {
		DBG_PRINTF("fc_callback_test: conn_fc maxdata=%" PRIu64 " not > initial %" PRIu64,
			ctx.last_conn_fc_maxdata, (uint64_t)FCCB_CONN_WINDOW);
		ret = -1;
	}

	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
	}
	return ret;
}

/* h3zero FC path callback test:
 * Verifies that picoquic_callback_stream_fc_updated is routed by h3zero_callback
 * to the registered path callback as picohttp_callback_stream_fc_updated.
 */

typedef struct st_h3fc_path_ctx_t {
	int fc_cb_count;
	size_t last_length;
	picohttp_call_back_event_t last_event;
} h3fc_path_ctx_t;

static int h3fc_path_callback(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length,
	picohttp_call_back_event_t event, h3zero_stream_ctx_t* stream_ctx,
	void* path_app_ctx)
{
	h3fc_path_ctx_t* ctx = (h3fc_path_ctx_t*)path_app_ctx;
	(void)cnx;
	(void)bytes;
	(void)stream_ctx;

	if (ctx != NULL) {
		ctx->fc_cb_count++;
		ctx->last_length = length;
		ctx->last_event = event;
	}
	return 0;
}

int h3fc_path_callback_test(void)
{
	int ret = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	uint64_t simulated_time = 0;
	picoquic_connection_id_t initial_cid = { {0xfc, 0xf3, 0x00, 0, 0, 0, 0, 0x01}, 8 };
	h3zero_callback_ctx_t* h3ctx = NULL;
	h3zero_stream_ctx_t* stream_ctx = NULL;
	h3fc_path_ctx_t path_ctx;
	uint64_t test_stream_id = 4; /* client-initiated bidi stream */
	size_t test_maxdata = 65536;

	memset(&path_ctx, 0, sizeof(path_ctx));

	ret = tls_api_init_ctx_ex2(&test_ctx,
		PICOQUIC_INTERNAL_TEST_VERSION_1,
		PICOQUIC_TEST_SNI, FCTEST_TEST_ALPN, &simulated_time,
		NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

	if (ret == 0) {
		h3ctx = h3zero_callback_create_context(NULL);
		if (h3ctx == NULL) {
			ret = -1;
		}
	}

	if (ret == 0) {
		stream_ctx = h3zero_find_or_create_stream(
			test_ctx->cnx_client, test_stream_id, h3ctx, 1, 1);
		if (stream_ctx == NULL) {
			ret = -1;
		}
	}

	if (ret == 0) {
		stream_ctx->path_callback = h3fc_path_callback;
		stream_ctx->path_callback_ctx = &path_ctx;

		ret = h3zero_callback(test_ctx->cnx_client, test_stream_id,
			NULL, test_maxdata, picoquic_callback_stream_fc_updated,
			h3ctx, NULL);
	}

	if (ret == 0 && path_ctx.fc_cb_count != 1) {
		DBG_PRINTF("h3fc_path_callback_test: fc_cb_count=%d expected 1",
			path_ctx.fc_cb_count);
		ret = -1;
	}
	if (ret == 0 && path_ctx.last_event != picohttp_callback_stream_fc_updated) {
		DBG_PRINTF("h3fc_path_callback_test: event=%d expected %d",
			(int)path_ctx.last_event, (int)picohttp_callback_stream_fc_updated);
		ret = -1;
	}
	if (ret == 0 && path_ctx.last_length != test_maxdata) {
		DBG_PRINTF("h3fc_path_callback_test: length=%zu expected %zu",
			path_ctx.last_length, test_maxdata);
		ret = -1;
	}

	if (h3ctx != NULL) {
		h3zero_callback_delete_context(test_ctx ? test_ctx->cnx_client : NULL, h3ctx);
	}
	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
	}
	return ret;
}
