/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief  RTMP (Adobe's Flash Media Server) 
 * 
 * \author Shishir Pokharel <shishir.pokharel@gmail.com>
 *
 * \credits
 * Philippe Sultan <philippe.sultan@inria.fr>
 *
 * \ingroup channel_drivers
 */

/*** MODULEINFO
	<depend>avcodec</depend>
	<depend>rtmp</depend>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 0001 $")

#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <libavcodec/avcodec.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>

#include "asterisk/astobj2.h"
#include "asterisk/lock.h"
#include "asterisk/channel.h"
#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/pbx.h"
#include "asterisk/utils.h"
#include "asterisk/strings.h"
#include "asterisk/app.h"

#define RTMP_DEFAULT_PORT 1935


static struct sockaddr_in rtmpserver;

static char rtmpserverstr[50];

static int port = RTMP_DEFAULT_PORT;

static char application[200];

static unsigned int rtmpinputrate = 11000;	/* default for Nellymoser ASAO */

static unsigned int astinputrate = 8000;

FILE *rtmplog = 0;

static int rlog = 0;

static char rtmplogfile[] = "/tmp/on24rtmp.log";

static const char tdesc[] = "ON24RTMP driver";

static const char config[] = "fms.conf";

static int prefformat = AST_FORMAT_SLINEAR;

static char context[AST_MAX_EXTENSION] = "default";

static char type[] = "ON24RTMP";


/**
 * This structure stores information about the bi-directionnal media connection
 * to the server.
 *
 *  A minimum of 2 connections are used per Asterisk channel to receive/send 
 *  data from/to the RTMP server. Each connection is used to either publish
 *  or read a live stream to the RTMP server.
 */
struct rtmp_pvt 

{
	struct ast_channel *owner;

	pthread_t thread;

	AVCodec *encoder;

	AVCodec *decoder;

	AVCodecContext *encoding_context;

	AVCodecContext *decoding_context;

	ReSampleContext *tortmp_resample_context;

	ReSampleContext *fromrtmp_resample_context;

	unsigned int rtmpinputrate;			/* default : 11000 Hz */

	unsigned int astinputrate;			/* default : 8000 Hz */


	char readstream[AST_MAX_EXTENSION];

	char writestream[AST_MAX_EXTENSION];

	/* two RTMP connections : one read a stream from the server, the other
	 * to publish a stream */

	RTMP *rtmpin;

	RTMP *rtmpout;

	/* \brief Pipe file descriptor handles array.
	 * Read from pipe[0], write to pipe[1]
	 */
	
	int pipe[2];

	int timestamp;
};




static struct ast_channel *rtmp_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause);

static int rtmp_call(struct ast_channel *ast, char *dest, int timeout);

static void rtmp_destroy(struct rtmp_pvt *p);

static int rtmp_hangup(struct ast_channel *ast);

static struct ast_frame *rtmp_read(struct ast_channel *ast);

static int rtmp_write(struct ast_channel *ast, struct ast_frame *frame);

static enum ast_bridge_result rtmp_bridge(struct ast_channel *c0, struct ast_channel *c1, int flags, struct ast_frame **fo, struct ast_channel **rc, int timeoutms);

static void *rtmp_readstream(void *data);

static int rtmp_send_audio(struct rtmp_pvt *p, struct ast_frame *frame); 

static int rtmp_send_video(struct rtmp_pvt *p, struct ast_frame *frame); 

static int rtmp_handle_apacket(struct rtmp_pvt *p, RTMPPacket *packet);

static void rtmp_destroy_fn(void *p);



static const struct ast_channel_tech rtmp_tech = 
{

	.type = type,
	.description = tdesc,
	.capabilities = AST_FORMAT_SLINEAR,
	.requester = rtmp_request,
	.call = rtmp_call,
	.hangup = rtmp_hangup,
	.read = rtmp_read,
	.write = rtmp_write,
	.bridge = rtmp_bridge,
	.write_video = rtmp_write,

};



/*
*
*
*
*	allocating a new rtmp stream for .requester  
*
*
*
*/

/** \brief Allocate a new RTMP stream */
static struct rtmp_pvt *rtmp_alloc(char *writestream, char *readstream, char *readnum) 
{

	struct rtmp_pvt *p;

	/*	
	Temp disable to test its functionality.
	int rnum = 0;

	if (!readnum) {
		rnum = 1;
	} else {
		rnum = atoi(readnum);
	}*/

	ast_log(LOG_DEBUG,"Getting value for rnum %s\n",readnum);

	if (!(p = ao2_t_alloc(sizeof(*p), rtmp_destroy_fn, "allocate a rtmp_pvt struct"))) 
	{
	
		return NULL;

	}

	p->encoder = NULL;

	p->decoder = NULL;

	p->encoding_context = NULL;

	p->decoding_context = NULL;

	p->rtmpinputrate = rtmpinputrate;

	p->astinputrate = astinputrate;

	/* the outputrate value of this context matches with the sampling
	 * rate of the RTMP packets that come in to Asterisk. On the other
	 * hand, the inputrate value of this context matches with the 
	 * sampling rate of the packets that come in to Asterisk from the
	 * opposite Asterisk channel (eg : RTP packets).
	 * Other values are taken from the examples given in FFMPEG.
	 * The function prototype is :
	 * ReSampleContext *av_audio_resample_init(int output_channels, int input_channels,
         * 		                           int output_rate, int input_rate,
         * 			    		   enum SampleFormat sample_fmt_out,
         *                             		   enum SampleFormat sample_fmt_in,
         *                               	   int filter_length, int log2_phase_count,
         *                               	   int linear, double cutoff)
	 */
	p->tortmp_resample_context = av_audio_resample_init(
			
			1, 1,
			p->rtmpinputrate, p->astinputrate,
			AV_SAMPLE_FMT_S16 , AV_SAMPLE_FMT_S16 ,
			16, 10, 1, 0.8

			);

	ast_verbose(VERBOSE_PREFIX_3 "Rtmp resampler for write data \n");

 
	
	p->fromrtmp_resample_context = av_audio_resample_init(
			
			1, 1,
			p->astinputrate, p->rtmpinputrate,
			AV_SAMPLE_FMT_S16 , AV_SAMPLE_FMT_S16 ,
			16, 10, 1, 0.8

			); 

	ast_verbose(VERBOSE_PREFIX_3 "Rtmp resampler for read data \n");

	strncpy(p->readstream, readstream, AST_MAX_EXTENSION);

	strncpy(p->writestream, writestream, AST_MAX_EXTENSION);

	p->rtmpin = RTMP_Alloc();

	RTMP_Init(p->rtmpin);

	p->rtmpout = RTMP_Alloc();

	RTMP_Init(p->rtmpout);

	p->thread = AST_PTHREADT_NULL;

	p->timestamp = time(NULL) * 1000;

	return p;
}



/*
*
*
*
*	creating a new rtmp channel for .requester  
*
*
*
*/


static struct ast_channel *rtmp_new(struct rtmp_pvt *p, int state, const char *linkedid)
{

	ast_verbose(VERBOSE_PREFIX_3 "Creating a new rtmp channel\n");

	struct ast_channel *tmp;

	tmp = ast_channel_alloc(1, state, 0, 0, "", linkedid, "s", context, 0, "RTMP/%s-%s-%04lx", p->readstream, p->writestream, ast_random() & 0xffff);

	if (!tmp) 
	{
	
		ast_log(LOG_WARNING, "Unable to allocate channel structure\n");
		return NULL;
	
	}

	if (pipe(p->pipe) < 0) 
	{
	
		ast_log(LOG_ERROR, "Pipe failed\n");
	
	}

	ast_channel_set_fd(tmp, 0, p->pipe[0]);
	
	tmp->tech = &rtmp_tech;

	tmp->nativeformats = prefformat;

	tmp->readformat = prefformat;

	tmp->writeformat = prefformat;

	if (state == AST_STATE_RING)
		tmp->rings = 1;
	
	tmp->tech_pvt = p;

	ast_copy_string(tmp->context, context, sizeof(tmp->context));

	ast_copy_string(tmp->exten, "s",  sizeof(tmp->exten));

	ast_string_field_set(tmp, language, "");

	p->owner = tmp;

	ast_verbose(VERBOSE_PREFIX_3 "Finding encoder %d\n",CODEC_ID_PCM_S16LE);

	p->encoder = avcodec_find_encoder(CODEC_ID_PCM_S16LE);

	if (!p->encoder)
	{
		ast_debug(3, "Codec not found\n");

		ast_hangup(tmp);
	}

	ast_verbose(VERBOSE_PREFIX_3 "Allocating context\n");

	p->encoding_context = avcodec_alloc_context3(NULL);
	
	p->encoding_context->channels = 1;

	p->encoding_context->sample_fmt = AV_SAMPLE_FMT_S16 ;

	p->encoding_context->sample_rate = 11000;

	if (avcodec_open2(p->encoding_context, p->encoder, NULL) < 0) 
	{
	
		ast_debug(3, "Could not open codec\n");
		ast_hangup(tmp);
	
	}

	
	p->decoder = avcodec_find_decoder(CODEC_ID_NELLYMOSER);

	if (!p->decoder) 
	{
	
		ast_debug(3, "Codec not found\n");
		ast_hangup(tmp);
	
	}

	p->decoding_context = avcodec_alloc_context3(NULL);

	if (avcodec_open2(p->decoding_context, p->decoder, NULL) < 0) {

		ast_debug(3, "Could not open codec\n");
		ast_hangup(tmp);

	}

	if (state != AST_STATE_DOWN) 
	{
		if (ast_pbx_start(tmp)) 
		{

			ast_log(LOG_WARNING, "Unable to start PBX on %s\n", tmp->name);
			ast_hangup(tmp);

		}
	}

	return tmp;
}



/*
*
*
*	.requester i.e rtmp_request called when other channel calls to rtmp channel
* 
*
*
*/




static struct ast_channel *rtmp_request(const char *type, format_t format, const struct ast_channel *requestor, void *data, int *cause)
{
	format_t oldformat;
	struct rtmp_pvt *p;
	struct ast_channel *tmp = NULL;
	char *parse;

	AST_DECLARE_APP_ARGS(
		    
		    args,
			AST_APP_ARG(writestream);
			AST_APP_ARG(readstream);
			AST_APP_ARG(readnum);
			
			);

	oldformat = format;

	format &= (AST_FORMAT_SLINEAR);
	
	ast_verbose(VERBOSE_PREFIX_3 "I have a Rtmp request\n");	

	if (!format) 
	{
	
		ast_log(LOG_WARNING, "Asked to get a channel of unsupported format %s\n", ast_getformatname(oldformat));
		return NULL;
	
	}

	parse = ast_strdupa(data);

    AST_NONSTANDARD_APP_ARGS(args, parse, '/');

	if (ast_strlen_zero(args.readstream)) 
	{
	
		ast_log(LOG_WARNING, "The RTMP driver requires a stream identifier to read\n");
		return NULL;

	}

	if (ast_strlen_zero(args.writestream)) {

		ast_log(LOG_WARNING, "The RTMP driver requires a stream identifier to publish\n");
		return NULL;
	}

	ast_verbose(VERBOSE_PREFIX_3 "Building new stream, on : %s\n", parse);
	
	ast_verbose(VERBOSE_PREFIX_3 "readnum : %s\n", ast_strlen_zero(args.readnum) ? "None" : args.readnum);
	
	p = rtmp_alloc(args.writestream, args.readstream, ast_strlen_zero(args.readnum) ? NULL : args.readnum);

	
	if (p) 
	{
		tmp = rtmp_new(p, AST_STATE_DOWN, requestor ? requestor->linkedid : NULL);
	
		if (!tmp) 
		{
		
			rtmp_destroy(p);

		}

		p->owner = tmp;
	}

	return tmp;
}








static enum ast_bridge_result rtmp_bridge(struct ast_channel *c0, struct ast_channel *c1, int flags, struct ast_frame **fo, struct ast_channel **rc, int timeoutms) {
	return 0;
}


/*
*
*
*
*	fucntion called when there is a audio packets coming in 
*
*
*
*
*/


static int rtmp_write(struct ast_channel *ast, struct ast_frame *frame)
{
	struct rtmp_pvt *p = ast->tech_pvt;
	
	int res = -1;

	if (frame->frametype != AST_FRAME_VOICE && frame->frametype != AST_FRAME_VIDEO) 
	{
	
		ast_log(LOG_WARNING, "Don't know what to do with  frame type '%d'\n", frame->frametype);
		return 0;

	}

	if (frame->frametype == AST_FRAME_VOICE) 
	{
		if (!(frame->subclass.codec & (AST_FORMAT_SLINEAR))) 
		{

			ast_log(LOG_WARNING, "Cannot handle frames in format %s\n", ast_getformatname(frame->subclass.codec));
			return 0;

		}
	}

	if (ast->_state != AST_STATE_UP) 
	{
	
		return 0;
	
	}
	
	if (frame->frametype == AST_FRAME_VIDEO) 
	{
		
		ast_log(LOG_DEBUG, "I GOT A VIDEO FRAME, Not Implemented yet\n");
	//	res = rtmp_send_video(p, frame);	

		
	}

	if (frame->frametype == AST_FRAME_VOICE) 
	{
	
		//ast_log(LOG_DEBUG, "I GOT A VOICE FRAME, RESAMPLING AND SENDING!\n");
		res = rtmp_send_audio(p, frame);	

	}
	

	return res;
}




/*
*
*
*
*	Create and send rtmp packet
*
*
*
*
*/



static int rtmp_send_audio(struct rtmp_pvt *p, struct ast_frame *frame) {
	int res = -1;
	uint8_t *input = NULL;
	short rawsamples[AVCODEC_MAX_AUDIO_FRAME_SIZE];
	//uint8_t samples[1024];
	uint8_t *buf;
	int len = 0, inputlen;
	char pbuf[1024];
	RTMPPacket packet = { 0 };

	packet.m_nChannel = 0x06;
	packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
	packet.m_packetType = RTMP_PACKET_TYPE_AUDIO;
	packet.m_nTimeStamp = (time(NULL) * 1000) -  p->timestamp;
	packet.m_nInfoField2 = p->rtmpout->m_stream_id;
	packet.m_hasAbsTimestamp = 0;
	packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

	buf = (uint8_t *)packet.m_body;

	inputlen = frame->datalen;
	input = ast_malloc(inputlen);
	memcpy(input, frame->data.ptr, inputlen);

	len = audio_resample(p->tortmp_resample_context, rawsamples, (short *)input, inputlen/2);

	//len = avcodec_encode_audio(p->encoding_context, samples, len*2, rawsamples);
	//ast_debug(3, "samples size = %d\n", len);

	*buf++ = 6;
	memcpy(buf, rawsamples, len*2);
	//memcpy(buf, input, inputlen);

	packet.m_nBodySize = len*2 + 1;
	//packet.m_nBodySize = inputlen + 1;

	res = RTMP_SendPacket(p->rtmpout, &packet, 0);

	ast_free(input);
	return res;
}



/*
*
*
*
*	Call other destination channel
*
*
*
*
*/




static int rtmp_call(struct ast_channel *ast, char *dest, int timeout) {
	struct rtmp_pvt *p;
	char tcUrlin[250];
	char tcUrlout[250];

	p = ast->tech_pvt;
	if (!p) {
		ast_debug(3, "tech_pvt is NULL\n");
		return -1;
	}

	if ((ast->_state != AST_STATE_DOWN) && (ast->_state != AST_STATE_RESERVED)) {
		ast_log(LOG_WARNING, "rtmp_call called on %s, neither down nor reserved\n", ast->name);
		return -1;
	}

	ast_debug(3, "Calling %s on %s\n", dest, ast->name);

	/* setup the inbound connection and associated stream */
	snprintf(tcUrlin, sizeof(tcUrlin), "rtmp://%s:%d/%s/%s", rtmpserverstr, port, application, p->readstream);
	RTMP_SetupURL(p->rtmpin, tcUrlin);
	p->rtmpin->Link.lFlags |= RTMP_LF_LIVE;

	if (!RTMP_Connect(p->rtmpin, NULL)) {
		ast_log(LOG_ERROR, "Could not connect to server.\n");
		rtmp_hangup(ast);
		return -1;
	} 

	if (!RTMP_ConnectStream(p->rtmpin, 0)) {
		ast_log(LOG_ERROR, "Could not establish stream.\n");
		rtmp_hangup(ast);
		return -1;
	}

	/* now setup the outbound connection and associated stream and make
	 * sure to enable publishing */
	snprintf(tcUrlout, sizeof(tcUrlout), "rtmp://%s:%d/%s/%s", rtmpserverstr, port, application, p->writestream);
	RTMP_SetupURL(p->rtmpout, tcUrlout);
	p->rtmpout->Link.lFlags |= RTMP_LF_LIVE;

	RTMP_EnableWrite(p->rtmpout);

	if (!RTMP_Connect(p->rtmpout, NULL)) {
		ast_log(LOG_ERROR, "Could not connect to server.\n");
		rtmp_hangup(ast);
		return -1;
	} 

	if (!RTMP_ConnectStream(p->rtmpout, 0)) {
		ast_log(LOG_ERROR, "Could not establish stream.\n");
		rtmp_hangup(ast);
		return -1;
	}

	ast_pthread_create_background(&p->thread, NULL, rtmp_readstream, p);

	/* the RTMP stream is connected */
	ast_queue_control(p->owner, AST_CONTROL_ANSWER);

	return 0;
}




/*
*
*
*
*	Read RTMP Incoming data from FMS server if there is any 
*
*
*
*
*/



static struct ast_frame *rtmp_read(struct ast_channel *ast) {
	struct rtmp_pvt *p = ast->tech_pvt;
	static char buf[4096];
	int res;
	static struct ast_frame f;
	
	if (!buf) {
		return NULL;
	}

	f.frametype = AST_FRAME_NULL;
	f.subclass.codec = 0;
	f.samples = 0;
	f.datalen = 0;
	f.data.ptr = NULL;
	f.offset = 0;
	f.src = "RTMP";
	f.mallocd = 0;
	f.delivery.tv_sec = 0;
	f.delivery.tv_usec = 0;

	res = read(p->pipe[0], buf, 4096);
	if (!res) {
		ast_log(LOG_ERROR, "Failed to read frame from channel %s\n", ast->name);
		return &f;
	}

	f.frametype = AST_FRAME_VOICE;
	f.subclass.codec = AST_FORMAT_SLINEAR;
	f.samples = res / 2;
	f.datalen = res;
	f.data.ptr = buf;

	ast_debug(7, "Read %d bytes as a frame on %s\n", res, ast->name);

	return &f;
}



/*
*
*
*
*	Read RTMP Incoming data from FMS server if there is any 
*
*
*
*
*/

static void *rtmp_readstream(void *data) {
	struct rtmp_pvt *p = data;
	RTMPPacket packet = { 0 };

	while (p->rtmpin && RTMP_IsConnected(p->rtmpin)) {
		RTMP_GetNextMediaPacket(p->rtmpin, &packet);
		
		if (!packet.m_nBodySize) {
			/* ignore zero length media packets */
			continue;
		}

		switch (packet.m_packetType) {
			case RTMP_PACKET_TYPE_AUDIO:
				ast_debug(7, "Received audio packet.\n");
				ast_debug(7, "RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %u. body: 0x%02x\n",
						packet.m_packetType, packet.m_nChannel, packet.m_nTimeStamp, packet.m_nInfoField2,
						packet.m_nBodySize, packet.m_body ? (unsigned char)packet.m_body[0] : 0);
				rtmp_handle_apacket(p, &packet);
				break;
			case RTMP_PACKET_TYPE_VIDEO:
				ast_debug(7, "Received video packet.\n");
				ast_debug(7, "RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %u. body: 0x%02x\n",
						packet.m_packetType, packet.m_nChannel, packet.m_nTimeStamp, packet.m_nInfoField2,
						packet.m_nBodySize, packet.m_body ? (unsigned char)packet.m_body[0] : 0);
				break;
			default:
				ast_debug(7, "Received unknown packet type : %d\n", packet.m_packetType); 
				ast_debug(7, "RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %u. body: 0x%02x\n",
						packet.m_packetType, packet.m_nChannel, packet.m_nTimeStamp, packet.m_nInfoField2,
						packet.m_nBodySize, packet.m_body ? (unsigned char)packet.m_body[0] : 0);
				break;
		}
	}

	ast_debug(7, "Left loop.\n");

	return 0;
}



/** \brief Handle audio packets
 *
 * The first byte is not a media packet,
 * it contains the following codec information :
 *  soundType 	(byte & 0x01) >> 0 	0: mono, 1: stereo
 *  soundSize 	(byte & 0x02) >> 1 	0: 8-bit, 1: 16-bit
 *  soundRate 	(byte & 0x0c) >> 2 	0: 5.5 kHz, 1: 11 kHz, 2: 22 kHz, 3: 44 kHz
 *  soundFormat (byte & 0xf0) >> 4 	0: Uncompressed, 1: ADPCM, 2: MP3, 5: Nellymoser 8kHz mono, 6: Nellymoser, 11: Speex
 */



static int rtmp_handle_apacket(struct rtmp_pvt *p, RTMPPacket *packet) {
	int res = -1;
	uint8_t *input = NULL;
	uint8_t *rawsamples = NULL;
	uint8_t *firstbyte = NULL;
	uint16_t samples[1024];
	int len = 0;
	int rawsampleslen;
	int inputchannels = 0, inputrate = 0, sample_fmt_in = 0, sample_fmt_out = 0;

	rawsampleslen = AVCODEC_MAX_AUDIO_FRAME_SIZE;

	input = ast_malloc(packet->m_nBodySize - 1);
	rawsamples = ast_malloc(rawsampleslen);
	memcpy(input, packet->m_body + 1, packet->m_nBodySize - 1);
	firstbyte = (uint8_t *)packet->m_body;

	ast_debug(7, "firsbyte = %d\n", *firstbyte);
	if ((*firstbyte & 0x01) >> 0 == 1) {
		inputchannels = 2;	/* stereo */
	} else {
		inputchannels = 1;	/* mono */
	}

	if ((*firstbyte & 0x02) >> 1 == 1) {
		sample_fmt_in = 16;
	} else {
		sample_fmt_in = 8;
	}
	sample_fmt_out = 8;

	ast_debug(7, "Audio type : %s\n", (*firstbyte & 0x01) >> 0 ? "stereo" : "mono");
	ast_debug(7, "Sample size : %s\n", (*firstbyte & 0x02) >> 1 ? "16-bit" : "8-bit");
	switch ((*firstbyte & 0x0c) >> 2) {
		case 0:
			ast_debug(7, "Sampling rate : 5,5 kHz\n");
			inputrate = 5500;
			break;
		case 1:
			ast_debug(7, "Sampling rate : 11 kHz\n");
			inputrate = 11000;
			break;
		case 2:
			ast_debug(7, "Sampling rate : 22 kHz\n");
			inputrate = 22000;
			break;
		case 3:
			ast_debug(7, "Sampling rate : 44 kHz\n");
			inputrate = 44000;
			break;
		default:
			inputrate = 44000;
	}

	switch ((*firstbyte & 0xf0) >> 4) {
		case 0:
			ast_debug(7, "Format : Uncompressed\n");
			break;
		case 1:
			ast_debug(7, "Format : ADPCM\n");
			break;
		case 2:
			ast_debug(7, "Format : MP3\n");
			break;
		case 5:
			ast_debug(7, "Format : Nellymoser 8 kHz mono\n");
			/* overwrite input rate */
			inputrate = 8000;
			break;
		case 6:
			ast_debug(7, "Format : Nellymoser\n");
			break;
		case 11:
			ast_debug(7, "Format : Speex\n");
			break;
		default:
			ast_debug(7, "Unknown format : %d\n", (*firstbyte & 0xf0) >> 4);
			break;
	}

	len = avcodec_decode_audio3(p->decoding_context, (int16_t *) rawsamples, &rawsampleslen,  packet);
	if (inputrate != p->rtmpinputrate) {
		/* incoming audio packets are not sampled at the expected rate
		 * so let's reinitialize the sampling context */
		if (!p->fromrtmp_resample_context) {
			ast_log(LOG_WARNING, "No sampling context found\n");
			res = -1;
			goto safeout;
		}
		audio_resample_close(p->fromrtmp_resample_context);
		ast_log(LOG_NOTICE, "Changed incoming sample rate from %d Hz to %d Hz\n", p->rtmpinputrate, inputrate);
		p->rtmpinputrate = inputrate;
		p->fromrtmp_resample_context = av_audio_resample_init(
						1, 1,		/* One channel in both ways */
						p->astinputrate, p->rtmpinputrate,
						AV_SAMPLE_FMT_S16, AV_SAMPLE_FMT_S16,
						16, 10, 1, 0.8); 
	}

	len = audio_resample(p->fromrtmp_resample_context, (short *)samples, (short *)rawsamples, rawsampleslen/2);
	len = write(p->pipe[1], samples, len * 2);

safeout:
	ast_free(input);
	ast_free(rawsamples);

	return res;
}



/*
*
*
* hangup and destroy RTMP channel
*
*
*
*/



static int rtmp_hangup(struct ast_channel *ast) {
	struct rtmp_pvt *p;

	p = ast->tech_pvt;

	ast_debug(3, "rtmp_hangup(%s)\n", ast->name);
	if (!ast->tech_pvt) {
		ast_log(LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}

	rtmp_destroy(p);

	ast->tech_pvt = NULL;
	ast_setstate(ast, AST_STATE_DOWN);
	return 0;
}



static void rtmp_destroy_fn(void *p) {
	rtmp_destroy(p);
}




static void rtmp_destroy(struct rtmp_pvt *p) {
	ast_debug(3, "Freeing rtmp_pvt structures\n");
	close(p->pipe[0]);
	close(p->pipe[1]);
	avcodec_close(p->encoding_context);
	avcodec_close(p->decoding_context);
	if (p->tortmp_resample_context) {
		audio_resample_close(p->tortmp_resample_context);
	}
	if (p->fromrtmp_resample_context) {
		audio_resample_close(p->fromrtmp_resample_context);
	}
	av_free(p->encoding_context);
	av_free(p->decoding_context);

	if (p->thread != AST_PTHREADT_NULL) {
		pthread_cancel(p->thread);
	}

	RTMP_Close(p->rtmpin);
	RTMP_Free(p->rtmpin);

	RTMP_Close(p->rtmpout);
	RTMP_Free(p->rtmpout);
}



/*
*
*
*
*
*	Asterisk load and unload functions for chan_fms
*
*
*
*/


static int load_module(void) 
{

	struct ast_config *cfg = NULL;
	struct ast_variable *v;
	struct ast_flags config_flags = { 0 };

	
	/* load config file */
	if (!(cfg = ast_config_load(config, config_flags))) 
	{
	
		ast_log(LOG_WARNING, "Unable to load config %s\n", config);
	
		return AST_MODULE_LOAD_DECLINE;
	
	}

	else if (cfg == CONFIG_STATUS_FILEINVALID) 
	{
	
		ast_log(LOG_ERROR, "Config file %s is in an invalid format.  Aborting.\n", config);
	
		return AST_MODULE_LOAD_DECLINE;
	}


	RTMP_debuglevel = RTMP_LOGINFO;

	v = ast_variable_browse(cfg, "general");

	for (; v; v = v->next) 
	{
	
		if (!strcasecmp(v->name, "server"))
			ast_copy_string(rtmpserverstr, v->value, sizeof(rtmpserverstr));
		else if (!strcasecmp(v->name, "port"))
			port = atoi(v->value);
		else if (!strcasecmp(v->name, "application"))
			ast_copy_string(application, v->value, sizeof(application));
		else if (!strcasecmp(v->name, "samplerate"))
			rtmpinputrate = atoi(v->value);
		else if (!strcasecmp(v->name, "log"))
			rlog = ast_true(v->value);
		else if (!strcasecmp(v->name, "rtmplogfile"))
			ast_copy_string(rtmplogfile, v->value, sizeof(rtmplogfile));
		else if (!strcasecmp(v->name, "loglevel")) 
			RTMP_debuglevel = atoi(v->value);
	}

	
	if (rlog) 
	{

		rtmplog = fopen(rtmplogfile, "w");
		RTMP_LogSetOutput(rtmplog);

	}

	

	/* must be called before using avcodec lib */
	ast_verbose(VERBOSE_PREFIX_3 "Initializing avcodec\n");	
	avcodec_init();


	/* register all the codecs */
	ast_verbose(VERBOSE_PREFIX_3 "Registering avcodecs \n");	
	avcodec_register_all();


	/* make sure we can register our channel type */
	if (ast_channel_register(&rtmp_tech)) 
	{
	
		ast_log(LOG_ERROR, "Unable to register channel class %s\n", type);
		return -1;
	
	}

	
	memset(&rtmpserver, 0, sizeof(rtmpserver));
	rtmpserver.sin_family      = AF_INET;
	rtmpserver.sin_addr.s_addr = inet_addr(rtmpserverstr);
	rtmpserver.sin_port        = htons(RTMP_DEFAULT_PORT);

	
	return AST_MODULE_LOAD_SUCCESS;
}




static int unload_module(void) 
{

	/* take us out of the channel loop */
	ast_channel_unregister(&rtmp_tech);

	if (rtmplog != 0) 
	{
	
		fclose(rtmplog);
	
	}

	return 0;
}



AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "ON24RTMP Support");
