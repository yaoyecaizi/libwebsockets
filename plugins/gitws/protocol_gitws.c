/*
 * gitws - git to websockets bridge
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

#include <libjsongit2.h>

struct pss_gitws {
	struct jg2_ctx *ctx;
	struct lws *wsi;
	int state;
};

struct vhd_gitws {
	struct jg2_vhost *jg2_vhost;
	struct lws_vhost *vhost;
	const char *html, *vpath, *repo_base_dir, *acl_user, *avatar_url;
	const struct lws_protocols *cache_protocol;
};

void refchange(void * user)
{
	struct pss_gitws *pss = (struct pss_gitws *)user;

	lwsl_notice("%s: %p\n", __func__, pss);

	if (!pss)
		return;

	lws_callback_on_writable(pss->wsi);
}

static const char *hex = "0123456789abcdef";

static const char *
md5_to_hex_cstr(char *md5_hex_33, const unsigned char *md5)
{
	int n;

	if (!md5) {
		*md5_hex_33++ = '?';
		*md5_hex_33++ = '\0';
		return md5_hex_33 - 2;
	}
	for (n = 0; n < 16; n++) {
		*md5_hex_33++ = hex[((*md5) >> 4) & 0xf];
		*md5_hex_33++ = hex[*(md5++) & 0xf];
	}
	*md5_hex_33 = '\0';

	return md5_hex_33 - 32;
}

int avatar(void *avatar_arg, const unsigned char *md5)
{
	struct vhd_gitws *vhd = (struct vhd_gitws *)avatar_arg;
	typedef int (*mention_t)(const struct lws_protocols *pcol,
			struct lws_vhost *vh, const char *path);
	char md[256];

	if (!vhd->cache_protocol)
		vhd->cache_protocol = lws_vhost_name_to_protocol(
					vhd->vhost, "lws-hproxy");

	if (!vhd->cache_protocol)
		return 0;

	strcpy(md, "/avatar/");
	md5_to_hex_cstr(md + strlen(md), md5);
	strcat(md, "?s=128&d=retro");

	((mention_t)(void *)vhd->cache_protocol->user)
			(vhd->cache_protocol, vhd->vhost, md);

	return 0;
}

static int
get_pvo_gitws(void *in, const char *name, const char **result)
{
	const struct lws_protocol_vhost_options *pv =
		lws_pvo_search((const struct lws_protocol_vhost_options *)in,
				name);

	if (!pv)
		return 1;

	*result = (const char *)pv->value;

	return 0;
}

static int
callback_gitws(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct pss_gitws *pss = (struct pss_gitws *)user;
	struct vhd_gitws *vhd = (struct vhd_gitws *)
			      lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						       lws_get_protocol(wsi));
	char buf[LWS_PRE + 4096], etag[36], inm[36];
	unsigned char *p = (unsigned char *)&buf[LWS_PRE], *start = p,
		      *end = (unsigned char *)buf + sizeof(buf);
	struct jg2_ctx_create_args args;
	struct jg2_vhost_config config;
	const char *mimetype = NULL;
	unsigned long length = 0;
	int n, uid, gid;
	size_t used;

	switch (reason) {

	/* --------------- protocol --------------- */

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
					    lws_get_protocol(wsi),
					    sizeof(struct vhd_gitws));
		vhd = (struct vhd_gitws *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));

		vhd->vhost = lws_get_vhost(wsi);

		if (get_pvo_gitws(in, "html-file", &vhd->html) ||
		    get_pvo_gitws(in, "vpath", &vhd->vpath) ||
		    get_pvo_gitws(in, "repo-base-dir", &vhd->repo_base_dir) ||
		    get_pvo_gitws(in, "acl-user", &vhd->acl_user) ||
		    get_pvo_gitws(in, "avatar-url", &vhd->avatar_url)) {

			lwsl_err("%s: required pvos: html-file, vpath,"
				 "repo-base-dir, acl-user, avatar-url\n",
				 __func__);

			return -1;
		}

		memset(&config, 0, sizeof(config));
		config.virtual_base_urlpath = vhd->vpath;
		config.refchange = refchange;
		config.avatar = avatar;
		config.avatar_arg = vhd;
		config.avatar_url = vhd->avatar_url;
		config.repo_base_dir = vhd->repo_base_dir;
		config.vhost_html_filepath = vhd->html;
		config.acl_user = vhd->acl_user;

		/* optional... no caching if not set */
		if (!get_pvo_gitws(in, "cache-base", &config.json_cache_base)) {
			lws_get_effective_uid_gid(lws_get_context(wsi), &uid,
						  &gid);
			(void)mkdir(config.json_cache_base, 0700);
			(void)chown(config.json_cache_base, uid, gid);
		}

		vhd->jg2_vhost = jg2_vhost_create(&config);
		if (!vhd->jg2_vhost)
			return -1;

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
					       lws_get_protocol(wsi),
					       LWS_CALLBACK_USER, 3);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY: /* per vhost */
		jg2_vhost_destroy(vhd->jg2_vhost);
		vhd->jg2_vhost = NULL;
		break;

	case LWS_CALLBACK_USER:

		jg2_vhost_repo_reflist_update(vhd->jg2_vhost);

		lws_timed_callback_vh_protocol(lws_get_vhost(wsi),
						lws_get_protocol(wsi),
						LWS_CALLBACK_USER, 3);
		break;

	/* --------------- http --------------- */

	case LWS_CALLBACK_HTTP:
		/*
		 * "in" contains the url part after our mountpoint, if any.
		 *
		 * Our strategy is to record the URL for the duration of the
		 * transaction and return the user's configured html template,
		 * plus JSON prepared based on the URL.  That lets the page
		 * display remotely in one roundtrip (+tls) without having to
		 * wait for the ws link to come up.
		 *
		 * Serving anything other than the configured html template
		 * will have to come from outside this mount URL path.
		 */

		{
			p = start;
			if ((int)len >= end - p)
				len = end - p - 1;
			memcpy(p, in, len);
			p += len;

			n = 0;
			while (lws_hdr_copy_fragment(wsi, (char *)p + 1,
						     end - p - 2,
						     WSI_TOKEN_HTTP_URI_ARGS,
						     n) > 0) {
				if (!n)
					*p = '?';
				else
					*p = '&';

				p += strlen((char *)p);
				n++;
			}

			*p++ = '\0';
		}

		memset(&args, 0, sizeof(args));
		args.repo_path = (const char *)start;
		args.flags = JG2_CTX_FLAG_HTML;
		args.mimetype = &mimetype;
		args.length = &length;
		args.etag = etag;
		args.etag_length = sizeof(etag);

		n = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_IF_NONE_MATCH);
		if (n && lws_hdr_copy(wsi, inm, sizeof(inm),
				      WSI_TOKEN_HTTP_IF_NONE_MATCH) > 0)
			args.client_etag = inm;

		p = start;

		if (jg2_ctx_create(vhd->jg2_vhost, &pss->ctx, &args)) {
			lwsl_err("%s: jg2_ctx_create fail: %s\n", __func__,
					start);

			/* we can't serve this, for whatever reason */

			if (lws_add_http_header_status(wsi,
					HTTP_STATUS_INTERNAL_SERVER_ERROR,
					&p, end))
				return -1;

			if (lws_finalize_http_header(wsi, &p, end))
				return -1;

			n = lws_write(wsi, start, p - start,
				      LWS_WRITE_HTTP_HEADERS |
				      LWS_WRITE_H2_STREAM_END);
			if (n != (p - start)) {
				lwsl_err("_write returned %d from %ld\n", n,
					 (long)(p - start));
				return -1;
			}

			goto transaction_completed;
		}


		/* does he actually already have a current version of it? */

		n = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_IF_NONE_MATCH);
		if (etag[0] && n && !strcmp(etag, inm)) {

			lwsl_notice("%s: etag match %s\n", __func__, etag);

			/* we don't need to send the payload... lose the ctx */

			jg2_ctx_destroy(pss->ctx);
			pss->ctx = NULL;

			/* inform the client he already has the latest guy */

			if (lws_add_http_header_status(wsi,
					HTTP_STATUS_NOT_MODIFIED, &p, end))
				return -1;

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_ETAG,
					(unsigned char *)etag, n, &p, end))
				return -1;

			if (lws_finalize_http_header(wsi, &p, end))
				return 1;

			n = lws_write(wsi, start, p - start,
				      LWS_WRITE_HTTP_HEADERS |
				      LWS_WRITE_H2_STREAM_END);
			if (n != (p - start)) {
				lwsl_err("_write returned %d from %ld\n", n,
					 (long)(p - start));
				return -1;
			}

			goto transaction_completed;
		}

		/* nope... he doesn't already have it, so we must issue it */

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				mimetype, length? length :
				LWS_ILLEGAL_HTTP_CONTENT_LEN, &p, end))
			return 1;

		/*
		 * if we know the etag already, issue it so we can recognize
		 * if he asks for it again while he already has it
		 */

		if (etag[0] &&
		    lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_ETAG,
						 (unsigned char *)etag,
						 strlen(etag), &p, end))
				return 1;

		if (lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		lwsl_debug("%s: LWS_CALLBACK_CLOSED_HTTP\n", __func__);
		if (pss)
			jg2_ctx_destroy(pss->ctx);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:

		if (!pss)
			break;

		n = LWS_WRITE_HTTP;
		if (jg2_ctx_fill(pss->ctx, buf + LWS_PRE,
				 sizeof(buf) - LWS_PRE, &used))
			n = LWS_WRITE_HTTP_FINAL;

		if (lws_write(wsi, (unsigned char *)buf + LWS_PRE, used,
			      n) != (int)used) {
			lwsl_err("lws_write failed\n");

			return 1;
		}

		if (n == LWS_WRITE_HTTP_FINAL)
			goto transaction_completed;

		lws_callback_on_writable(wsi);

		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

transaction_completed:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_LWS_GITWS \
	{ \
		"lws-gitws", \
		callback_gitws, \
		sizeof(struct pss_gitws), \
		4096, \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_GITWS
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_gitws(struct lws_context *context,
				struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d",
			 LWS_PLUGIN_API_MAGIC, c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_gitws(struct lws_context *context)
{
	return 0;
}
#endif
