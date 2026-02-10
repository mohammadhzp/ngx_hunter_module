/**
* Copyright (c) 2026 mohammadhzp
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/mohammadhzp
 * Date: 6/8/20
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#define NGX_STREAM_HUNTER_IP_SHM_NAME  "hunter_stream_ip_pool"
#define NGX_STREAM_HUNTER_UPSTREAM_VAR "hunter_upstream"
#define NGX_STREAM_HUNTER_IPS_COUNT_VAR "hunter_ips_count"

#define NGX_STREAM_IPO_OP_TYPE_SIZE 2
#define NGX_STREAM_TCP_IP_VERSION_DELIMITER "!!!!"

ngx_module_t  ngx_stream_hunter_module;
static ngx_int_t ngx_stream_hunter_status_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_hunter_ips_count_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data);


typedef struct {  // Tree (per tree data goes here) [struct located in shm]
    ngx_rbtree_t         rbtree;
    ngx_rbtree_node_t    sentinel;
#if (NGX_HAVE_INET6)
    ngx_rbtree_t         rbtree6;
    ngx_rbtree_node_t    sentinel6;
#endif
    uint32_t             n;

} ngx_stream_hunter_ip_rb_tree_sh_ctx_t;


typedef struct {
    ngx_stream_hunter_ip_rb_tree_sh_ctx_t    *sh;
    ngx_slab_pool_t                          *shpool;
    ngx_log_t                                *log;
    ngx_str_t                                 source_host; // Equal to the main config hunter_ips_source_host
    size_t                                    source_port;
    ngx_flag_t                                hunter_ignore_errors_on_ips_start_fill;
    ngx_str_t                                 key;
} ngx_stream_ip_shm_hunter_ctx_t;


typedef struct {  // Pointers to shared memories
    ngx_shm_zone_t    *ip_shm_zone;
} ngx_stream_hunter_shm_zones;


typedef struct { // Server level configuration
    ngx_flag_t hunter_status;            // ENABLE or DISABLE module in current server
    ngx_flag_t hunter_check_ip;          // Check Ip in current server
    ngx_flag_t hunter_check_range;       // Same as hunter_check_ip but for ip ranges
    ngx_str_t  hunter_upstream_success;  // Redirect to this location if session was OK
    ngx_str_t  hunter_upstream_block;    // Redirect to this upstream in case of access deny
    ngx_flag_t hunter_drop_on_block;     // Should we pass blocked request to backend or just drop it asap?
    ngx_uint_t hunter_binary_ra_index;   // Index of $binary_remote_addr variable(We save it at config time to speed up at runtime)
} ngx_stream_hunter_srv_conf_t;


typedef struct { // Main level configuration
    ngx_flag_t                   hunter_enabled;      // If disabled, current module will react to nothing
    ngx_str_t                    hunter_ips_source_host;
    size_t                       hunter_ips_source_port;
    ngx_flag_t                   hunter_ignore_errors_on_ips_start_fill;
    size_t                       hunter_memory_size;  // Determine shared memory size
    ngx_stream_hunter_shm_zones *shm_zones;

} ngx_stream_hunter_main_conf_t;


typedef ngx_int_t (*ngx_stream_ip_shm_operation_handler_pt)
        (ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_rbtree_t *tree, ngx_str_t *binary_ip);


typedef struct {  // WAF Context
    ngx_int_t    deny;  // Determine upstream using this
} ngx_stream_hunter_waf_ctx_t;


typedef struct {  // IP Operation Context
    ngx_rbtree_t                             *tree;      // Which is it ? for IPv6 or IPv4 ?
    ngx_chain_t                              *out;       // Used in order to send response
    short                                     init;      // Determine what stage we are at
    short                                     succeed;   // keep track of successful operations
    short                                     family;    // either AF_INET or AF_INET6
    uint32_t                                  i;         // Keep the number of received IPs(may differ from succeed)
    size_t                                    len;       // IP length -> 4 byte for IPV4 and 128 byte for IPv6
    ngx_stream_ip_shm_operation_handler_pt    chandler;  // aka handler :p  -> determine what rb-tree func to call

} ngx_stream_hunter_ipo_ctx_t;


static ngx_stream_variable_t  ngx_stream_hunter_vars[] = {

        { ngx_string(NGX_STREAM_HUNTER_UPSTREAM_VAR), NULL,
          ngx_stream_hunter_status_variable, 0, NGX_STREAM_VAR_CHANGEABLE|NGX_STREAM_VAR_NOCACHEABLE, 0 },

        { ngx_string(NGX_STREAM_HUNTER_IPS_COUNT_VAR), NULL,
          ngx_stream_hunter_ips_count_variable, 0, NGX_STREAM_VAR_CHANGEABLE, 0 },

        ngx_stream_null_variable
};


/*
 * Functions
 */


static ngx_int_t ngx_stream_hunter_status_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data) {
    ngx_stream_hunter_waf_ctx_t    *ctx;
    ngx_stream_hunter_srv_conf_t   *srv_conf;
    srv_conf = ngx_stream_get_module_srv_conf(s, ngx_stream_hunter_module);

    if (srv_conf->hunter_status != 1 || (srv_conf->hunter_check_ip != 1 && srv_conf->hunter_check_range != 1)) {
        v->not_found = 1;
        return NGX_OK;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_hunter_module);

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    if (ctx->deny == 0) {
        v->len = srv_conf->hunter_upstream_success.len;
        v->data = srv_conf->hunter_upstream_success.data;
    } else {
        v->len = srv_conf->hunter_upstream_block.len;
        v->data = srv_conf->hunter_upstream_block.data;
    }
    return NGX_OK;
}

static ngx_int_t ngx_stream_hunter_ips_count_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data) {
    ngx_stream_hunter_main_conf_t     *main_conf;
    ngx_stream_ip_shm_hunter_ctx_t    *sh_ctx;
    u_char  *p;

    main_conf = ngx_stream_get_module_main_conf(s, ngx_stream_hunter_module);

    if (main_conf->hunter_enabled != 1) {
        v->not_found = 1;
        return NGX_OK;
    }

    sh_ctx = main_conf->shm_zones->ip_shm_zone->data;

    p = ngx_pnalloc(s->connection->pool, NGX_INT32_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%P", sh_ctx->sh->n) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static void ngx_stream_hunter_response_writer(ngx_event_t *ev) {
    ngx_connection_t               *c;
    ngx_stream_session_t           *s;
    ngx_stream_hunter_ipo_ctx_t    *ctx;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out in hunter ipo");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_hunter_module);

    if (ngx_stream_top_filter(s, ctx->out, 1) == NGX_ERROR) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out = NULL;

    if (!c->buffered) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "stream hunter done sending ipo response");
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    if (ngx_handle_write_event(ev, 0) != NGX_OK) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_add_timer(ev, 5000);
}


static void ngx_send_response(ngx_stream_session_t *s, ngx_str_t *response, ngx_int_t status) {
    ngx_connection_t               *c;
    ngx_buf_t                      *b;
    ngx_stream_hunter_ipo_ctx_t    *ctx;

    c = s->connection;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (response->len == 0) {
        ngx_stream_finalize_session(s, status);
        return;
    }

    b = ngx_calloc_buf(c->pool);

    if (b == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    b->pos = response->data;
    b->last = response->data + response->len;
    b->memory = 1;
    b->last_buf = 1;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_hunter_module);

    ctx->out = ngx_alloc_chain_link(c->pool);
    if (ctx->out == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->out->buf = b;
    ctx->out->next = NULL;

    c->write->handler = ngx_stream_hunter_response_writer;
    ngx_stream_hunter_response_writer(c->write);
}


static ngx_str_node_t *ngx_stream_hunter_ip_shm_get(ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_rbtree_t *tree, ngx_str_t *binary_ip) {
    ngx_str_node_t    *container;
    uint32_t           hash;

    hash = ngx_murmur_hash2(binary_ip->data, binary_ip->len);

    ngx_shmtx_lock(&sh_ctx->shpool->mutex);
    container = ngx_str_rbtree_lookup(tree, binary_ip, hash);
    ngx_shmtx_unlock(&sh_ctx->shpool->mutex);

    return container;
}


static ngx_int_t ngx_stream_hunter_ip_shm_exists(ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_rbtree_t *tree, ngx_str_t *binary_ip) {
    return ngx_stream_hunter_ip_shm_get(sh_ctx, tree, binary_ip) == NULL ? 0 : 1;
}


static ngx_int_t ngx_stream_hunter_ip_shm_insert(ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_rbtree_t *tree, ngx_str_t *binary_ip) {
    ngx_str_node_t    *container;
    uint32_t           hash;

    hash = ngx_murmur_hash2(binary_ip->data, binary_ip->len);

    ngx_shmtx_lock(&sh_ctx->shpool->mutex);
    container = ngx_str_rbtree_lookup(tree, binary_ip, hash);

    if (container != NULL) {
        ngx_shmtx_unlock(&sh_ctx->shpool->mutex);
        return NGX_OK;
    }

    container = ngx_slab_alloc_locked(sh_ctx->shpool, sizeof(ngx_str_node_t));

    if (container == NULL) {
        ngx_shmtx_unlock(&sh_ctx->shpool->mutex);
        return NGX_ERROR;
    }

    container->str.data = ngx_slab_alloc_locked(sh_ctx->shpool, binary_ip->len);
    if (container->str.data == NULL) {
        ngx_shmtx_unlock(&sh_ctx->shpool->mutex);
        return NGX_ERROR;
    }

    container->node.key = hash;
    container->str.len = (size_t) binary_ip->len;

    ngx_memcpy(container->str.data, binary_ip->data, binary_ip->len);

    ngx_rbtree_insert(tree, &container->node);
    ngx_shmtx_unlock(&sh_ctx->shpool->mutex);

    ++sh_ctx->sh->n;

    return NGX_OK;
}


static ngx_int_t ngx_stream_hunter_ip_shm_delete(ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_rbtree_t *tree, ngx_str_t *binary_ip) {
    ngx_str_node_t    *container;
    uint32_t           hash;

    hash = ngx_murmur_hash2(binary_ip->data, binary_ip->len);

    ngx_shmtx_lock(&sh_ctx->shpool->mutex);
    container = ngx_str_rbtree_lookup(tree, binary_ip, hash);

    if (container == NULL) {
        ngx_shmtx_unlock(&sh_ctx->shpool->mutex);
        return NGX_OK;
    }

    ngx_rbtree_delete(&sh_ctx->sh->rbtree, &container->node);
    ngx_slab_free_locked(sh_ctx->shpool, container->str.data);
    ngx_slab_free_locked(sh_ctx->shpool, container);

    ngx_shmtx_unlock(&sh_ctx->shpool->mutex);
    --sh_ctx->sh->n;

    return NGX_OK;
}


static ngx_int_t ngx_stream_hunter_ip_shm_fill_on_start(ngx_stream_ip_shm_hunter_ctx_t * sh_ctx) {
    ngx_time_t           *ts;
    time_t                start_sec;
    ngx_uint_t            start_ms;
    ngx_msec_int_t        ms;
    u_char                buffer[16];
    ngx_str_t             delimiter;
    ngx_int_t             sock;
    ngx_str_t             binary_ip;
    short                 n;       // Ipv4 and Ipv6 indexed count
    short                 n4;      // Ipv4 indexed count
    short                 failed;  // Failed Ip insertion count
    short                 total;   // Total Ips received from upstream
    struct sockaddr_in    server_addr = {0};
    const char            *source_host_data;


    ts = ngx_timeofday();
    start_sec = ts->sec;
    start_ms = ts->msec;

    if (sh_ctx->source_port < 80 || sh_ctx->source_host.len == 0) {
        if (!ngx_test_config) {
            ngx_log_error(
                    NGX_LOG_INFO,
                    sh_ctx->log,
                    0,
                    "Skipped fetching blocked IPs by hunter as no valid HOST and/or PORT provided"
            );
        }
        return NGX_OK;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(sh_ctx->source_port);

    source_host_data = (const char *) sh_ctx->source_host.data;
    if (inet_pton(server_addr.sin_family, source_host_data, &server_addr.sin_addr) != 1) {
        ngx_log_error(
                NGX_LOG_ALERT,
                sh_ctx->log,
                0,
                "Cannot fetch blacklist ips, Invalid IP Address provided for hunter ips source"
        );
        return NGX_ERROR;
    }

    if (ngx_test_config) {
        return NGX_OK;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        ngx_log_error(
                NGX_LOG_ALERT,
                sh_ctx->log,
                0,
                "Unable to create socket to fetch blocked IPs for hunter"
        );
        return NGX_ERROR;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        shutdown(sock, SHUT_RDWR);
        close(sock);

        ngx_log_error(
                NGX_LOG_ALERT,
                sh_ctx->log,
                0,
                "Cannot connect to provided address for hunter IP source: endpoint is down"
        );
        return NGX_ERROR;
    }

    binary_ip.len = sizeof(in_addr_t);  // Always 4

    ngx_str_set(&delimiter, NGX_STREAM_TCP_IP_VERSION_DELIMITER);
    n = 0;
    n4 = 0;
    failed = 0;
    total = 0;

    while(read(sock, buffer, binary_ip.len) != 0) {
        if (ngx_memcmp(buffer, delimiter.data, binary_ip.len) == 0) {
            break;
        }
        ++total;
        binary_ip.data = buffer;

        if (ngx_stream_hunter_ip_shm_insert(sh_ctx, &sh_ctx->sh->rbtree, &binary_ip) == NGX_OK) {
            ++n;
            ++n4;

        } else {
            ++failed;
        }
    }

    binary_ip.len = sizeof(struct in6_addr);  // Always 16

    while(read(sock, buffer, binary_ip.len) != 0) {
        ++total;
        binary_ip.data = buffer;

        if (ngx_stream_hunter_ip_shm_insert(sh_ctx, &sh_ctx->sh->rbtree6, &binary_ip) == NGX_OK) {
            ++n;

        } else {
            ++failed;
        }
    }

    ngx_time_update();
    ts = ngx_timeofday();

    ms = (ngx_msec_int_t) ((ts->sec - start_sec) * 1000 + (ts->msec - start_ms));
    ms = ngx_max(ms, 0);

    ngx_log_error(
            NGX_LOG_CRIT,
            sh_ctx->log,
            0,
            "Hunter: Total Received IPs: %d | Total IPs indexed: %d | Total IPV4 indexed: %d | Failed: %d | Current Total: %d | took %T.%03M",
            total, n, n4, failed, sh_ctx->sh->n, (time_t) ms / 1000, ms % 1000
    );

    shutdown(sock, SHUT_RDWR);
    close(sock);

    return NGX_OK;
}


static ngx_int_t ngx_stream_hunter_init_ip_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_stream_ip_shm_hunter_ctx_t    *octx;
    ngx_stream_ip_shm_hunter_ctx_t    *ctx;
    size_t                             len;

    octx = data;
    ctx = shm_zone->data;
    ctx->log = shm_zone->shm.log;

    if (octx) {  // Reloaded
        if (ctx->key.len != octx->key.len || ctx->key.data != octx->key.data) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "Hunter new shm key does not match");
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_stream_hunter_ip_rb_tree_sh_ctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel, ngx_str_rbtree_insert_value);
#if (NGX_HAVE_INET6)
    ngx_rbtree_init(&ctx->sh->rbtree6, &ctx->sh->sentinel6, ngx_str_rbtree_insert_value);
#endif

    len = sizeof(" in hunter shm \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in hunter shm \"%V\"%Z", &shm_zone->shm.name);
    ctx->sh->n = 0;

    if (ngx_stream_hunter_ip_shm_fill_on_start(ctx) == NGX_ERROR) {
        if (ctx->hunter_ignore_errors_on_ips_start_fill != 1) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


static ngx_int_t ngx_stream_ip_init_from_ipo_type(ngx_stream_ip_shm_hunter_ctx_t *sh_ctx, ngx_stream_hunter_ipo_ctx_t *ctx, u_char *op) {

    if (ngx_memcmp(op, (u_char *) "a4", NGX_STREAM_IPO_OP_TYPE_SIZE) == 0) {
        ctx->len = sizeof(in_addr_t);
        ctx->tree = &sh_ctx->sh->rbtree;
        ctx->family = AF_INET;
        ctx->chandler = ngx_stream_hunter_ip_shm_insert;

    } else if(ngx_memcmp(op, (u_char *) "d4", NGX_STREAM_IPO_OP_TYPE_SIZE) == 0) {
        ctx->len = sizeof(in_addr_t);
        ctx->tree = &sh_ctx->sh->rbtree;
        ctx->family = AF_INET;
        ctx->chandler = ngx_stream_hunter_ip_shm_delete;

    } else if(ngx_memcmp(op, (u_char *) "a6", NGX_STREAM_IPO_OP_TYPE_SIZE) == 0) {
        ctx->len = sizeof(struct in6_addr);
        ctx->tree = &sh_ctx->sh->rbtree6;
        ctx->family = AF_INET6;
        ctx->chandler = ngx_stream_hunter_ip_shm_insert;

    } else if (ngx_memcmp(op, (u_char *) "d6", NGX_STREAM_IPO_OP_TYPE_SIZE) == 0) {
        ctx->len = sizeof(struct in6_addr);
        ctx->tree = &sh_ctx->sh->rbtree6;
        ctx->family = AF_INET6;
        ctx->chandler = ngx_stream_hunter_ip_shm_delete;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void ngx_stream_ip_operation_reader(ngx_event_t *ev) {
    ngx_connection_t               *c;
    ngx_stream_session_t           *s;
    ngx_stream_hunter_ipo_ctx_t    *ctx;
    ssize_t                         n; // result of recv call
    ngx_str_t                       response; // I hope it doesn't make a memory leak :-?

    ngx_stream_hunter_main_conf_t     *main_conf;
    ngx_stream_ip_shm_hunter_ctx_t    *sh_ctx;

    /*
     * There are variable declaration in the body of the function too
     */

    c = ev->data;
    s = c->data;

    main_conf = ngx_stream_get_module_main_conf(s, ngx_stream_hunter_module);
    sh_ctx = main_conf->shm_zones->ip_shm_zone->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_hunter_module);

    if (ctx->init == 0) {
        u_char    op[NGX_STREAM_IPO_OP_TYPE_SIZE]; // possible values are: a4|a6|d4|d6
        n = c->recv(c, op, NGX_STREAM_IPO_OP_TYPE_SIZE);
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n < 0) {
            ngx_handle_read_event(ev, NGX_CLOSE_EVENT);
            ngx_str_set(&response, "-1");
            ngx_send_response(s, &response, NGX_STREAM_OK);
            return;
        }

        if (n == 0) {
            ngx_handle_read_event(ev, NGX_CLOSE_EVENT);
            ngx_str_set(&response, "-6");
            ngx_send_response(s, &response, NGX_STREAM_OK);
            return;
        }

        if (ngx_stream_ip_init_from_ipo_type(sh_ctx, ctx, op) == NGX_ERROR) {
            ngx_handle_read_event(ev, NGX_CLOSE_EVENT);
            ngx_str_set(&response, "-2");
            ngx_send_response(s, &response, NGX_STREAM_OK);
            return;
        }

        ctx->init = 1;
    }

    if (ctx->init != 1) {
        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    ngx_str_t    binary_ip;
    ngx_str_t    end_mark = ngx_string("done");
    u_char       buffer[ctx->len];
    short        ip_len = ctx->family == AF_INET ? 16 : 128;
    char         ip[ip_len];

    binary_ip.len = ctx->len;

    for(;;) {
        n = c->recv(c, buffer, ctx->len);
        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n < 0) {
            ngx_str_set(&response, "-4");
            ngx_send_response(s, &response, NGX_STREAM_OK);
            return;
        }

        ++ctx->i;

        if (n == 0) {
            break;
        }

        if (ngx_memcmp(buffer, end_mark.data, end_mark.len) == 0) {
            break;
        }

        if (inet_ntop(ctx->family, buffer, ip, ip_len) == NULL) {
            ngx_handle_read_event(ev, NGX_CLOSE_EVENT);
            ngx_str_set(&response, "-5");
            ngx_send_response(s, &response, NGX_STREAM_OK);
            return;
        }

        binary_ip.data = buffer;
        if (ctx->chandler(sh_ctx, ctx->tree, &binary_ip) == NGX_OK) {
            ctx->succeed++;
        }

    }

    ngx_handle_read_event(ev, NGX_CLOSE_EVENT);

    ngx_log_error(
            NGX_LOG_ALERT,
            c->log,
            0,
            "Finished IPO succeed: %d | current total: %d", ctx->succeed, sh_ctx->sh->n
    );

    char final[8];
    sprintf(final, "%d", ctx->succeed);
    ngx_str_set(&response, final);

    ngx_send_response(s, &response, NGX_STREAM_OK);
}


/*
 * Handlers
 */


static void ngx_stream_ip_operation_handler(ngx_stream_session_t *s) {
    ngx_stream_hunter_ipo_ctx_t    *ctx;
    ngx_connection_t               *c;

    c = s->connection;

    c->read->handler = ngx_stream_ip_operation_reader;

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_hunter_ipo_ctx_t));

    ctx->init = 0;
    ctx->succeed = 0;
    ctx->i = 0;

    ngx_stream_set_ctx(s, ctx, ngx_stream_hunter_module);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, 10000);
    }

}


static ngx_int_t ngx_stream_hunter_handler(ngx_stream_session_t *s) {
    ngx_stream_hunter_srv_conf_t      *srv_conf;
    ngx_stream_hunter_main_conf_t     *main_conf;
    ngx_stream_ip_shm_hunter_ctx_t    *sh_ctx;
    ngx_stream_hunter_waf_ctx_t       *ctx;
    ngx_connection_t                  *c;
    ngx_stream_variable_value_t       *binary_ip;
    ngx_str_t                          binary_ra;
#if (NGX_HAVE_INET6)
    in_addr_t                          addr;
    struct sockaddr_in6               *sin6;
    u_char                            *p;
#endif

    srv_conf = ngx_stream_get_module_srv_conf(s, ngx_stream_hunter_module);
    if (srv_conf->hunter_status != 1 || (srv_conf->hunter_check_ip != 1 && srv_conf->hunter_check_range != 1)) {
        return NGX_DECLINED;
    }

    c = s->connection;
    if (srv_conf->hunter_upstream_success.len == 0) {
        ngx_log_error(
                NGX_LOG_ALERT,
                c->log,
                0,
                "You need to specify a valid upstream for success scenario"
        );
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    if (srv_conf->hunter_drop_on_block != 1 && srv_conf->hunter_upstream_block.len == 0) {
        ngx_log_error(
                NGX_LOG_ALERT,
                c->log,
                0,
                "You need to specify a valid upstream for block scenario"
        );
        return NGX_STREAM_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_hunter_waf_ctx_t));
    ngx_stream_set_ctx(s, ctx, ngx_stream_hunter_module);

    binary_ip = ngx_stream_get_indexed_variable(s, srv_conf->hunter_binary_ra_index);
    binary_ra.len = binary_ip->len;
    binary_ra.data = (u_char *)binary_ip->data;

    main_conf = ngx_stream_get_module_main_conf(s, ngx_stream_hunter_module);
    sh_ctx = main_conf->shm_zones->ip_shm_zone->data;

    if (sh_ctx->sh->n == 0) {
        return NGX_DECLINED;
    }

    if (srv_conf->hunter_check_ip) {
        switch (s->connection->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
                if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                    p = sin6->sin6_addr.s6_addr;
                    addr = p[12] << 24;
                    addr += p[13] << 16;
                    addr += p[14] << 8;
                    addr += p[15];
                    binary_ra.len = sizeof(in_addr_t);
                    *binary_ra.data = (u_char) addr;
                    ctx->deny = ngx_stream_hunter_ip_shm_exists(sh_ctx, &sh_ctx->sh->rbtree, &binary_ra);
                } else {
                    ctx->deny = ngx_stream_hunter_ip_shm_exists(sh_ctx, &sh_ctx->sh->rbtree6, &binary_ra);
                }
                break;
#endif
            case AF_INET:
                ctx->deny = ngx_stream_hunter_ip_shm_exists(sh_ctx, &sh_ctx->sh->rbtree, &binary_ra);
                break;
            default:
                ctx->deny = 0;
        }
    }

    if (ctx->deny == 1 && srv_conf->hunter_drop_on_block == 1) {
        return NGX_STREAM_FORBIDDEN;
    }

    return NGX_DECLINED;
}


/*
 * Configuration
 */


static ngx_int_t ngx_stream_hunter_pre_conf(ngx_conf_t *cf) {
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_hunter_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static char *ngx_stream_set_hunter_ip_operation_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_stream_hunter_main_conf_t *main_conf;
    main_conf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_hunter_module);

    if (main_conf->hunter_enabled != 1) {
        return NGX_CONF_OK;
    }


    ngx_stream_core_srv_conf_t *cl_cf;
    cl_cf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cl_cf->handler = ngx_stream_ip_operation_handler;

    return NGX_CONF_OK;
}


static ngx_int_t ngx_stream_hunter_attach_conf(ngx_conf_t *cf) {
    ngx_stream_hunter_main_conf_t *main_conf;
    main_conf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_hunter_module);

    if (main_conf->hunter_enabled != 1) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Hunter disabled so no attach");
        return NGX_OK;
    }

    ngx_stream_handler_pt *h;
    ngx_stream_core_main_conf_t *cm_cf;

    cm_cf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    h = ngx_array_push(&cm_cf->phases[NGX_STREAM_POST_ACCEPT_PHASE].handlers);

    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Could not attach hunter handler to post access phase");
        return NGX_ERROR;
    }

    *h = ngx_stream_hunter_handler;

    return NGX_OK;
}


static void *ngx_stream_hunter_create_main_conf(ngx_conf_t *cf) {
    ngx_stream_hunter_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_hunter_main_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unable to allocate memory to create hunter main config");
        return NGX_CONF_ERROR;
    }

    conf->hunter_enabled = NGX_CONF_UNSET;
    conf->hunter_memory_size = NGX_CONF_UNSET_SIZE;
    conf->hunter_ips_source_port = NGX_CONF_UNSET_UINT;
    conf->hunter_ignore_errors_on_ips_start_fill = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *ngx_stream_hunter_init_main_conf(ngx_conf_t *cf, void *configuration) {

    ngx_shm_zone_t                    *shm_zone;
    ngx_stream_hunter_shm_zones       *shm_zones;
    ngx_stream_ip_shm_hunter_ctx_t    *ip_sh_ctx;
    ngx_stream_hunter_main_conf_t     *conf;

    conf = (ngx_stream_hunter_main_conf_t*) configuration;

    ngx_conf_init_value(conf->hunter_enabled, 0);

    if (conf->hunter_enabled != 1) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Hunter disabled");
        return NGX_CONF_OK;
    }

    if (conf->hunter_memory_size == NGX_CONF_UNSET_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "No value specified for hunter memory size");
        return NGX_CONF_ERROR;
    }

    if (conf->hunter_memory_size < 1000000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Minimum allowed shared memory size for hunter is 1m");
        return NGX_CONF_ERROR;
    }

    ip_sh_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ip_shm_hunter_ctx_t));
    if (ip_sh_ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zones = ngx_pcalloc(cf->pool, sizeof(ngx_stream_hunter_shm_zones));
    if (shm_zones == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&ip_sh_ctx->key, NGX_STREAM_HUNTER_IP_SHM_NAME);
    shm_zone = ngx_shared_memory_add(cf, &ip_sh_ctx->key, conf->hunter_memory_size, &ngx_stream_hunter_module);

    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Unable to create shared memory for hunter");
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "shm is already created, but not by hunter");
        return NGX_CONF_ERROR;
    }

    ip_sh_ctx->source_host.len = conf->hunter_ips_source_host.len;
    ip_sh_ctx->source_host.data = conf->hunter_ips_source_host.data;
    ip_sh_ctx->source_port = conf->hunter_ips_source_port;
    ip_sh_ctx->hunter_ignore_errors_on_ips_start_fill = conf->hunter_ignore_errors_on_ips_start_fill;

    shm_zone->init = ngx_stream_hunter_init_ip_shm_zone;
    shm_zone->data = ip_sh_ctx;

    shm_zones->ip_shm_zone = shm_zone;
    conf->shm_zones = shm_zones;

    return NGX_CONF_OK;
}


static void *ngx_stream_hunter_create_srv_conf(ngx_conf_t *cf) {
    ngx_stream_hunter_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_hunter_srv_conf_t));

    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unable to allocate memory to create hunter srv config");
        return NGX_CONF_ERROR;
    }


    conf->hunter_status = NGX_CONF_UNSET;
    conf->hunter_check_ip = NGX_CONF_UNSET;
    conf->hunter_check_range = NGX_CONF_UNSET;
    conf->hunter_drop_on_block = NGX_CONF_UNSET;

    return conf;

}

static char *ngx_stream_hunter_merge_srv_conf(ngx_conf_t *cf, void *parent_configuration, void *configuration) {
    ngx_stream_hunter_srv_conf_t *parent;
    ngx_stream_hunter_srv_conf_t *conf;
    ngx_str_t                    ra_var_name;

    parent = parent_configuration;
    conf = configuration;

    ngx_conf_merge_value(conf->hunter_status, parent->hunter_status, 1);
    ngx_conf_merge_value(conf->hunter_check_ip, parent->hunter_check_ip, 1);
    ngx_conf_merge_value(conf->hunter_check_range, parent->hunter_check_range, 1);
    ngx_conf_merge_value(conf->hunter_drop_on_block, parent->hunter_drop_on_block, 1);

    ngx_str_set(&ra_var_name, "binary_remote_addr");
    conf->hunter_binary_ra_index = ngx_stream_get_variable_index(cf, &ra_var_name);

    return NGX_CONF_OK;
}

/*
 * End
 */


/*
 * Routines
 */

static ngx_command_t  ngx_stream_hunter_commands[] = {

        { ngx_string("hunter_ip_operation"),
          NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
          ngx_stream_set_hunter_ip_operation_conf,
          0,
          0,
          NULL },

        { ngx_string("hunter_status"),
          NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,                      // NGX_CONF_FLAG means accept boolean (on or off)
          ngx_conf_set_flag_slot,                                 // Turn on or off to 1 or 0(called on configuration)
          NGX_STREAM_SRV_CONF_OFFSET,                             // Save in server configuration
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_status),  // Save it to config automatically
          NULL },

        { ngx_string("hunter_check_ip"),  // Directive isn't in README.rst yet
          NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_STREAM_SRV_CONF_OFFSET,
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_check_ip),
          NULL },

        { ngx_string("hunter_check_range"),  // Directive isn't in README.rst yet
          NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_STREAM_SRV_CONF_OFFSET,
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_check_range),
          NULL },

        { ngx_string("hunter_upstream_block"),
          NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_str_slot,
          NGX_STREAM_SRV_CONF_OFFSET,
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_upstream_block),
          NULL },

        { ngx_string("hunter_upstream_success"),
          NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_str_slot,
          NGX_STREAM_SRV_CONF_OFFSET,
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_upstream_success),
          NULL },

        { ngx_string("hunter_drop_on_block"),
          NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_STREAM_SRV_CONF_OFFSET,
          offsetof(ngx_stream_hunter_srv_conf_t, hunter_drop_on_block),
          NULL },

        // Main config
        { ngx_string("hunter_memory_size"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_size_slot,  // Turn 1k or 512m to size_t
          NGX_STREAM_MAIN_CONF_OFFSET,
          offsetof(ngx_stream_hunter_main_conf_t, hunter_memory_size),
          NULL },

        { ngx_string("hunter_ips_source_host"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_str_slot, // Turn value to ngx_str_t
          NGX_STREAM_MAIN_CONF_OFFSET,
          offsetof(ngx_stream_hunter_main_conf_t, hunter_ips_source_host),
          NULL },

        { ngx_string("hunter_ips_source_port"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_num_slot,  // Turn value to ngx_int_t
          NGX_STREAM_MAIN_CONF_OFFSET,
          offsetof(ngx_stream_hunter_main_conf_t, hunter_ips_source_port),
          NULL },

        { ngx_string("hunter_ignore_errors_on_ips_start_fill"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_STREAM_MAIN_CONF_OFFSET,
          offsetof(ngx_stream_hunter_main_conf_t, hunter_ignore_errors_on_ips_start_fill),
          NULL },

        { ngx_string("hunter_enabled"),
          NGX_STREAM_MAIN_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_STREAM_MAIN_CONF_OFFSET,
          offsetof(ngx_stream_hunter_main_conf_t, hunter_enabled),
          NULL },

        ngx_null_command
};


static ngx_stream_module_t ngx_stream_hunter_module_ctx = {
        ngx_stream_hunter_pre_conf,            /* pre-configuration */
        ngx_stream_hunter_attach_conf,         /* post-configuration */

        ngx_stream_hunter_create_main_conf,    /* create main configuration */
        ngx_stream_hunter_init_main_conf,      /* init main configuration */

        ngx_stream_hunter_create_srv_conf,     /* create server configuration */
        ngx_stream_hunter_merge_srv_conf       /* merge server configuration */
};


ngx_module_t  ngx_stream_hunter_module = {
        NGX_MODULE_V1,
        &ngx_stream_hunter_module_ctx, /* module context */
        ngx_stream_hunter_commands,    /* module directives */
        NGX_STREAM_MODULE,             /* module type */
        NULL,                          /* init master */
        NULL,                          /* init module */
        NULL,                          /* init process */
        NULL,                          /* init thread */
        NULL,                          /* exit thread */
        NULL,                          /* exit process */
        NULL,                          /* exit master */
        NGX_MODULE_V1_PADDING
};

/*
 * End
 */