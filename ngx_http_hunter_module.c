/**
* Copyright (c) 2026 mohammadhzp
 * SPDX-License-Identifier: MIT
 * Project: https://github.com/mohammadhzp
 * Date: 6/8/20
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct { // Main level configuration
    ngx_flag_t hunter_enabled;      // If disabled, current module will react to nothing
    ngx_flag_t hunter_post_read;    // If enabled, phase would be post read, if disabled, phase would be access
    size_t     hunter_memory_size;  // Determine shared memory size
    ngx_str_t  hunter_source_host;
    ngx_int_t  hunter_source_port;

} ngx_http_hunter_main_conf_t;

typedef struct { // Location level configuration
    ngx_flag_t hunter_status;       // ENABLE or DISABLE current module anywhere in config(location, server and etc)
    ngx_flag_t hunter_check_ip;     // Flag to check ip or not anywhere in config(location, server and etc)
    ngx_flag_t hunter_check_range;  // Same as hunter_check_ip but for ip range

} ngx_http_hunter_loc_conf_t;


/*
 * Definitions
 */

static ngx_int_t ngx_http_ip_operation_handler(ngx_http_request_t *r); // Handle operation on IP(add,remove and etc)
static ngx_int_t ngx_http_hunter_handler(ngx_http_request_t *r); // Most important handler

static ngx_int_t ngx_http_hunter_attach_conf(ngx_conf_t *cf); // Attach hunter_handler to request cycle here

static void *ngx_http_hunter_create_main_conf(ngx_conf_t *cf); // Create Main default configurations here
static char *ngx_http_hunter_init_main_conf(ngx_conf_t *cf, void *conf); // Override defaults in initialize shared memory pool

static void *ngx_http_hunter_create_loc_conf(ngx_conf_t *cf); // Handle location block directives default
static char *ngx_http_hunter_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf); // Merge location block directives values

/*
 * Set handler on config time, this conf is different as it's from ngx_command_t
 */
static char *ngx_http_set_hunter_ip_operation_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*
 * End
 */


/*
 * Routines
 */

static ngx_command_t  ngx_http_hunter_commands[] = {  // Directives goes here
        { ngx_string("hunter_status"),
          NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,  // NGX_CONF_FLAG means accept boolean (on or off)
          ngx_conf_set_flag_slot,  // Turn on or off to 1 or 0(called on configuration)
          NGX_HTTP_LOC_CONF_OFFSET,  // Save in Location configuration
          offsetof(ngx_http_hunter_loc_conf_t, hunter_status),  // Save it to config automatically
          NULL },

        { ngx_string("hunter_ip_operation"),
          NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
          ngx_http_set_hunter_ip_operation_conf,  // Call this function on configuration
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },

        { ngx_string("hunter_memory_size"),
          NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_size_slot,  // Turn 1k or 512m to size_t
          NGX_HTTP_MAIN_CONF_OFFSET,
          offsetof(ngx_http_hunter_main_conf_t, hunter_memory_size),
          NULL },

        { ngx_string("hunter_check_ip"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_hunter_loc_conf_t, hunter_check_ip),
          NULL },

        { ngx_string("hunter_check_range"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(ngx_http_hunter_loc_conf_t, hunter_check_range),
          NULL },

        { ngx_string("hunter_source_host"),
          NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_str_slot, // Turn value to ngx_str_t
          NGX_HTTP_MAIN_CONF_OFFSET,
          offsetof(ngx_http_hunter_main_conf_t, hunter_source_host),
          NULL },

        { ngx_string("hunter_source_port"),
          NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
          ngx_conf_set_num_slot,  // Turn value to ngx_int_t
          NGX_HTTP_MAIN_CONF_OFFSET,
          offsetof(ngx_http_hunter_main_conf_t, hunter_source_port),
          NULL },

        { ngx_string("hunter_enabled"),
          NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_HTTP_MAIN_CONF_OFFSET,
          offsetof(ngx_http_hunter_main_conf_t, hunter_enabled),
          NULL },

        { ngx_string("hunter_post_read"),
          NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_HTTP_MAIN_CONF_OFFSET,
          offsetof(ngx_http_hunter_main_conf_t, hunter_post_read),
          NULL },

        ngx_null_command
};

static ngx_http_module_t ngx_http_hunter_module_ctx = {
        NULL,                              /* pre-configuration */
        ngx_http_hunter_attach_conf,       /* post-configuration */
        ngx_http_hunter_create_main_conf,  /* create main configuration */
        ngx_http_hunter_init_main_conf,    /* init main configuration */
        NULL,                              /* create server configuration */
        NULL,                              /* merge server configuration */
        ngx_http_hunter_create_loc_conf,   /* create location configuration */
        ngx_http_hunter_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_hunter_module = {
        NGX_MODULE_V1,
        &ngx_http_hunter_module_ctx, /* module context */
        ngx_http_hunter_commands,    /* module directives */
        NGX_HTTP_MODULE,             /* module type */
        NULL,                        /* init master */
        NULL,                        /* init module */
        NULL,                        /* init process */
        NULL,                        /* init thread */
        NULL,                        /* exit thread */
        NULL,                        /* exit process */
        NULL,                        /* exit master */
        NGX_MODULE_V1_PADDING
};

/*
 * End
 */


/*
 * Handlers
 */

static ngx_int_t ngx_http_ip_operation_handler(ngx_http_request_t *r) {
    //if (!(r->method & (NGX_HTTP_POST))) {
     //   return NGX_HTTP_NOT_ALLOWED;
    //}

    ngx_table_elt_t *h;
    h = ngx_list_push(&r->headers_out.headers);
    h->hash = 1;
    ngx_str_set(&h->key, "IPO");
    ngx_str_set(&h->value, "Worked");

    ngx_http_send_header(r);
    return NGX_HTTP_OK;
}

static ngx_int_t ngx_http_hunter_handler(ngx_http_request_t *r) {
    ngx_http_hunter_loc_conf_t *loc_conf;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_hunter_module);

    if (loc_conf->hunter_status != 1 || (loc_conf->hunter_check_ip != 1 && loc_conf->hunter_check_range != 1)) {
        return NGX_DECLINED;
    }

    ngx_table_elt_t *h;
    h = ngx_list_push(&r->headers_out.headers);
    h->hash = 1;
    ngx_str_set(&h->key, "Hunter");
    ngx_str_set(&h->value, "Worked");

    return NGX_DECLINED;
}

/*
 * End
 */


/*
 * Configuration
 */

static ngx_int_t ngx_http_hunter_attach_conf(ngx_conf_t *cf) {
    ngx_http_hunter_main_conf_t *main_conf;
    main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_hunter_module);

    if (main_conf->hunter_enabled != 1) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Hunter disabled so no attach");
        return NGX_OK;
    }

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cm_cf;

    cm_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cm_cf->phases[main_conf->hunter_post_read == 1 ? NGX_HTTP_POST_READ_PHASE : NGX_HTTP_PREACCESS_PHASE].handlers);

    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Could not attach hunter handler to post read phase");
        return NGX_ERROR;
    }

    *h = ngx_http_hunter_handler;
    return NGX_OK;
}

static void *ngx_http_hunter_create_main_conf(ngx_conf_t *cf) {
    ngx_http_hunter_main_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hunter_main_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unable to allocate memory to create hunter main config");
        return NGX_CONF_ERROR;
    }

    conf->hunter_enabled = NGX_CONF_UNSET_UINT;
    conf->hunter_post_read = NGX_CONF_UNSET_UINT;
    conf->hunter_memory_size = NGX_CONF_UNSET_SIZE;
    conf->hunter_source_port = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *ngx_http_hunter_init_main_conf(ngx_conf_t *cf, void *configuration) {
    ngx_http_hunter_main_conf_t *conf = (ngx_http_hunter_main_conf_t*) configuration;

    ngx_conf_init_uint_value(conf->hunter_enabled, 0);
    ngx_conf_init_uint_value(conf->hunter_post_read, 0);

    if (conf->hunter_enabled != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Hunter disabled");
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

    // TODO: Init shared memory here
    // TODO: Think about host/port scenario

    return NGX_CONF_OK;
}

static void *ngx_http_hunter_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_hunter_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hunter_loc_conf_t));

    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unable to allocate memory to create hunter loc config");
        return NGX_CONF_ERROR;
    }


    conf->hunter_status = NGX_CONF_UNSET_UINT;
    conf->hunter_check_ip = NGX_CONF_UNSET_UINT;
    conf->hunter_check_range = NGX_CONF_UNSET_UINT;

    return conf;

}

static char *ngx_http_hunter_merge_loc_conf(ngx_conf_t *cf, void *parent_configuration, void *configuration) {
    ngx_http_hunter_loc_conf_t *parent = parent_configuration;
    ngx_http_hunter_loc_conf_t *conf = configuration;

    ngx_conf_merge_uint_value(conf->hunter_status, parent->hunter_status, 1);
    ngx_conf_merge_uint_value(conf->hunter_check_ip, parent->hunter_check_ip, 1);
    ngx_conf_merge_uint_value(conf->hunter_check_range, parent->hunter_check_range, 1);

    return NGX_CONF_OK;
}

static char *ngx_http_set_hunter_ip_operation_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_hunter_main_conf_t *main_conf;
    main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_hunter_module);

    if (main_conf->hunter_enabled != 1) {
        return NGX_CONF_OK;
    }


    ngx_http_core_loc_conf_t  *cl_cf;
    cl_cf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    cl_cf->handler = ngx_http_ip_operation_handler;

    return NGX_CONF_OK;
}

/*
 * End
 */