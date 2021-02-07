/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_config_map.h>

struct flb_metrics_context {
    flb_sds_t field;
    int metrics_id;
    struct flb_output_instance *ins;
};

int cb_metrics_init(struct flb_output_instance *ins,
                    struct flb_config *config,
                    void *data)
{
    (void) ins;
    (void) config;
    (void) data;

    struct flb_metrics_context *ctx;
    int ret;

    ctx = flb_calloc(1, sizeof(struct flb_metrics_context));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->field = NULL;
    ctx->metrics_id = -1;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

#ifdef FLB_HAVE_METRICS
    ctx->metrics_id = flb_metrics_add(-1, "cpu0.p_cpu", ctx->ins->metrics);
#endif
    printf("METRICS ID: %d\n", ctx->metrics_id);

    /* Set the context */
    flb_output_set_context(ins, ctx);
    return 0;
}

void cb_metrics_flush(const void *data, size_t bytes,
                      const char *tag, int tag_len,
                      struct flb_input_instance *i_ins,
                      void *out_context,
                      struct flb_config *config)
{
    (void) data;
    (void) bytes;
    (void) tag;
    (void) tag_len;
    (void) out_context;
    (void) config;
    struct flb_metrics_context *ctx = out_context;

    msgpack_unpacked result;
    size_t off = 0;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        msgpack_object root;
        msgpack_object map;
        int i, map_size;

        root = result.data;
        /* TODO check if msgpack type is map */
        map = root.via.array.ptr[1];
        map_size = map.via.map.size;

        for (i = 0; i < map_size; i++) {
            msgpack_object key;
            msgpack_object value;
            key = map.via.map.ptr[i].key;
            value = map.via.map.ptr[i].val;
            if (flb_sds_cmp(ctx->field, key.via.str.ptr, key.via.str.size) != 0) {
                continue;
	    }
            if (value.type != MSGPACK_OBJECT_FLOAT) {
                flb_error("[metrics] input data format is not currently supported!");
                break;
            }
	    {
            char buff[2048];
            memset(buff, 0x00, sizeof(buff));
	    snprintf(buff, key.via.str.size + 1, "%s", key.via.str.ptr);
            printf("TYPE: %d, %s | %d\n", value.type, buff, key.via.str.size);
            printf("FIELD: %s\n", ctx->field);
            printf("FLOAT: %f\n", value.via.f64);
            }
        }
    }
    msgpack_unpacked_destroy(&result);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_STR, "field", NULL,
        0, FLB_TRUE, offsetof(struct flb_metrics_context, field),
        "Input field name to use for transform."
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_metrics_plugin = {
    .name         = "metrics",
    .description  = "Transform events to metrics",
    .cb_init      = cb_metrics_init,
    .cb_flush     = cb_metrics_flush,
    .config_map   = config_map,
    .flags        = 0
};
