#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sysrepo.h>
#include <libyang/libyang.h>

sr_session_ctx_t *sess;
sr_subscription_ctx_t *subscription;

char *get_date_output()
{
    FILE *fp;
    char buffer[128];         // Temporary buffer to hold the command output
    size_t output_size = 128; // Initial buffer size for the final output
    size_t used_size = 0;     // Keeps track of the used size in the final buffer

    // Allocate memory for the final output buffer
    char *output = (char *)malloc(output_size);
    if (output == NULL)
    {
        perror("malloc");
        return NULL;
    }

    // Open the command for reading
    fp = popen("date", "r");
    if (fp == NULL)
    {
        perror("popen");
        free(output);
        return NULL;
    }

    // Read the output of the command
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        size_t len = strlen(buffer);
        // Check if the final buffer needs to be resized
        if (used_size + len + 1 > output_size)
        {
            output_size *= 2;
            char *temp = (char *)realloc(output, output_size);
            if (temp == NULL)
            {
                perror("realloc");
                free(output);
                pclose(fp);
                return NULL;
            }
            output = temp;
        }
        // Append the buffer content to the final output
        strcpy(output + used_size, buffer);
        used_size += len;
    }

    // Close the pipe
    pclose(fp);

    return output;
}

int set_time(const char *time_str)
{
    char cmd[sizeof("timedatectl set-ntp no; timedatectl set-time ") + 8];
    snprintf(cmd, sizeof(cmd), "timedatectl set-ntp no; timedatectl set-time %s", time_str);
    int result = system(cmd);
    return result;
}

static int set_time_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    int res = set_time(input[0].data.string_val);
    return res;
}

static int sync_time_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                        const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                        void *private_data)
{
    (void)input;
    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    int result = system("timedatectl set-ntp yes");
    if (result != 0)
    {
        return SR_ERR_INTERNAL;
    }
    return SR_ERR_OK;
}

static int get_time_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    char *datetime = get_date_output();
    if (datetime == NULL)
    {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:get-time/time");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = datetime;
    return SR_ERR_OK;
}

char *get_command_output(const char *command)
{
    FILE *fp;
    char buffer[1024];        // Temporary buffer to hold the command output
    size_t output_size = 1024; // Initial buffer size for the final output
    size_t used_size = 0;     // Keeps track of the used size in the final buffer

    // Allocate memory for the final output buffer
    char *output = (char *)malloc(output_size);
    if (output == NULL)
    {
        perror("malloc");
        return NULL;
    }

    // Open the command for reading
    fp = popen(command, "r");
    if (fp == NULL)
    {
        perror("popen");
        free(output);
        return NULL;
    }

    // Read the output of the command
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        size_t len = strlen(buffer);
        // Check if the final buffer needs to be resized
        if (used_size + len + 1 > output_size)
        {
            output_size = used_size + len + 1; // Ensure enough space for new data and null terminator
            char *temp = (char *)realloc(output, output_size);
            if (temp == NULL)
            {
                perror("realloc");
                free(output);
                pclose(fp);
                return NULL;
            }
            output = temp;
        }
        // Append the buffer content to the final output
        memcpy(output + used_size, buffer, len);
        used_size += len;
    }

    // Null-terminate the final output buffer
    output[used_size] = '\0';

    // Close the pipe
    if (pclose(fp) == -1)
    {
        perror("pclose");
        free(output);
        return NULL;
    }

    return output;
}

static int get_uptime_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    char *out = get_command_output("uptime");
    if (out == NULL)
    {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:uptime/out");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = out;
    return SR_ERR_OK;
}

static int get_freeg_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    char *out = get_command_output("free -g");
    if (out == NULL)
    {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:freeg/out");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = out;
    return SR_ERR_OK;
}

static int get_lscpu_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    char *out = get_command_output("lscpu");
    if (out == NULL)
    {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:lscpu/out");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = out;
    return SR_ERR_OK;
}

static int get_top_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
                       const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
                       void *private_data)
{
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    char *out = get_command_output("top -b -n 1");
    if (out == NULL)
    {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:top/out");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = out;
    return SR_ERR_OK;
}
char *get_server_ip() {
    char *cmd = "ifconfig | grep -Eo 'inet (addr:)?([0-9]*\\.){3}[0-9]*' | grep -Eo '([0-9]*\\.){3}[0-9]*' | grep -v '127.0.0.1'";
    char *ip = malloc(INET_ADDRSTRLEN);
    FILE *fp;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return NULL;
    }

    if (fgets(ip, INET_ADDRSTRLEN, fp) == NULL) {
        perror("fgets");
        pclose(fp);
        return NULL;
    }

    // Remove newline character if present
    ip[strcspn(ip, "\n")] = 0;

    pclose(fp);
    return ip;
}

/* Callback for the get-ip RPC */
static int
get_ip_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *path, const sr_val_t *input,
          const size_t input_cnt, sr_event_t event, uint32_t request_id, sr_val_t **output, size_t *output_cnt,
          void *private_data)
{
    char *ip;
    sr_val_t *output_val;

    (void)sub_id;
    (void)path;
    (void)input;
    (void)input_cnt;
    (void)event;
    (void)request_id;
    (void)private_data;

    ip = get_server_ip();
    if (!ip) {
        return SR_ERR_INTERNAL;
    }

    *output_cnt = 1;
    *output = calloc(1, sizeof(**output));
    output_val = *output;

    output_val->xpath = strdup("/ASELSAN-Sysrepo-OS-Metrics:get-ip/ip-address");
    output_val->type = SR_STRING_T;
    output_val->data.string_val = ip;

    return SR_ERR_OK;
}

int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
    int rc;

    sess = session;

    /* Subscribe to get-ip RPC */
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:freeg", get_freeg_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:uptime", get_uptime_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:lscpu", get_lscpu_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:top", get_top_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:set-time", set_time_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:get-time", get_time_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:sync-time", sync_time_cb, NULL, 0, 0, &subscription);
    rc = sr_rpc_subscribe(session, "/ASELSAN-Sysrepo-OS-Metrics:get-ip", get_ip_cb, NULL, 0, 0, &subscription);
    if (rc != SR_ERR_OK)
    {
        SRPLG_LOG_ERR("server", "Server plugin initialization failed: %s.", sr_strerror(rc));
        return rc;
    }

    SRPLG_LOG_DBG("server", "Server plugin initialized successfully.");
    return SR_ERR_OK;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
    (void)session;
    (void)private_data;

    sr_unsubscribe(subscription);
    SRPLG_LOG_DBG("server", "Server plugin cleanup finished.");
}
