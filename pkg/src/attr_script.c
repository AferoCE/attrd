/*
 * file attr_script.c -- attribute script handler code
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "attr_script.h"
#include "value_formats.h"
#include "af_log.h"
#include "attrd_attr.h"
#include "af_mempool.h"

#define ATTR_SCRIPT_FILE_NAME "/etc/af_events.conf"

typedef enum {
    ENTRY_TYPE_INIT = 0,
    ENTRY_TYPE_NOTIFY,
    ENTRY_TYPE_SET,
    ENTRY_TYPE_GET
} entry_type_t;

typedef struct script_entry_struct {
    struct script_entry_struct *next;
    uint32_t attrId;
    char *path;
    value_format_t format;
    entry_type_t type;
} script_entry_t;

typedef struct path_entry_struct {
    struct path_entry_struct *next;
    char *path;
} path_entry_t;

/* these need to be freed upon cleanup */
static af_mempool_t *s_pathPool = NULL;
static path_entry_t *s_paths = NULL;

static af_mempool_t *s_scriptPool = NULL;
static script_entry_t *s_scripts = NULL;

static int s_scriptTimeoutsSec[] = {
    20, /* init */
    20, /* notify */
    3,  /* set */
    3   /* get */
};

typedef struct pid_entry_struct {
    struct pid_entry_struct *next;
    pid_t pid;
    script_entry_t *script;
    struct event *event;
    union {
        struct {
            struct event *pipeEvent;
            int pipeFd;
            char *value;
            uint32_t seqNum;
            uint16_t getId;
            uint16_t size;
            uint8_t done;
        } g;
        struct {
            attr_value_t *v;
            void *a;
            char *vs;
            uint16_t clientId;
            uint16_t setId;
        } s;
        struct {
            attr_value_t *v;
            char *vs;
        } n;
    } u;
} pid_entry_t;

static af_mempool_t *s_pidPool = NULL;
static pid_entry_t *s_pidEntries = NULL;

static struct event_base *s_base = NULL;
static struct event *s_sigchld = NULL;

static char *find_path(char *path)
{
    path_entry_t *p;
    for (p = s_paths; p; p = p->next) {
        if (strcmp(path, p->path) == 0) {
            return p->path;
        }
    }
    return NULL;
}

static char *add_path_if_not_found(char *path)
{
    char *actualPath = find_path(path);
    if (actualPath == NULL) {
        path_entry_t *p = (path_entry_t *)af_mempool_alloc(s_pathPool);
        if (p != NULL) {
            actualPath = strdup(path);
            if (actualPath == NULL) {
                AFLOG_ERR("add_path_if_not_found_strdup::can't allocate path string");
                af_mempool_free(p);
                actualPath = NULL;
            }
            p->path = actualPath;

            /* add to head of list */
            p->next = s_paths;
            s_paths = p;
        } else {
            AFLOG_ERR("add_path_if_not_found_full::path table is full");
            actualPath = NULL;
        }
    }
    return actualPath;
}

static void free_paths(void)
{
    path_entry_t *p;

    for (p = s_paths; p; p = p->next) {
        free(p->path);
    }
    s_paths = NULL;

    af_mempool_destroy(s_pathPool);
    s_pathPool = NULL;
}

static void add_script(entry_type_t entryType, uint32_t attrId, value_format_t format, char *actualPath, int lineno)
{
    script_entry_t *s = (script_entry_t *)af_mempool_alloc(s_scriptPool);
    if (s != NULL) {
        memset(s, 0, sizeof(script_entry_t));

        s->attrId = attrId;
        s->format = format;
        s->path = actualPath;
        s->type = entryType;

        /* add to head of list */
        s->next = s_scripts;
        s_scripts = s;
    } else {
        AFLOG_ERR("add_script_full:lineno=%d:script table is full", lineno);
    }
}

static void free_scripts(void)
{
    af_mempool_destroy(s_scriptPool);
    s_scriptPool = NULL;
    s_scripts = NULL;
}

static void free_pids(void)
{
    af_mempool_destroy(s_pidPool);
    s_pidPool = NULL;
    s_scripts = NULL;
}

static script_entry_t *find_script_with_attr_id_and_type(uint32_t attrId, entry_type_t entryType)
{
    script_entry_t *e;

    for (e = s_scripts; e != NULL; e = e->next) {
        if (e->attrId == attrId && e->type == entryType) {
            return e;
        }
    }
    return NULL;
}

static pid_entry_t *find_pid_entry(pid_t pid)
{
    pid_entry_t *pe;

    for (pe = s_pidEntries; pe != NULL; pe = pe->next) {
        if (pe->pid == pid) {
            return pe;
        }
    }
    return NULL;
}

static void remove_pid(pid_entry_t *dp)
{
    pid_entry_t *last = NULL, *pe;
    for (pe = s_pidEntries; pe; pe = pe->next) {
        if (pe == dp) {
            if (last != NULL) {
                last->next = pe->next;
            } else {
                s_pidEntries = pe->next;
            }
            af_mempool_free(pe);
            return;
        }
        last = pe;
    }
    AFLOG_ERR("remove_pid_not_found::removing pid that doesn't exist");
}

static void handle_sigchld(evutil_socket_t fd, short what, void *arg)
{
    /* find available pids */
    pid_t pid;
    int status;

    AFLOG_DEBUG3("handle_sigchld_received");
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pid_entry_t *pe = find_pid_entry(pid);
        if (pe == NULL) {
            AFLOG_ERR("handle_sigchld_pid:pid=%d:unknown pid", pid);
            continue;
        }
        AFLOG_DEBUG3("handle_sigchld_pid_found:path=%s,status=%d", pe->script->path, status);

        /* get the exit status */
        uint8_t returnStatus = AF_ATTR_STATUS_UNSPECIFIED;
        if (WIFEXITED(status)) {
            int exitStatus = WEXITSTATUS(status);
            if (exitStatus > AF_ATTR_STATUS_MAX) {
                AFLOG_WARNING("handle_sigchld_script_failed:errno=%d", exitStatus - AF_ATTR_STATUS_MAX);
                returnStatus = AF_ATTR_STATUS_UNSPECIFIED;
            } else if (exitStatus != 0) {
                AFLOG_WARNING("handle_sigchld_status:status=%d", exitStatus);
                returnStatus = exitStatus;
            } else {
                returnStatus = AF_ATTR_STATUS_OK;
            }
        } else if (WIFSIGNALED(status)) {
            /* assume a timeout */
            returnStatus = AF_ATTR_STATUS_TIMEOUT;
            AFLOG_WARNING("handle_sigchld_timeout:path=%s", pe->script->path);
        } else {
            AFLOG_WARNING("handle_sigchld_not_exited:status=%d", status);
        }

        /* clean up the timeout event */
        if (pe->event) {
            event_del(pe->event);
            event_free(pe->event);
        }

        switch (pe->script->type) {
            case ENTRY_TYPE_GET : {
                /* shut down the pipe event */
                if (pe->u.g.pipeEvent) {
                    event_del(pe->u.g.pipeEvent);
                    event_free(pe->u.g.pipeEvent);
                }

                if (returnStatus == AF_ATTR_STATUS_OK) {
                    if (pe->u.g.value != NULL && pe->u.g.size > 0) {
                        int sendSize = 0;

                        uint8_t *sendValue = vf_alloc_and_convert_input_value(pe->script->format, pe->u.g.value, &sendSize);
                        if (sendValue != NULL) {
                            send_attrd_get_response(returnStatus, pe->u.g.seqNum, pe->u.g.getId, sendValue, sendSize);
                            free(sendValue);
                        } else {
                            AFLOG_ERR("handle_sigchld_sendSize:sendSize=%d", sendSize);
                        }
                        free(pe->u.g.value);
                    } else {
                        AFLOG_WARNING("handle_sigcld_script_get_empty:path=%s,attrId=%d", pe->script->path, pe->script->attrId);
                    }
                } else {
                    send_attrd_get_response(returnStatus, pe->u.g.seqNum, pe->u.g.getId, NULL, 0);
                }
                break;
            }

            case ENTRY_TYPE_SET :
                send_attrd_set_response(returnStatus, pe->u.s.clientId, pe->u.s.setId, pe->u.s.v, pe->u.s.a);
                free(pe->u.s.vs);
                break;

            case ENTRY_TYPE_NOTIFY :
                free(pe->u.n.vs);
                break;

            default :
                break;
        }

        /* remove pid from list */
        remove_pid(pe);
    }
}

static void handle_line(int lineno, char **tokens, int nt)
{
    if (nt < 1) {
        AFLOG_ERR("handle_line_strtok:line=%d,nt=%d:unable to parse entry", lineno, nt);
        return;
    }

    char typeToken = tokens[0][0];
    if (typeToken == 'i' || typeToken == 'n' || typeToken == 's' || typeToken == 'g') {

        char *path;
        value_format_t format = VALUE_FORMAT_UNKNOWN;
        uint32_t attrId = 0;

        if (typeToken == 'i') {
            if (nt == 2) {
                path = tokens[1];
            } else {
                AFLOG_ERR("handle_line_init_nt:line=%d,nt=%d,expected=2:init entry has the incorrect number of parameters", lineno, nt);
                return;
            }
        } else {
            if (nt == 4) {
                errno = 0;
                attrId = strtoul(tokens[1], NULL, 10);
                if (errno != 0) {
                    AFLOG_ERR("handle_line_attrId:line=%d,errno=%d:failed to convert attribute ID to uint32_t", lineno, errno);
                    return;
                }
                if (attrId < 1024) {
                    AFLOG_DEBUG3("handle_line_edge:line=%d,attrId=%d:edge attribute ignored", lineno, attrId);
                    return;
                }
                format = vf_get_format_for_name(tokens[2]);
                if (format == VALUE_FORMAT_UNKNOWN) {
                    AFLOG_ERR("handle_line_format:line=%d:format=%s:value format is unknown", lineno, tokens[2]);
                    return;
                }
                path = tokens[3];
                if (path[0] != '/') {
                    AFLOG_ERR("handle_line_path:line=%d:path=%s:path must be absolute", lineno, path);
                    return;
                }
            } else {
                AFLOG_ERR("handle_line_other_nt:line=%d,nt=%d,expected=4:entry has the incorrect number of parameters", lineno, nt);
                return;
            }
        }

        char *actualPath = add_path_if_not_found(path);
        if (actualPath == NULL) {
            return;
        }

        switch (typeToken) {
            case 'i' :
                add_script(ENTRY_TYPE_INIT, attrId, format, actualPath, lineno);
                AFLOG_DEBUG3("handle_line_add_init:path=%s", actualPath);
                break;
            case 'n' :
                add_script(ENTRY_TYPE_NOTIFY, attrId, format, actualPath, lineno);
                AFLOG_DEBUG3("handle_line_add_notify:attrId=%d,format=%s,path=%s", attrId, vf_get_name_for_format(format), actualPath);
                break;
            case 's' :
                if (find_script_with_attr_id_and_type(attrId, ENTRY_TYPE_SET) == NULL) {
                    add_script(ENTRY_TYPE_SET, attrId, format, actualPath, lineno);
                    AFLOG_DEBUG3("handle_line_add_set:attrId=%d,format=%s,path=%s", attrId, vf_get_name_for_format(format), actualPath);
                } else {
                    AFLOG_WARNING("handle_line_set_dup:attrId=%d,lineno=%d:set script for this attribute already exists; ignoring", attrId, lineno);
                }
                break;
            case 'g' :
                if (find_script_with_attr_id_and_type(attrId, ENTRY_TYPE_GET) == NULL) {
                    add_script(ENTRY_TYPE_GET, attrId, format, actualPath, lineno);
                    AFLOG_DEBUG3("handle_line_add_get:attrId=%d,format=%s,path=%s", attrId, vf_get_name_for_format(format), actualPath);
                } else {
                    AFLOG_WARNING("handle_line_get_dup:attrId=%d,lineno=%d:get script for this attribute already exists; ignoring", attrId, lineno);
                }
                break;
            default :
                break;
        }

    } else {
        AFLOG_ERR("handle_line_token:lineNum=%d,token=%s:unknown token", lineno, tokens[0]);
    }
}

static int tokenize(char *line, char **tokenArray, int tokenArraySize)
{
    if (line == NULL || tokenArray == NULL || tokenArraySize <= 0) {
        AFLOG_ERR("tokenize_param:line_NULL=%d,tokenArray_NULL=%d,tokenArraySize=%d", line==NULL, tokenArray==NULL, tokenArraySize);
        errno = EINVAL;
        return -1;
    }

    char *save = NULL;
    int i;

    for (i = 0; i < tokenArraySize; i++) {
        tokenArray[i] = (i == 0 ? strtok_r(line, " ", &save) : strtok_r(NULL, " ", &save));
        if (tokenArray[i] == NULL) {
            break;
        }
    }
    return i;
}

#define VALUE_BLOCK_SIZE 4096

static void on_pipe_read(evutil_socket_t fd, short what, void *arg)
{
    if (arg == NULL) {
        AFLOG_ERR("on_pipe_read_null::");
        return;
    }

    pid_entry_t *pe = (pid_entry_t *)arg;

    if (pe->script->type != ENTRY_TYPE_GET) {
        AFLOG_ERR("on_pipe_read_type:type=%d", pe->script->type);
        return;
    }

    char buf[VALUE_BLOCK_SIZE];

    int bytesRead = read(fd, buf, sizeof(buf));
    if (bytesRead < 0) {
        AFLOG_ERR("on_pipe_read_read:errno=%d:read failed", errno);
        return;
    } else if (bytesRead == 0) { /* EOF */
        return;
    }

    /* if we've already finished reading the value, ignore the rest */
    if (pe->u.g.done) {
        return;
    }

    /* stop at the (first) newline, which is the end of the value */
    int i;
    for (i = 0; i < bytesRead; i++) {
        if (buf[i] == '\n') {
            bytesRead = i;
            pe->u.g.done = 1;
            break;
        }
    }

    if (pe->u.g.value == NULL && pe->u.g.size != 0) {
        AFLOG_ERR("on_pipe_read_size_nz:size=%d", pe->u.g.size);
        return;
    }

    /* realloc(NULL, size) is the same as malloc(size) */
    /* allow space for string termination */
    pe->u.g.value = realloc(pe->u.g.value, pe->u.g.size + bytesRead + 1);
    if (pe->u.g.value == NULL) {
        AFLOG_ERR("on_pipe_read_realloc::");
        return;
    }
    memcpy(&pe->u.g.value[pe->u.g.size], buf, bytesRead);
    pe->u.g.size += bytesRead;
    /* preemptively terminate string; note that we added a byte in the realloc for this */
    pe->u.g.value[pe->u.g.size] = '\0';
}

static void on_pid_timeout(evutil_socket_t fd, short what, void *arg)
{
    if (arg != NULL) {
        pid_entry_t *pe = (pid_entry_t *)arg;

        /* kill the slow script and let waitpid handle the rest */
        kill(pe->pid, SIGTERM);
    }
}

#define SCRIPT_TIMEOUT (3)
static void script_exec(pid_entry_t *p)
{
    if (p == NULL) {
        AFLOG_ERR("script_exec_param:p_NULL=%d", p==NULL);
        return;
    }

    AFLOG_DEBUG3("script_exec_execute:path=%s,type=%d,attrId=%d",p->script->path,p->script->type,p->script->attrId);

    char attrNumBuf[10];
    sprintf(attrNumBuf, "%u", p->script->attrId);

    char *argv[5];
    char *vs = NULL;

    int pipeFds[2];

    switch (p->script->type) {
        case ENTRY_TYPE_INIT :
            argv[0] = p->script->path;
            argv[1] = "init";
            argv[2] = NULL;
            break;

        case ENTRY_TYPE_SET :
        case ENTRY_TYPE_NOTIFY :
            if (p->script->type == ENTRY_TYPE_NOTIFY) {
                vs = vf_alloc_and_convert_output_value_for_execv(p->script->format, p->u.n.v->value, p->u.n.v->size);
                attr_value_dec_ref_count(p->u.n.v);
            } else {
                vs = vf_alloc_and_convert_output_value(p->script->format, p->u.s.v->value, p->u.s.v->size);
                /* we do not decrement the ref count because we need it to notify listeners later */
            }
            if (vs == NULL) {
                AFLOG_ERR("script_exec_convert::");
                return;
            }

            argv[0] = p->script->path;
            argv[1] = (p->script->type == ENTRY_TYPE_NOTIFY ? "notify" : "set");
            argv[2] = attrNumBuf;
            argv[3] = vs;
            argv[4] = NULL;
            break;

        case ENTRY_TYPE_GET :
            if (pipe(pipeFds) < 0) {
                AFLOG_ERR("script_exec_pipe:errno=%d:can't create pipe", errno);
                return;
            }

            argv[0] = p->script->path;
            argv[1] = "get";
            argv[2] = attrNumBuf;
            argv[3] = NULL;
            break;

        default :
            AFLOG_ERR("script_exec_type:type=%d", p->script->type);
            return;
    }

    int pid = fork();
    if (pid == 0) {
        if (p->script->type == ENTRY_TYPE_GET) {
            dup2(pipeFds[1], STDOUT_FILENO);
            close(pipeFds[0]);
            close(pipeFds[1]);
        }

        /* This is the child */
        AFLOG_DEBUG2("script_exec_executing:argv[0]=%s", argv[0]);
        int res = execv(argv[0], argv);

        if (res < 0) {
            exit(errno + AF_ATTR_STATUS_MAX);
        }

        return; /* this will never happen */
    } else {
        /* this is the parent; pid = process ID of child */

        /* add the pid to the table */
        pid_entry_t *pe = af_mempool_alloc(s_pidPool);
        if (pe == NULL) {
            AFLOG_ERR("script_exec_pid_full::pid table is full");
            return;
        }

        memcpy(pe, p, sizeof(pid_entry_t));
        pe->pid = pid;

        /* add to head of list */
        pe->next = s_pidEntries;
        s_pidEntries = pe;

        /* set up event to read incoming data */
        if (p->script->type == ENTRY_TYPE_GET) {
            /* close the write fd */
            close(pipeFds[1]);

            /* Add an event for the fd[0] */
            pe->u.g.pipeFd = pipeFds[0];
            struct event *ev = event_new(s_base, pipeFds[0], EV_READ | EV_PERSIST, on_pipe_read, pe);
            pe->u.g.pipeEvent = ev;
            if (ev == NULL) {
                AFLOG_ERR("script_exec_pipe_event::failed to allocate event");
                /* we're in a low memory situation and don't attempt to clean up at this point */
                return;
            }
            event_add(ev, NULL);
        }

        /* allocate a timer */
        pe->event = evtimer_new(s_base, on_pid_timeout, pe);
        if (pe->event == NULL) {
            AFLOG_ERR("script_exec_timer::failed to allocate a timer");
            /* we're in a low memory situation and don't attempt to clean up at this point */
            return;
        }
        struct timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = s_scriptTimeoutsSec[p->script->type];
        evtimer_add(pe->event, &tv);
    }
}

static void clean_pools(void)
{
    if (s_scriptPool != NULL) {
        free_scripts();
    }

    if (s_pathPool != NULL) {
        free_paths();
    }

    if (s_pidPool != NULL) {
        free_pids();
    }
}

/* public API */

int script_parse_config(struct event_base *base)
{
    if (base == NULL) {
        errno = EINVAL;
        return -1;
    }
    s_base = base;

    /* if scripts are currently running exit immediately */
    if (s_pidEntries != NULL) {
        AFLOG_ERR("reload_scripts_in_progress:pid=%d", s_pidEntries->pid);
        errno = EBUSY;
        return -1;
    }

    /* destroy any existing mempools */
    clean_pools();

    /* create mempools */
    s_scriptPool = af_mempool_create(16, sizeof(script_entry_t), AF_MEMPOOL_FLAG_EXPAND);
    if (s_scriptPool == NULL) {
        AFLOG_ERR("reload_scripts_script_create:errno=%d", errno);
        goto error;
    }

    s_pathPool = af_mempool_create(8, sizeof(path_entry_t), AF_MEMPOOL_FLAG_EXPAND);
    if (s_pathPool == NULL) {
        AFLOG_ERR("reload_scripts_path_create:errno=%d", errno);
        goto error;
    }

    s_pidPool = af_mempool_create(8, sizeof(pid_entry_t), AF_MEMPOOL_FLAG_EXPAND);
    if (s_pidPool == NULL) {
        AFLOG_ERR("reload_scripts_pid_create:errno=%d", errno);
        goto error;
    }

    FILE *f;

    f = fopen(ATTR_SCRIPT_FILE_NAME, "r");
    if (f == NULL) {
        AFLOG_ERR("reload_scripts_open:errno=%d", errno);
        goto error;
    }

    char buf[1024];
    int lineno = 1;
    char *line;
    while ((line = fgets(buf, sizeof(buf), f)) != NULL) {
        /* chop off the trailing newline */
        char *cp = line;
        while (*cp) {
            if (*cp == '\n') {
                *cp = '\0';
                break;
            }
            cp++;
        }

        /* search for first non whitespace character */
        cp = line;
        while (isspace(*cp) && *cp != '\0') cp++;

        /* if none or comment, skip line */
        if (*cp == '\0' || *cp == '#') {
            continue;
        }

        char *tokens[4];
        int nt = tokenize(line, tokens, sizeof(tokens)/sizeof(tokens[0]));
        handle_line(lineno, tokens, nt);
        lineno++;
    }
    fclose(f);

    if (s_sigchld == NULL) {
        /* register the SIGCHLD event handler */
        s_sigchld = evsignal_new(s_base, SIGCHLD, handle_sigchld, NULL);
        if (s_sigchld == NULL) {
            AFLOG_ERR("reload_scripts_sigchld");
            goto error;
        }
        event_add(s_sigchld, NULL);
    }

    return 0;

error:
    clean_pools();

    return -1;
}

void script_init(void)
{
    script_entry_t *e;
    for (e = s_scripts; e; e = e->next) {
        if (e->path && e->type == ENTRY_TYPE_INIT) {
            pid_entry_t p;
            memset(&p, 0, sizeof(p));

            p.script = e;
            script_exec(&p);
        }
    }
}

void script_notify(attr_value_t *v)
{
    if (v == NULL) {
        AFLOG_ERR("script_notify_NULL");
        return;
    }

    script_entry_t *e;

    /* execute all scripts interested in this attribute */
    for (e = s_scripts; e; e = e->next) {
        if (e->attrId == v->attrId && e->type == ENTRY_TYPE_NOTIFY) {
            pid_entry_t p;
            memset(&p, 0, sizeof(p));

            p.script = e;
            /* hold a reference until script finishes */
            attr_value_inc_ref_count(v);
            p.u.n.v = v;
            script_exec(&p);
        }
    }
}

int script_owner_set(uint16_t clientId, uint16_t setId, attr_value_t *v, void *a)
{
    if (v == NULL || a == NULL) {
        AFLOG_ERR("script_owner_set_param:v_NULL=%d,a_NULL=%d", v==NULL, a==NULL);
        return -1;
    }
    script_entry_t *e = find_script_with_attr_id_and_type(v->attrId, ENTRY_TYPE_SET);
    if (e) {

        pid_entry_t p;
        memset(&p, 0, sizeof(p));

        p.script = e;
        p.u.s.clientId = clientId;
        p.u.s.setId = setId;

        /* increment the attribute value ref count; we'll decrement when script finishes */
        attr_value_inc_ref_count(v);
        p.u.s.v = v;
        p.u.s.a = a;

        script_exec(&p);
        return 0;
    } else {
        return -1;
    }
}

int script_get(uint32_t attrId, uint32_t seqNum, uint16_t getId)
{
    script_entry_t *e = find_script_with_attr_id_and_type(attrId, ENTRY_TYPE_GET);
    if (e) {
        pid_entry_t p;
        memset(&p, 0, sizeof(p));

        p.script = e;
        p.u.g.value = NULL;
        p.u.g.size = 0;
        p.u.g.seqNum = seqNum;
        p.u.g.getId = getId;

        script_exec(&p);
        return 0;
    } else {
        return -1;
    }
}

