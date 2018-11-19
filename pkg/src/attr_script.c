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
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include "attr_script.h"
#include "value_formats.h"
#include "af_log.h"
#include "attrd_attr.h"
#include "af_mempool.h"

#define ATTR_SCRIPT_FILE_NAME "/etc/af_events.conf"
#define ATTR_SCRIPT_DIR "/etc/af_attr.d/"

#define __ETYPES \
    __ETYPE_DEF(INIT,init,20) \
    __ETYPE_DEF(NOTIFY,notify,20) \
    __ETYPE_DEF(SET,set,3) \
    __ETYPE_DEF(GET,get,3) \
    __ETYPE_DEF(DEFAULT,default,5) \


#define __ETYPE_DEF(_x,_y,_z) ENTRY_TYPE_##_x,

typedef enum {
    __ETYPES
    NUM_ENTRY_TYPES
} entry_type_t;

#undef __ETYPE_DEF

#define __ETYPE_DEF(_x,_y,_z) #_y,

static char *s_entryNames[] = {
    __ETYPES
};

#undef __ETYPE_DEF

#define __ETYPE_DEF(_x,_y,_z) _z,

static int s_scriptTimeoutsSec[] = {
    __ETYPES
};

#undef __ETYPE_DEF

typedef struct script_entry_struct {
    struct script_entry_struct *next;
    uint32_t attrId;
    char *path;
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


typedef struct pid_entry_struct {
    struct pid_entry_struct *next;
    pid_t pid;
    script_entry_t *script;
    struct event *event;
    uint8_t format;
    uint8_t pad;
    uint16_t pad2;
    union {
        struct {
            struct event *pipeEvent;
            int pipeFd;
            char *value;
            uint32_t seqNum;
            uint16_t getId;
            uint16_t size;
            uint8_t done;
            uint8_t pad;
            uint16_t pad2;
        } get;
        struct {
            attr_value_t *v;
            void *a;
            char *vs;
            uint16_t clientId;
            uint16_t setId;
        } set;
        struct {
            attr_value_t *v;
            char *vs;
        } notify;
    } u;
} pid_entry_t;

static af_mempool_t *s_pidPool = NULL;
static pid_entry_t *s_pidEntries = NULL;

static struct event_base *s_base = NULL;
static struct event *s_sigchld = NULL;
static struct event *s_sighup = NULL;

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

static void add_script(entry_type_t entryType, uint32_t attrId, char *actualPath, int lineno)
{
    script_entry_t *s = (script_entry_t *)af_mempool_alloc(s_scriptPool);
    if (s != NULL) {
        memset(s, 0, sizeof(script_entry_t));

        s->attrId = attrId;
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
                if (pe->u.get.pipeEvent) {
                    event_del(pe->u.get.pipeEvent);
                    event_free(pe->u.get.pipeEvent);
                }

                if (returnStatus == AF_ATTR_STATUS_OK) {
                    if (pe->u.get.value != NULL && pe->u.get.size > 0) {
                        int sendSize = 0;

                        uint8_t *sendValue = vf_alloc_and_convert_input_value(pe->format, pe->u.get.value, &sendSize);
                        if (sendValue != NULL) {
                            send_attrd_get_response(returnStatus, pe->u.get.seqNum, pe->u.get.getId, sendValue, sendSize);
                            free(sendValue);
                        } else {
                            AFLOG_ERR("handle_sigchld_sendSize:sendSize=%d", sendSize);
                        }
                        free(pe->u.get.value);
                    } else {
                        AFLOG_WARNING("handle_sigcld_script_get_empty:path=%s,attrId=%d", pe->script->path, pe->script->attrId);
                    }
                } else {
                    send_attrd_get_response(returnStatus, pe->u.get.seqNum, pe->u.get.getId, NULL, 0);
                }
                break;
            }

            case ENTRY_TYPE_SET :
                send_attrd_set_response(returnStatus, pe->u.set.clientId, pe->u.set.setId, pe->u.set.v, pe->u.set.a);
                free(pe->u.set.vs);
                break;

            case ENTRY_TYPE_NOTIFY :
                free(pe->u.notify.vs);
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
        AFLOG_ERR("%s_strtok:line=%d,nt=%d:unable to parse entry", __func__, lineno, nt);
        return;
    }

    char typeToken = tokens[0][0];
    entry_type_t et;
    for (et = ENTRY_TYPE_INIT; et < NUM_ENTRY_TYPES; et++) {
        if (typeToken == s_entryNames[et][0]) {
            break;
        }
    }
    if (et >= NUM_ENTRY_TYPES) {
        AFLOG_ERR("%s_token:lineNum=%d,token=%s:unknown token; ignored", __func__, lineno, tokens[0]);
        return;
    }

    char *path;
    uint32_t attrId = 0;

    if (et == ENTRY_TYPE_INIT) {
        if (nt == 2) {
            path = tokens[1];
            if (path[0] != '/') {
                AFLOG_ERR("%s_init_path:line=%d:path=%s:path must be absolute", __func__, lineno, path);
                return;
            }
        } else {
            AFLOG_ERR("%s_init_nt:line=%d,nt=%d,expected=2:init entry has the incorrect number of parameters", __func__, lineno, nt);
            return;
        }
    } else {
        if (nt == 3) {
            errno = 0;
            attrId = strtoul(tokens[1], NULL, 10);
            if (errno != 0) {
                AFLOG_ERR("%s_attrId:line=%d,errno=%d:failed to convert attribute ID to uint32_t", __func__, lineno, errno);
                return;
            }
            path = tokens[2];
            if (path[0] != '/') {
                AFLOG_ERR("%s_path:line=%d:path=%s:path must be absolute", __func__, lineno, path);
                return;
            }
        } else {
            AFLOG_ERR("%s_other_nt:line=%d,nt=%d,expected=3:entry has the incorrect number of parameters", __func__, lineno, nt);
            return;
        }
    }

    char *actualPath = add_path_if_not_found(path);
    if (actualPath == NULL) {
        return;
    }

    switch (et) {
        case ENTRY_TYPE_INIT :
            add_script(et, attrId, actualPath, lineno);
            AFLOG_DEBUG2("%s_add_%s:path=%s", __func__, s_entryNames[et], actualPath);
            break;
        case ENTRY_TYPE_DEFAULT :
        case ENTRY_TYPE_NOTIFY :
            add_script(et, attrId, actualPath, lineno);
            AFLOG_DEBUG2("%s_add_%s:attrId=%d,path=%s", __func__, s_entryNames[et], attrId, actualPath);
            break;
        case ENTRY_TYPE_SET :
        case ENTRY_TYPE_GET :
            if (find_script_with_attr_id_and_type(attrId, et) == NULL) {
                add_script(et, attrId, actualPath, lineno);
                AFLOG_DEBUG2("%s_add_%s:attrId=%d,path=%s", __func__, s_entryNames[et], attrId, actualPath);
            } else {
                AFLOG_WARNING("%s_%s_dup:attrId=%d,lineno=%d:%s script for this attribute already exists; ignoring",
                __func__, s_entryNames[et], attrId, lineno, s_entryNames[et]);
            }
            break;
        default :
            break;
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
    if (pe->u.get.done) {
        return;
    }

    /* stop at the (first) newline, which is the end of the value */
    int i;
    for (i = 0; i < bytesRead; i++) {
        if (buf[i] == '\n') {
            bytesRead = i;
            pe->u.get.done = 1;
            break;
        }
    }

    if (pe->u.get.value == NULL && pe->u.get.size != 0) {
        AFLOG_ERR("on_pipe_read_size_nz:size=%d", pe->u.get.size);
        return;
    }

    /* realloc(NULL, size) is the same as malloc(size) */
    /* allow space for string termination */
    pe->u.get.value = realloc(pe->u.get.value, pe->u.get.size + bytesRead + 1);
    if (pe->u.get.value == NULL) {
        AFLOG_ERR("on_pipe_read_realloc::");
        return;
    }
    memcpy(&pe->u.get.value[pe->u.get.size], buf, bytesRead);
    pe->u.get.size += bytesRead;
    /* preemptively terminate string; note that we added a byte in the realloc for this */
    pe->u.get.value[pe->u.get.size] = '\0';
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

    argv[1] = s_entryNames[p->script->type];

    switch (p->script->type) {
        case ENTRY_TYPE_INIT :
            argv[0] = p->script->path;
            argv[2] = NULL;
            break;

        case ENTRY_TYPE_SET :
        case ENTRY_TYPE_NOTIFY :
        case ENTRY_TYPE_DEFAULT :
            if (p->script->type == ENTRY_TYPE_NOTIFY) {
                vs = vf_alloc_and_convert_output_value_for_execv(p->format, p->u.notify.v->value, p->u.notify.v->size);
                attr_value_dec_ref_count(p->u.notify.v);
            } else {
                vs = vf_alloc_and_convert_output_value_for_execv(p->format, p->u.set.v->value, p->u.set.v->size);
                /* we do not decrement the ref count because we need it to notify listeners later */
            }
            if (vs == NULL) {
                AFLOG_ERR("script_exec_convert::");
                return;
            }

            argv[0] = p->script->path;
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
            pe->u.get.pipeFd = pipeFds[0];
            struct event *ev = event_new(s_base, pipeFds[0], EV_READ | EV_PERSIST, on_pipe_read, pe);
            pe->u.get.pipeEvent = ev;
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

static void load_script(char *name, int warn)
{
    struct stat st;
    if (stat(name, &st) < 0) {
        return;
    }

    if (!S_ISREG(st.st_mode)) {
        if (warn) {
            AFLOG_WARNING("%s_ignore:node=%s,dir=%s:node not a regular file; ignoring", __func__, name, ATTR_SCRIPT_DIR);
        }
        return;
    }

    AFLOG_INFO("%s_load:name=%s", __func__, name);

    FILE *f = fopen(name, "r");
    if (f == NULL) {
        return;
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
}

static int reload_scripts(void)
{
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

    load_script(ATTR_SCRIPT_FILE_NAME, 0);
    DIR *dir = opendir(ATTR_SCRIPT_DIR);
    if (dir) {
        struct dirent *ent;
        char buf[1024];
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] != '.') {
                sprintf(buf, "%s%s", ATTR_SCRIPT_DIR, ent->d_name);
                load_script(buf, 1);
            }
        }
        closedir(dir);
    } else {
        AFLOG_INFO("%s_opendir:errno=%d,dir=%s:ignoring directory", __func__, errno, ATTR_SCRIPT_DIR);
    }

    return 0;

error:
    clean_pools();

    return -1;
}

static void handle_sighup(evutil_socket_t fd, short what, void *context)
{
    AFLOG_INFO("%s::sighup received", __func__);
    if (reload_scripts() < 0) {
        AFLOG_ERR("%s_reload_err:errno=%d", __func__, errno);
    }
}

/* public API */

int script_setup(struct event_base *base)
{
    if (base == NULL) {
        errno = EINVAL;
        return -1;
    }
    s_base = base;

    /* register the SIGHUP event handler */
    if (s_sighup == NULL) {
        s_sighup = evsignal_new(s_base, SIGHUP, handle_sighup, NULL);
        if (s_sighup == NULL) {
            AFLOG_ERR("%s_sighup:errno=%d", __func__, errno);
            goto error;
        }
        event_add(s_sighup, NULL);
    }

    /* register the SIGCHLD event handler */
    if (s_sigchld == NULL) {
        s_sigchld = evsignal_new(s_base, SIGCHLD, handle_sigchld, NULL);
        if (s_sigchld == NULL) {
            AFLOG_ERR("%s_sigchld:errno=%d", __func__, errno);
            goto error;
        }
        event_add(s_sigchld, NULL);
    }

    if (reload_scripts() < 0) {
        goto error;
    }

    return 0;

error:
    if (s_sighup) {
        event_free(s_sighup);
        s_sighup = NULL;
    }
    if (s_sigchld) {
        event_free(s_sigchld);
        s_sigchld = NULL;
    }

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

void script_notify(attr_value_t *v, af_attr_type_t aType)
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
            p.format = aType;
            /* hold a reference until script finishes */
            attr_value_inc_ref_count(v);
            p.u.notify.v = v;
            script_exec(&p);
        }
    }
}

int script_owner_set(uint16_t clientId, uint16_t setId, attr_value_t *v, af_attr_type_t aType, void *a)
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
        p.format = aType;
        p.u.set.clientId = clientId;
        p.u.set.setId = setId;

        /* increment the attribute value ref count; we'll decrement when script finishes */
        attr_value_inc_ref_count(v);
        p.u.set.v = v;
        p.u.set.a = a;

        script_exec(&p);
        return 0;
    } else {
        return -1;
    }
}

int script_get(uint32_t attrId, uint32_t seqNum, uint16_t getId, af_attr_type_t aType)
{
    script_entry_t *e = find_script_with_attr_id_and_type(attrId, ENTRY_TYPE_GET);
    if (e) {
        pid_entry_t p;
        memset(&p, 0, sizeof(p));

        p.script = e;
        p.format = aType;
        p.u.get.value = NULL;
        p.u.get.size = 0;
        p.u.get.seqNum = seqNum;
        p.u.get.getId = getId;

        script_exec(&p);
        return 0;
    } else {
        return -1;
    }
}

void script_notify_default(uint32_t attrId, af_attr_type_t aType, uint8_t *value, uint16_t size)
{
    attr_value_t *av = NULL;
    for (script_entry_t *e = s_scripts; e; e = e->next) {
        if (e->type == ENTRY_TYPE_DEFAULT && e->attrId == attrId) {
            if (!av) {
                av = attr_value_create_with_value(attrId, value, size);
                if (!av) {
                    return;
                }
            }
            pid_entry_t p;
            memset(&p, 0, sizeof(p));

            p.script = e;
            p.format = aType;
            /* hold a reference until script finishes */
            attr_value_inc_ref_count(av);
            p.u.notify.v = av;
            script_exec(&p);
        }
    }
    if (av) {
        attr_value_dec_ref_count(av);
    }
}

void script_dump(void)
{
    AFLOG_DEBUG3("SCRIPT_DUMP");
    for (script_entry_t *s = s_scripts; s; s = s->next) {
        if (s->type == ENTRY_TYPE_INIT) {
            AFLOG_DEBUG3("  %s:path=%s", s_entryNames[s->type], s->path);
        } else {
            AFLOG_DEBUG3("  %s:attrId=%d,path=%s", s_entryNames[s->type], s->attrId, s->path);
        }
    }
    AFLOG_DEBUG3("END_OF_SCRIPTS");
}

