#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <string.h>

#include "lib/config.h"
#include "lib/lbucket.h"
#include "lib/memory.h"
#include "lib/session.h"
#include "lib/session_private.h"

#define DEBUG_TITLE "main: "
#include "lib/log.h"

#define SESSIONS_S_EXPORT_NAME     "Sessions_sym"
#define SESSIONS_A_EXPORT_NAME     "Sessions_asym"

#define str(s) #s

/* Global variables */
bool count_empty = false;

/* Types definitions */
enum modes {
	MODE_NONE = 0,
	MODE_SYM,
	MODE_ASYM
};


#define PROTOS_LIST \
    X(tcp, 6) \
    X(udp, 17) \
    X(icmp, 1) \
    X(gre, 47) \
    X(ipip, 4) \
    X(esp, 50) \
    X(ah, 51) \
    X(sctp, 132) \
    X(ospf, 89) \
    X(swipe, 53) \
    X(tlsp, 56) \
    X(compaq_peer, 110)

#define X(name, value) uint32_t name;
struct protocols_statistics {
    PROTOS_LIST
};
#undef X


#define STATES_LIST \
    X(CLOSING, 2) \
    X(SYN_IN, 4) \
    X(SYN_OUT, 8) \
    X(VALID_CONFIRMED, 32) \
    X(VALID, 64)

#define X(name, value) uint32_t name;
struct states_statistics {
    STATES_LIST
};
#undef X

struct statistics {
    uint64_t total_sessions;
    uint64_t total_lines;
    uint64_t full_masks;
    uint64_t full_lines;
    uint64_t old_sessions;
    uint64_t unknown_old;
    struct states_statistics old_state_stats;
    struct states_statistics valid_state_stats;
    struct protocols_statistics old_proto_stats;
    struct protocols_statistics valid_proto_stats;
    uint64_t modes[PIE_SES_BUCKET_SIZE + 1];
    uint32_t ips[PIE_VALID_SESSIONS_HASH_SIZE * PIE_SES_BUCKET_SIZE];
    uint64_t ips_count;
};

static void proto_state_count(uint16_t proto,
                              uint16_t state,
                              struct protocols_statistics* prot_stat,
                              struct states_statistics* state_stat)
{
#define X(name, value) case value: prot_stat->name++; break;
    switch ( proto ) {
        PROTOS_LIST
        default:
            break;
    }
#undef X

#define X(name, value) case value: state_stat->name++; break;
    switch ( state ) {
        STATES_LIST
        default:
            break;
    }
#undef X
}

//TODO: Надо упростить написание подобных программ вынесением заголовочных
// файлов в какую-нибудь стандартную директорию  /usr/local/include. Кроме
// того некоторые вещи вроде time.c и memory.c можно засунуть в заголовочный
// файл.

static void analyze_sessions(struct valid_sessions* sessions_array,
                    struct statistics* st,
                    bool print)
{
    struct session* sessions;
    lbucket_t* buckets;
    mask_t mask;
    uint64_t time;

    st->total_sessions = 0;
    st->total_lines = PIE_VALID_SESSIONS_HASH_SIZE;

    if (!print) {
        fprintf(stderr, "Time now %" PRIx64 ", hz  %" PRIx64 "\n", T_NOW,
                TIME_1SEC);
    }
    else {
        fprintf(stdout,
                "hash_index,index,mask,"
                "s.saddr,s.daddr,s.state,s.timeout,s.sync_time,s.created,s.seq,s.ack,"
                "b.last,b.locked,b.pool,b.tbd,b.size\n");
    }

    for (int i = 0; i < PIE_VALID_SESSIONS_HASH_SIZE; ++i) {
        uint8_t full = 0;

        sessions = sessions_array[i].data;
        buckets = sessions_array[i].tb;
        mask = sessions_array[i].mask;
        time = T_NOW;

        for (int j = 0; j < PIE_SES_BUCKET_SIZE; ++j) {
            struct session* s = &sessions[j];
            lbucket_t* b = &buckets[j];

            if (s->timeout == 0 && !count_empty ) {
                continue;
            }

            st->total_sessions++;

            if (s->timeout && s->timeout - time > 0x7fffffffffffffff) {
                st->old_sessions++;
                full++;

                if ( (1 << j) & mask) {
                    st->unknown_old++;
                }

                proto_state_count(s->state.proto,
                                  s->state.state,
                                  &st->old_proto_stats,
                                  &st->old_state_stats);
            }
            else {
                proto_state_count(s->state.proto,
                                  s->state.state,
                                  &st->valid_proto_stats,
                                  &st->valid_state_stats);
            }

            if (print) {
                fprintf(stdout,
                        "%X,%d,%X,"
                            "0x%" PRIx32 ",0x%" PRIx32 ",0x%" PRIx64 ","
                            "0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ","
                            "0x%" PRIx32 ",0x%" PRIx32 ",0x%" PRIx64 ","
                            "%X,0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 "\n",
                        i, j, mask,
                        s->addr.saddr, s->addr.daddr, s->state.state64,
                        ((s->timeout) ? s->timeout - time : 0),
                        s->sync_time - time,
                        ((s->created) ? time - s->created : 0),
                        s->seq, s->ack, b->last,
                        b->locked, (uint64_t)b->pool, b->tbd, b->size);
            }

            st->ips[st->ips_count] = s->addr.daddr;
            st->ips_count++;
        }

        st->modes[full]++;

        if (mask == 0xff) {
            st->full_masks++;
        }
        if (full == PIE_SES_BUCKET_SIZE) {
            st->full_lines++;
        }

        if (!print && (i * 100) % PIE_VALID_SESSIONS_HASH_SIZE == 0) {
            fprintf(stderr, "Progress %ld\n",
                    ((long int)i * 100) / PIE_VALID_SESSIONS_HASH_SIZE);
        }

    }

}

static void print_statistics(struct statistics* st)
{
    int i;

    fprintf(stdout, "Total sessions dumped: %" PRId64 "\n", st->total_sessions);
    fprintf(stdout, "Total buckets dumped: %" PRId64 "\n", st->total_lines);
    fprintf(stdout, "Full lines (0xff masks): %" PRId64 "(%" PRId64 "%%)\n",
            st->full_masks, st->full_masks * 100 / st->total_lines);
    fprintf(stdout, "Full lines (really full): %" PRId64 " (%" PRId64 "%%)\n",
            st->full_lines, st->full_lines * 100 / st->total_lines);
    fprintf(stdout, "Old sessions: %" PRId64 " (%" PRId64 "%%)\n",
            st->old_sessions, st->old_sessions * 100 / st->total_sessions);
    fprintf(stdout, "Old sessions we don\'t know about: %" PRId64 "(%" PRId64 "%%)\n",
            st->unknown_old, st->unknown_old * 100 / st->old_sessions);

    fprintf(stdout, "Old sessions states statistics:\n");
#define X(name, value) fprintf(stdout, "%s: %" PRId32 "\n", \
    str(name), st->old_state_stats.name);
    STATES_LIST
#undef X
    fprintf(stdout, "Valid sessions states statistics:\n");
#define X(name, value) fprintf(stdout, "%s: %" PRId32 "\n", \
    str(name), st->valid_state_stats.name);
    STATES_LIST
#undef X

    fprintf(stdout, "Old sessions protos statistics:\n");
#define X(name, value) fprintf(stdout, "%s: %" PRId32 "\n", \
    str(name), st->old_proto_stats.name);
    PROTOS_LIST
#undef X
    fprintf(stdout, "Valid sessions protos statistics:\n");
#define X(name, value) fprintf(stdout, "%s: %" PRId32 "\n", \
    str(name), st->valid_proto_stats.name);
    PROTOS_LIST
#undef X

    fprintf(stdout, "Lines fullness:\n");
    for (i = 0; i < PIE_SES_BUCKET_SIZE + 1; ++i) {
        fprintf(stdout, "%d: %"PRId64 " (%" PRId64 "%%)\n",
                i, st->modes[i], st->modes[i] * 100 / st->total_lines);
    }

    FILE* outfile = fopen("ips", "wb");
    fwrite((void*)(st->ips), sizeof(st->ips[0]) * st->ips_count, 1, outfile);

    fclose(outfile);
}

int main(int argc, char* argv[])
{
    int mode;
    bool print;

    struct valid_sessions* sessions;
    struct statistics* st = (struct statistics*)calloc(
        1, sizeof(struct statistics));

    int rte_argc = 3;
    char* rte_argv[] = {
        "shared_memory_reader",
        "--proc-type=secondary",
        "--log-level=4"
    };

    mode = MODE_SYM;
    print = false;
    count_empty = false;

    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            switch (argv[i][0]) {
                case 's':
                    mode = MODE_SYM;
                    break;
                case 'a':
                    mode = MODE_ASYM;
                    break;
                case 'p':
                    print = true;
                    break;
                case 'e':
                    count_empty = true;
                    break;
                default:
                    break;
            }
        }
    }

    rte_eal_init(rte_argc, rte_argv);

    pie_memory_init();
    time_init_per_core();

    switch (mode) {
        case MODE_SYM:
            sessions = pie_shmem_get_pointer(SESSIONS_S_EXPORT_NAME);
            break;
        case MODE_ASYM:
            sessions = pie_shmem_get_pointer(SESSIONS_A_EXPORT_NAME);
            break;
        default:
            sessions = NULL;
            break;
    }

    if (sessions) {
        analyze_sessions(sessions, st, print);
    }
    else {
        ERROR("Unable to get symmetric sessions pointer.\n");
    }

    print_statistics(st);

    return 0;
}
