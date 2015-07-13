/*
libPCStatePlugin.so,
a library to count frequencies and cycles spent in C-states
on Intel x86_64 for VampirTrace.
Copyright (C) 2010-2014 TU Dresden, ZIH

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, v2, as
published by the Free Software Foundation

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef VT
#include <vampirtrace/vt_plugin_cntr.h>
#endif /* ifdef VT */
#ifdef SCOREP
#include <scorep/SCOREP_MetricPlugins.h>
#endif /* ifdef SCOREP */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>

#ifdef X86_ADAPT
    #include <x86_adapt.h>
#else /* ifdef X86_ADAPT */
    #include "msr.h"
#endif /* ifdef X86_ADAPT */

/* partially copied from turbostat.c
 * Copyright (c) 2010, Intel Corporation.
 * Len Brown <len.brown@intel.com>
 * GPL v2 */

#define MSR_APERF 0xE8
#define MSR_MPERF 0xE7
#define MSR_PKG_C2_RESIDENCY 0x60D
#define MSR_PKG_C3_RESIDENCY 0x3F8
#define MSR_PKG_C6_RESIDENCY 0x3F9
#define MSR_PKG_C7_RESIDENCY 0x3FA
#define MSR_PKG_C8_RESIDENCY 0x630
#define MSR_PKG_C9_RESIDENCY 0x631
#define MSR_PKG_C10_RESIDENCY 0x632
#define MSR_CORE_C3_RESIDENCY 0x3FC
#define MSR_CORE_C6_RESIDENCY 0x3FD
#define MSR_CORE_C7_RESIDENCY 0x3FE /* SNB only */

#ifdef X86_ADAPT

#define X86_ADAPT_APERF "APERF"
#define X86_ADAPT_MPERF "MPERF"
#define X86_ADAPT_PKG_C2_RESIDENCY "Intel_PKG_C2_RESIDENCY"
#define X86_ADAPT_PKG_C3_RESIDENCY "Intel_PKG_C3_RESIDENCY"
#define X86_ADAPT_PKG_C6_RESIDENCY "Intel_PKG_C6_RESIDENCY"
#define X86_ADAPT_PKG_C7_RESIDENCY "Intel_PKG_C7_RESIDENCY"
#define X86_ADAPT_PKG_C8_RESIDENCY "Intel_PKG_C8_RESIDENCY"
#define X86_ADAPT_PKG_C9_RESIDENCY "Intel_PKG_C9_RESIDENCY"
#define X86_ADAPT_PKG_C10_RESIDENCY "Intel_PKG_C10_RESIDENCY"
#define X86_ADAPT_CORE_C3_RESIDENCY "Intel_CORE_C3_RESIDENCY"
#define X86_ADAPT_CORE_C6_RESIDENCY "Intel_CORE_C6_RESIDENCY"
#define X86_ADAPT_CORE_C7_RESIDENCY "Intel_CORE_C7_RESIDENCY"

#endif


struct event {
    int32_t pinned;
#ifdef X86_ADAPT
    int handle;
    int cpu;
    int id;
#else
    struct msr_handle handle;
#endif
}__attribute__((aligned(64)));

static uint32_t event_list_size;
//static struct event * event_list;
static struct event event_list[2048];

/* whether the processor supports aperf/mperf */
static unsigned int has_aperf;

/* run this plugin verbose? */
static unsigned int verbose;

/* haswell (and successors) cstate information avail? */
static unsigned int haswell_cstates;
/* sandy bridge (and successors) cstate information avail? */
static unsigned int snb_cstates;
/* nehalem (and successors) cstate information avail? */
static unsigned int nhm_cstates;
/* is intel processor */
static unsigned int genuine_intel;
/* has invariant tsc (i.e. tsc increases with reference freq.) */
static unsigned int has_invariant_tsc;


/* gracefully copied from turbostat.c
 * Copyright (c) 2010, Intel Corporation.
 * Len Brown <len.brown@intel.com>
 * GPL v2 */
int is_snb(unsigned int family, unsigned int model)
{
    if (!genuine_intel)
        return 0;

    switch (model) {
    case 0x2A: /* desktop sandy */
    case 0x2D: /* server sandy */
    case 0x3a: /* desktop ivy */
    case 0x3c: /* desktop haswell */
    case 0x3e: /* server ivy */
    case 0x3f: /* server haswell */
        return 1;
    }
    return 0;
}
int is_haswell(unsigned int family, unsigned int model)
{
    if (!genuine_intel)
        return 0;

    switch (model) {
    case 0x3c: /* desktop haswell */
    case 0x3f: /* server haswell */
        return 1;
    }
    return 0;
}

void check_cpuid(void)
{
    unsigned int eax, ebx, ecx, edx, max_level;
    unsigned int fms, family, model, stepping;

    eax = ebx = ecx = edx = 0;

    asm("cpuid" : "=a" (max_level), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0));

    if (ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e)
        genuine_intel = 1;

    if (verbose)
        fprintf(stderr, "%.4s%.4s%.4s ",
                (char *)&ebx, (char *)&edx, (char *)&ecx);

    asm("cpuid" : "=a" (fms), "=c" (ecx), "=d" (edx) : "a" (1) : "ebx");
    family = (fms >> 8) & 0xf;
    model = (fms >> 4) & 0xf;
    stepping = fms & 0xf;
    if (family == 6 || family == 0xf)
        model += ((fms >> 16) & 0xf) << 4;

    if (verbose)
        fprintf(stderr, "%d CPUID levels; family:model:stepping 0x%x:%x:%x (%d:%d:%d)\n",
                max_level, family, model, stepping, family, model, stepping);

    if (!(edx & (1 << 5))) {
        fprintf(stderr, "CPUID: no MSR\n");
        exit(1);
    }

    /*
     * check max extended function levels of CPUID.
     * This is needed to check for invariant TSC.
     * This check is valid for both Intel and AMD.
     */
    ebx = ecx = edx = 0;
    asm("cpuid" : "=a" (max_level), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0x80000000));

    if (max_level < 0x80000007) {
        fprintf(stderr, "CPUID: no invariant TSC (max_level 0x%x)\n", max_level);
        exit(1);
    }

    /*
     * Non-Stop TSC is advertised by CPUID.EAX=0x80000007: EDX.bit8
     * this check is valid for both Intel and AMD
     */
    asm("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0x80000007));
    has_invariant_tsc = edx & (1 << 8);

    if (!has_invariant_tsc) {
        fprintf(stderr, "No invariant TSC\n");
        exit(1);
    }

    /*
     * APERF/MPERF is advertised by CPUID.EAX=0x6: ECX.bit0
     * this check is valid for both Intel and AMD
     */

    asm("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0x6));
    has_aperf = ecx & (1 << 0);

    nhm_cstates = genuine_intel; /* all Intel w/ non-stop TSC have NHM counters */
    snb_cstates = is_snb(family, model);
    haswell_cstates = is_haswell(family, model);
}

static pthread_mutex_t add_counter_mutex;

int32_t init(void)
{
    /* for reading environment variable */
    char * verbose_string;
    int ret;
    /* initially no events */
    event_list_size=0;
    /* should we run verbose? */
    verbose_string=getenv("SCOREP_CPU_STATE_PLUGIN_VERBOSE");
    verbose=0;
    if (verbose_string!=NULL){
        verbose=atoi(verbose_string);
    }
    /* initially everything is disabled */
    has_aperf=0;
    genuine_intel=0;
    snb_cstates=0;
    haswell_cstates=0;
    nhm_cstates=0;
    /* init information reading infrastructure */
#ifdef X86_ADAPT
    ret = x86_adapt_init();
#else
    ret = init_msr(O_RDONLY);
#endif
    if(ret)
        return ret;
    /* get CPU information */
    check_cpuid();
    /* check if pthread mutex can be created */
    return pthread_mutex_init( &add_counter_mutex, NULL );
}

#ifdef VT

/* macros for defining events */
#define CNTR_METRIC_APERF_VT do { \
        return_values[i].name = strdup("aperf (actual frequency)"); \
        return_values[i].unit = NULL; \
        return_values[i++].cntr_property = VT_PLUGIN_CNTR_ACC \
                        | VT_PLUGIN_CNTR_UNSIGNED | VT_PLUGIN_CNTR_LAST; \
    } while(0)

#define CNTR_METRIC_MPERF_VT do { \
        return_values[i].name = strdup("mperf (constant frequency)"); \
        return_values[i].unit = NULL; \
        return_values[i++].cntr_property = VT_PLUGIN_CNTR_ACC \
                        | VT_PLUGIN_CNTR_UNSIGNED | VT_PLUGIN_CNTR_LAST; \
    } while(0)

#define CNTR_METRIC_STATE_VT(STATE) do { \
        return_values[i].name = strdup(STATE); \
        return_values[i].unit = strdup("cycles"); \
        return_values[i++].cntr_property = VT_PLUGIN_CNTR_ACC \
                        | VT_PLUGIN_CNTR_UNSIGNED | VT_PLUGIN_CNTR_LAST; \
    } while(0)

/* get information for events */
vt_plugin_cntr_metric_info * get_event_info_vt(char * event_name)
{
    int i = 0;
    int nr_states = 0;
    if (!strcmp(event_name,"aperf")){
        if (!has_aperf){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The aperf/mperf does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_APERF_VT;
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"mperf")){
        if (!has_aperf){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The aperf/mperf does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_MPERF_VT;
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC2")){
        if (!nhm_cstates){
            fprintf(stderr,"ERROR\n");
            fprintf(stderr, "The PC2 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC2");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC3")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC3 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC3");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC6")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC6 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC6");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC7")){
        if (!snb_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC7 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC7");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC8")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC8 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC8");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC9")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC9 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC9");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC10")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC10 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("PC10");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C3")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C3 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("C3");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C6")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C6 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("C6");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C7")){
        if (!snb_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C7 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc(2 * sizeof(vt_plugin_cntr_metric_info));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE_VT("C7");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC*")){
        if (nhm_cstates){
            nr_states=nr_states+3;
        } else {
            if (verbose)
                fprintf(stderr, "No PC2/PC3/PC6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1;
        } else{
            if (verbose)
                fprintf(stderr, "No PC7 state support\n");
        }
        if (haswell_cstates){
            nr_states=nr_states+3;
        } else{
            if (verbose)
                fprintf(stderr, "No PC8/PC9/PC10 state support\n");
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc((nr_states+1) * sizeof(vt_plugin_cntr_metric_info));
        if (nhm_cstates){
            CNTR_METRIC_STATE_VT("PC3");
            CNTR_METRIC_STATE_VT("PC6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE_VT("PC2");
            CNTR_METRIC_STATE_VT("PC7");
        }
        if (haswell_cstates){
            CNTR_METRIC_STATE_VT("PC8");
            CNTR_METRIC_STATE_VT("PC9");
            CNTR_METRIC_STATE_VT("PC10");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C*")){
        if (nhm_cstates){
            nr_states=nr_states+2;
        } else {
            if (verbose)
                fprintf(stderr, "No C3/C6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1;
        } else{
            if (verbose)
                fprintf(stderr, "No C7 state support\n");
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc((nr_states+1) * sizeof(vt_plugin_cntr_metric_info));
        if (nhm_cstates){
            CNTR_METRIC_STATE_VT("C3");
            CNTR_METRIC_STATE_VT("C6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE_VT("C7");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"*")){
        if (has_aperf){
            nr_states=nr_states+2;
        } else{
            if (verbose)
                fprintf(stderr, "No aperf/mperf support\n");
        }
        if (nhm_cstates){
            nr_states=nr_states+2+2;
        } else{
            if (verbose)
                fprintf(stderr, "No C3/C6,PC3/PC6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1+2;
        } else{
            if (verbose)
                fprintf(stderr, "No C7,PC2/PC7 state support\n");
        }
        if (haswell_cstates){
            nr_states=nr_states+3;
        } else{
            if (verbose)
                fprintf(stderr, "No PC8/PC9/PC10 state support\n");
        }
        vt_plugin_cntr_metric_info * return_values;
        return_values = malloc((nr_states+1) * sizeof(vt_plugin_cntr_metric_info));
        if (has_aperf){
            CNTR_METRIC_APERF_VT;
            CNTR_METRIC_MPERF_VT;
        }
        if (nhm_cstates){
            CNTR_METRIC_STATE_VT("C3");
            CNTR_METRIC_STATE_VT("C6");
            CNTR_METRIC_STATE_VT("PC3");
            CNTR_METRIC_STATE_VT("PC6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE_VT("C7");
            CNTR_METRIC_STATE_VT("PC2");
            CNTR_METRIC_STATE_VT("PC7");
        }
        if (haswell_cstates){
            CNTR_METRIC_STATE_VT("PC8");
            CNTR_METRIC_STATE_VT("PC9");
            CNTR_METRIC_STATE_VT("PC10");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    return NULL;
}
#endif /* ifdef VT */


#ifdef SCOREP

/* macros for defining events */
#define CNTR_METRIC_APERF do { \
        return_values[i].name        = strdup("aperf (actual frequency)"); \
        return_values[i].description = NULL; \
        return_values[i].unit        = strdup("actual cycles"); \
        return_values[i].mode        = SCOREP_METRIC_MODE_ACCUMULATED_START; \
        return_values[i].value_type  = SCOREP_METRIC_VALUE_UINT64; \
        return_values[i].base        = SCOREP_METRIC_BASE_DECIMAL; \
        return_values[i++].exponent  = 0; \
    } while(0)

#define CNTR_METRIC_MPERF do { \
        return_values[i].name        = strdup("mperf (constant frequency)"); \
        return_values[i].description = NULL; \
        return_values[i].unit        = strdup("reference cycles"); \
        return_values[i].mode        = SCOREP_METRIC_MODE_ACCUMULATED_START; \
        return_values[i].value_type  = SCOREP_METRIC_VALUE_UINT64; \
        return_values[i].base        = SCOREP_METRIC_BASE_DECIMAL; \
        return_values[i++].exponent  = 0; \
    } while(0)

#define CNTR_METRIC_STATE(STATE) do { \
        return_values[i].name        = strdup(STATE); \
        return_values[i].description = NULL; \
        return_values[i].unit        = strdup("cycles"); \
        return_values[i].mode        = SCOREP_METRIC_MODE_ACCUMULATED_START; \
        return_values[i].value_type  = SCOREP_METRIC_VALUE_UINT64; \
        return_values[i].base        = SCOREP_METRIC_BASE_DECIMAL; \
        return_values[i++].exponent  = 0; \
    } while(0)


/* get information for events */
SCOREP_Metric_Plugin_MetricProperties * get_event_info(char * event_name)
{
    int i = 0;
    int nr_states = 0;
    if (!strcmp(event_name,"aperf")){
        if (!has_aperf){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The aperf/mperf does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_APERF;
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"mperf")){
        if (!has_aperf){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The aperf/mperf does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_MPERF;
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC2")){
        if (!nhm_cstates){
            fprintf(stderr,"ERROR\n");
            fprintf(stderr, "The PC2 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC2");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC3")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC3 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC3");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC6")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC6 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC6");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC7")){
        if (!snb_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC7 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC7");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC8")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC8 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC8");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC9")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC9 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC9");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC10")){
        if (!haswell_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The PC10 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("PC10");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C3")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C3 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("C3");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C6")){
        if (!nhm_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C6 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("C6");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C7")){
        if (!snb_cstates){
            fprintf(stderr, "ERROR\n");
            fprintf(stderr, "The C7 residency counter does NOT exist on your platform\n");
            return NULL;
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc(2 * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        /* if the description is null it should be considered the end */
        CNTR_METRIC_STATE("C7");
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"PC*")){
        if (nhm_cstates){
            nr_states=nr_states+3;
        } else {
            if (verbose)
                fprintf(stderr, "No PC2/PC3/PC6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1;
        } else{
            if (verbose)
                fprintf(stderr, "No PC7 state support\n");
        }
        if (haswell_cstates){
            nr_states=nr_states+3;
        } else{
            if (verbose)
                fprintf(stderr, "No PC8/PC9/PC10 state support\n");
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc((nr_states+1) * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        if (nhm_cstates){
            CNTR_METRIC_STATE("PC3");
            CNTR_METRIC_STATE("PC6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE("PC2");
            CNTR_METRIC_STATE("PC7");
        }
        if (haswell_cstates){
            CNTR_METRIC_STATE("PC8");
            CNTR_METRIC_STATE("PC9");
            CNTR_METRIC_STATE("PC10");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"C*")){
        if (nhm_cstates){
            nr_states=nr_states+2;
        } else {
            if (verbose)
                fprintf(stderr, "No C3/C6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1;
        } else{
            if (verbose)
                fprintf(stderr, "No C7 state support\n");
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc((nr_states+1) * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        if (nhm_cstates){
            CNTR_METRIC_STATE("C3");
            CNTR_METRIC_STATE("C6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE("C7");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    if (!strcmp(event_name,"*")){
        if (has_aperf){
            nr_states=nr_states+2;
        } else{
            if (verbose)
                fprintf(stderr, "No aperf/mperf support\n");
        }
        if (nhm_cstates){
            nr_states=nr_states+2+2;
        } else{
            if (verbose)
                fprintf(stderr, "No C3/C6,PC3/PC6 state support\n");
        }
        if (snb_cstates){
            nr_states=nr_states+1+2;
        } else{
            if (verbose)
                fprintf(stderr, "No C7,PC2/PC7 state support\n");
        }
        if (haswell_cstates){
            nr_states=nr_states+3;
        } else{
            if (verbose)
                fprintf(stderr, "No PC8/PC9/PC10 state support\n");
        }
        SCOREP_Metric_Plugin_MetricProperties * return_values;
        return_values = malloc((nr_states+1) * sizeof(SCOREP_Metric_Plugin_MetricProperties));
        if (has_aperf){
            CNTR_METRIC_APERF;
            CNTR_METRIC_MPERF;
        }
        if (nhm_cstates){
            CNTR_METRIC_STATE("C3");
            CNTR_METRIC_STATE("C6");
            CNTR_METRIC_STATE("PC3");
            CNTR_METRIC_STATE("PC6");
        }
        if (snb_cstates){
            CNTR_METRIC_STATE("C7");
            CNTR_METRIC_STATE("PC2");
            CNTR_METRIC_STATE("PC7");
        }
        if (haswell_cstates){
            CNTR_METRIC_STATE("PC8");
            CNTR_METRIC_STATE("PC9");
            CNTR_METRIC_STATE("PC10");
        }
        /* Last element empty */
        return_values[i].name = NULL;
        return return_values;
    }
    return NULL;
}
#endif /* ifdef SCOREP */

/* finalize everithing */
void fini(void)
{
    uint32_t i;
    for (i=0;i<event_list_size;i++){
#ifdef X86_ADAPT
        x86_adapt_put_device(X86_ADAPT_CPU,event_list[i].handle);
#else
        close_msr(event_list[i].handle);
#endif
    }
#ifdef X86_ADAPT
    x86_adapt_finalize();
#endif
}

/* add a counter (called after get_event_info())
 * called per thread
 * */
int32_t add_counter(char * event_name)
{
    uint32_t i,j;
    int id;
    int ret = 0;
    uint32_t msr = 0;
    int number_of_cpus=0;
    int cpu_id=0;
    /*check whether this thread is bound to only one cpu*/
    cpu_set_t cpumask;
    char * cpumask_as_char_array;
    sched_getaffinity (0, sizeof(cpu_set_t),
                            &cpumask);
    cpumask_as_char_array=(char *)&cpumask;
    /* do a popcount */
    for (i=0;i<sizeof (cpu_set_t);i++){
        for (j=0;j<8;j++)
            if (cpumask_as_char_array[i]&(1<<j)){
                number_of_cpus++;
                cpu_id=i*8+j;
            }
    }
    /* lock */
    pthread_mutex_lock( &add_counter_mutex );
    id=event_list_size;
    event_list_size++;
    /*popcount > 1 --> not pinned!*/
    if (number_of_cpus>1){
        event_list[id].pinned = 0;
        fprintf(stderr, "WARNING Task not pinned to a certain core. "
                "Using current cpu.\n"
                "This might influence performance significantly and not represent the current tasks performance.\n");
    } else {
        event_list[id].pinned = 1;

    }
    /* pinned to cpu_id :) */
    cpu_id=sched_getcpu();
    /* realloc */
    /* unlock */
    pthread_mutex_unlock( &add_counter_mutex );
#ifdef X86_ADAPT
    if (!strcmp(event_name,"aperf (actual frequency)")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_APERF);
    }
    else if (!strcmp(event_name,"mperf (constant frequency)")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_MPERF);
    }
    else if (!strcmp(event_name,"C3")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_CORE_C3_RESIDENCY);
    }
    else if (!strcmp(event_name,"C6")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_CORE_C6_RESIDENCY);
    }
    else if (!strcmp(event_name,"C7")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_CORE_C7_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC2")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C2_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC3")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C3_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC6")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C6_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC7")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C7_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC8")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C8_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC9")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C9_RESIDENCY);
    }
    else if (!strcmp(event_name,"PC10")){
      event_list[id].id = x86_adapt_lookup_ci_name(X86_ADAPT_CPU, X86_ADAPT_PKG_C10_RESIDENCY);
    }
    if (event_list[id].id < 0 ){
      fprintf(stderr, "Your x86_adapt kernel module does not support the %s counter.\n",event_name);
      return event_list[id].id;
    }

#else
    if (!strcmp(event_name,"aperf (actual frequency)")){
        msr = MSR_APERF;
    }
    else if (!strcmp(event_name,"mperf (constant frequency)")){
        msr = MSR_MPERF;
    }
    else if (!strcmp(event_name,"C3")){
        msr = MSR_CORE_C3_RESIDENCY;
    }
    else if (!strcmp(event_name,"C6")){
        msr = MSR_CORE_C6_RESIDENCY;
    }
    else if (!strcmp(event_name,"C7")){
        msr = MSR_CORE_C7_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC2")){
        msr = MSR_PKG_C2_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC3")){
        msr = MSR_PKG_C3_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC6")){
        msr = MSR_PKG_C6_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC7")){
        msr = MSR_PKG_C7_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC8")){
        msr = MSR_PKG_C8_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC9")){
        msr = MSR_PKG_C9_RESIDENCY;
    }
    else if (!strcmp(event_name,"PC10")){
        msr = MSR_PKG_C10_RESIDENCY;
    }
#endif
    /* return id */

#ifdef X86_ADAPT
    ret = x86_adapt_get_device_ro(X86_ADAPT_CPU,cpu_id);
    if (ret>0){
      event_list[id].handle=ret;
      event_list[id].cpu=cpu_id;
      return id;
    } else
      return ret;
#else
    ret = open_msr(cpu_id, msr, &event_list[id].handle);
    if(ret)
            return ret;
    else
            return id;
#endif
}

/* read the current value, called at every enter/exit/sample event */
uint64_t get_current_value(int32_t id){
#ifdef X86_ADAPT
    uint64_t reading=777;
#endif
    /* not pinned?*/
    if (!event_list[id].pinned) {
        /* get current CPU */
        uint32_t cpu_id = sched_getcpu(); 
#ifdef X86_ADAPT
        if (event_list[id].cpu != cpu_id) {
            /* TASK HAS BEEN SWITCHED!
             * get device for new CPU */
            x86_adapt_put_device(X86_ADAPT_CPU, event_list[id].cpu);
            event_list[id].handle = x86_adapt_get_device_ro(X86_ADAPT_CPU,cpu_id);
        }
#else
        if (event_list[id].handle.cpu != cpu_id) {
            /* TASK HAS BEEN SWITCHED!
             * get device for new CPU */
            uint32_t msr = event_list[id].handle.msr;
            close_msr(event_list[id].handle);
            open_msr(cpu_id, msr, &event_list[id].handle);
        }
#endif
    }
    /* now read the current value */
#ifdef X86_ADAPT
    x86_adapt_get_setting(event_list[id].handle, event_list[id].id, &reading);
    return reading;
#else
    read_msr(&event_list[id].handle);
    return event_list[id].handle.data;
#endif
}

bool get_optional_value( int32_t   id,
                               uint64_t* value ){
  *value=get_current_value(id);
  return true;
}

#ifdef VT

vt_plugin_cntr_info get_info()
{
        vt_plugin_cntr_info info;
        memset(&info,0,sizeof(vt_plugin_cntr_info));
        info.init                       = init;
        info.add_counter                = add_counter;
        info.vt_plugin_cntr_version     = VT_PLUGIN_CNTR_VERSION;
        info.run_per                    = VT_PLUGIN_CNTR_PER_THREAD;
        info.synch                      = VT_PLUGIN_CNTR_SYNCH;
        info.get_event_info             = get_event_info_vt;
        info.get_current_value          = get_current_value;
        info.finalize                   = fini;
        return info;
}

#endif

#ifdef SCOREP
/**
 * This function get called to give some informations about the plugin to scorep
 */
SCOREP_METRIC_PLUGIN_ENTRY( pcPlugin )
{
    /* Initialize info data (with zero) */
    SCOREP_Metric_Plugin_Info info;
    memset( &info, 0, sizeof( SCOREP_Metric_Plugin_Info ) );

    /* Set up the structure */
    info.plugin_version               = SCOREP_METRIC_PLUGIN_VERSION;
    info.run_per                      = SCOREP_METRIC_PER_THREAD;
    info.sync                         = SCOREP_METRIC_SYNC;
    info.initialize                   = init;
    info.finalize                     = fini;
    info.get_event_info               = get_event_info;
    info.add_counter                  = add_counter;
    info.get_current_value            = get_current_value;
    info.get_optional_value           = get_optional_value;

    return info;
}
#endif
