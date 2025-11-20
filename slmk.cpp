/*
 * Copyright (C) 2025 AxionOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "USLMK"

#include <android-base/properties.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <log/log.h>
#include <processgroup/processgroup.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/pidfd.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <system/thread_defs.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "reaper.h"
#include "slmk.h"

#define NS_PER_MS (NS_PER_SEC / MS_PER_SEC)
#define THREAD_POOL_SIZE 2
#define RECLAIM_TIMEOUT_MS 200
#define VM_PRESSURE_CRITICAL 100
#define ALLOCSTALL_SIGNIFICANT_THRESHOLD 1000ULL
#define PAGE_ALLOC_COSTLY_ORDER 3
#define VMPRESS_LEVEL_LOW 0
#define VMPRESS_LEVEL_MEDIUM 1
#define VMPRESS_LEVEL_CRITICAL 2
#define PERCEPTIBLE_APP_ADJ 200
#define PREVIOUS_APP_ADJ 700
#define LOW_MEM_ADJ_CUT_OFF 0

static Reaper* reaper_instance = nullptr;

static std::vector<proc_info> victims_array;
static std::atomic<int> nr_victims(0);
static std::atomic<int> nr_killed(0);
static std::atomic<bool> reclaim_active(false);
static pthread_mutex_t victims_lock = PTHREAD_MUTEX_INITIALIZER;
static int current_pressure_level = 0;

static inline long get_time_diff_ms(struct timespec* from, struct timespec* to) {
    return (to->tv_sec - from->tv_sec) * 1000L +
           (to->tv_nsec - from->tv_nsec) / NS_PER_MS;
}

static bool is_pid_alive(pid_t pid) {
    int pidfd = pidfd_open(pid, 0);
    if (pidfd >= 0) {
        close(pidfd);
        return true;
    }
    return (kill(pid, 0) == 0);
}

static char* reread_file(const char* filename) {
    int fd = TEMP_FAILURE_RETRY(open(filename, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        return nullptr;
    }

    ssize_t buf_size = 4096;
    char* buf = static_cast<char*>(malloc(buf_size));
    if (!buf) {
        close(fd);
        return nullptr;
    }

    ssize_t total_read = 0;
    while (true) {
        ssize_t n = TEMP_FAILURE_RETRY(
            read(fd, buf + total_read, buf_size - total_read - 1));
        if (n < 0) {
            free(buf);
            close(fd);
            return nullptr;
        }
        if (n == 0) break;
        total_read += n;
        if (total_read >= buf_size - 1) {
            buf_size *= 2;
            char* new_buf = static_cast<char*>(realloc(buf, buf_size));
            if (!new_buf) {
                free(buf);
                close(fd);
                return nullptr;
            }
            buf = new_buf;
        }
    }
    buf[total_read] = '\0';
    close(fd);
    return buf;
}

union vmpressure {
    struct {
        double some_avg10;
        double some_avg60;
        double some_avg300;
        unsigned long long some_total;
        double full_avg10;
        double full_avg60;
        double full_avg300;
        unsigned long long full_total;
    } field;
};

static int vmpressure_parse_file(const char* filename, union vmpressure* vp) {
    char* buf = reread_file(filename);
    if (!buf) {
        ALOGE("Failed to read %s", filename);
        return -1;
    }

    memset(vp, 0, sizeof(*vp));
    char* save_ptr;
    bool found_some = false;
    bool found_full = false;

    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, "some", 4) == 0) {
            int matched = sscanf(line, "some avg10=%lf avg60=%lf avg300=%lf total=%llu",
                                &vp->field.some_avg10,
                                &vp->field.some_avg60,
                                &vp->field.some_avg300,
                                &vp->field.some_total);
            if (matched == 4) found_some = true;
        } else if (strncmp(line, "full", 4) == 0) {
            int matched = sscanf(line, "full avg10=%lf avg60=%lf avg300=%lf total=%llu",
                                &vp->field.full_avg10,
                                &vp->field.full_avg60,
                                &vp->field.full_avg300,
                                &vp->field.full_total);
            if (matched == 4) found_full = true;
        }
    }

    free(buf);

    if (!found_some && !found_full) {
        ALOGE("Failed to parse pressure metrics from %s", filename);
        return -1;
    }

    return 0;
}

static unsigned long long parse_vmstat_field_ull(const char* key) {
    char* buf = reread_file("/proc/vmstat");
    if (!buf) {
        ALOGE("Failed to read /proc/meminfo");
        return 0;
    }

    unsigned long long value = 0;
    char* save_ptr;
    size_t keylen = strlen(key);
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, key, keylen) == 0) {
            const char* p = line + keylen;
            while (*p && (*p == ' ' || *p == '\t')) p++;
            value = strtoull(p, nullptr, 10);
            break;
        }
    }
    free(buf);
    return value;
}

static unsigned long parse_meminfo_field_kb(const char* key) {
    char* buf = reread_file("/proc/meminfo");
    if (!buf) {
        ALOGE("Failed to read /proc/meminfo");
        return 0;
    }

    unsigned long value_kb = 0;
    char* save_ptr;
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, key, strlen(key)) == 0) {
            const char* p = line + strlen(key);
            while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
            value_kb = strtoul(p, nullptr, 10);
            break;
        }
    }
    free(buf);
    return value_kb;
}

static void read_vmstat_allocstall(unsigned long long* allocstall_total,
                                   unsigned long long* pgsteal_direct,
                                   unsigned long long* pgsteal_kswapd) {
    unsigned long long normal = parse_vmstat_field_ull("allocstall_normal");
    unsigned long long movable = parse_vmstat_field_ull("allocstall_movable");
    unsigned long long device = parse_vmstat_field_ull("allocstall_device");
    unsigned long long dma32 = parse_vmstat_field_ull("allocstall_dma32");
    unsigned long long dma = parse_vmstat_field_ull("allocstall_dma");

    unsigned long long costly_allocs = parse_vmstat_field_ull("pgskip_normal") +
                                       parse_vmstat_field_ull("pgskip_movable") +
                                       parse_vmstat_field_ull("pgskip_device") +
                                       parse_vmstat_field_ull("pgskip_dma32") +
                                       parse_vmstat_field_ull("pgskip_dma");

    if (allocstall_total) {
        *allocstall_total = normal + movable + device + dma32 + dma;

        if (*allocstall_total <= costly_allocs) {
            *allocstall_total = 0;
        } else {
            *allocstall_total -= costly_allocs;
        }
    }

    if (pgsteal_direct)
        *pgsteal_direct = parse_vmstat_field_ull("pgsteal_direct");
    if (pgsteal_kswapd)
        *pgsteal_kswapd = parse_vmstat_field_ull("pgsteal_kswapd");
}

static bool reclaim_active_in_slow_path() {
    unsigned long long allocstall_total = 0;
    unsigned long long pgsteal_direct = 0;
    unsigned long long pgsteal_kswapd = 0;

    read_vmstat_allocstall(&allocstall_total, &pgsteal_direct, &pgsteal_kswapd);

    return allocstall_total > 0;
}

static bool is_memory_under_pressure() {
    union vmpressure mem;
    double mem_p = 0.0;

    bool vp_read_ok = (vmpressure_parse_file("/proc/pressure/memory", &mem) == 0);

    if (vp_read_ok && reclaim_active_in_slow_path()) {
        mem_p = std::max(mem.field.full_avg10, mem.field.some_avg10);
    } else {
        mem_p = 0.0;
    }

    if (mem_p >= 1.0) {
        return mem_p >= VM_PRESSURE_CRITICAL;
    }

    unsigned long mem_available = parse_meminfo_field_kb("MemAvailable");
    unsigned long mem_total = parse_meminfo_field_kb("MemTotal");
    unsigned long inactive_file = parse_meminfo_field_kb("Inactive(file)");
    unsigned long inactive_anon = parse_meminfo_field_kb("Inactive(anon)");
    unsigned long k_reclaimable = parse_meminfo_field_kb("KReclaimable");
    unsigned long swap_total = parse_meminfo_field_kb("SwapTotal");
    unsigned long swap_free = parse_meminfo_field_kb("SwapFree");

    double avail_frac = (double)mem_available / (double)mem_total;
    double reclaimable_pool = (double)(inactive_file + inactive_anon + k_reclaimable);
    double reclaimable_frac = reclaimable_pool / (double)mem_total;
    double swap_free_frac = swap_total ? (double)swap_free / (double)swap_total : 1.0;

    bool no_reclaimable = reclaimable_frac < 0.01 && k_reclaimable < 128 * 1024;
    bool low_avail = avail_frac < 0.05 || (swap_total && swap_free_frac < 0.10);

    if (no_reclaimable && low_avail) {
        unsigned long long allocstall_total = 0;
        unsigned long long pgsteal_direct = 0;
        unsigned long long pgsteal_kswapd = 0;

        read_vmstat_allocstall(&allocstall_total, &pgsteal_direct, &pgsteal_kswapd);

        bool direct_reclaim_dominant = (pgsteal_direct > pgsteal_kswapd);

        if (allocstall_total >= ALLOCSTALL_SIGNIFICANT_THRESHOLD || !direct_reclaim_dominant) {
            mem_p = 100.0;
        }
    }

    return mem_p >= VM_PRESSURE_CRITICAL;
}

static int get_oom_score_adj(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", pid);
    char* buf = reread_file(path);
    if (!buf) return 0;
    int adj = strtol(buf, nullptr, 10);
    free(buf);
    return adj;
}

static unsigned long get_task_rss_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char* buf = reread_file(path);
    if (!buf) return 0;
    
    unsigned long rss_kb = 0;
    char* save_ptr;
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            char* p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            rss_kb = strtoul(p, nullptr, 10);
            break;
        }
    }
    free(buf);
    return rss_kb;
}

static unsigned long get_task_anon_kb(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char* buf = reread_file(path);
    if (!buf) return 0;
    
    unsigned long anon_kb = 0;
    char* save_ptr;
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, "RssAnon:", 8) == 0) {
            char* p = line + 8;
            while (*p == ' ' || *p == '\t') p++;
            anon_kb = strtoul(p, nullptr, 10);
            break;
        }
    }
    free(buf);
    return anon_kb;
}

static uid_t get_task_uid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char* buf = reread_file(path);
    if (!buf) return 0;
    
    uid_t uid = 0;
    char* save_ptr;
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            char* p = line + 4;
            while (*p == ' ' || *p == '\t') p++;
            uid = strtoul(p, nullptr, 10);
            break;
        }
    }
    free(buf);
    return uid;
}

static bool is_process_dying(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    char* buf = reread_file(path);
    if (!buf) return true;
    
    bool dying = false;
    char* save_ptr;
    for (char* line = strtok_r(buf, "\n", &save_ptr); line;
         line = strtok_r(nullptr, "\n", &save_ptr)) {
        if (strncmp(line, "State:", 6) == 0) {
            if (strstr(line, "Z (zombie)")) {
                dying = true;
                break;
            }
        }
    }
    free(buf);
    return dying;
}

static void get_process_name(pid_t pid, char* name, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    char* buf = reread_file(path);
    if (!buf) {
        snprintf(name, len, "<unknown>");
        return;
    }
    
    size_t buflen = strlen(buf);
    if (buflen > 0 && buf[buflen - 1] == '\n') {
        buf[buflen - 1] = '\0';
    }
    
    snprintf(name, len, "%s", buf);
    free(buf);
}

unsigned long SimpleLmk::find_victims(int* vindex) {
    std::map<short, std::vector<proc_info>> task_bucket;
    short min_adj = SHRT_MAX;
    short max_adj = 0;
    unsigned long pages_found = 0;
    
    int adj_cut_off = LOW_MEM_ADJ_CUT_OFF;

    DIR* d = opendir("/proc");
    if (!d) {
        ALOGE("Failed to open /proc: %s", strerror(errno));
        return 0;
    }

    struct dirent* de;
    while ((de = readdir(d))) {
        if (de->d_type != DT_DIR) continue;
        pid_t pid = atoi(de->d_name);
        if (pid <= 0) continue;

        if (!is_pid_alive(pid)) continue;

        int adj = get_oom_score_adj(pid);

        if (adj <= adj_cut_off || is_process_dying(pid)) {
            continue;
        }

        unsigned long rss_kb = get_task_rss_kb(pid);
        uid_t uid = get_task_uid(pid);

        proc_info p = {pid, adj, rss_kb, uid, 0};
        task_bucket[adj].push_back(p);

        if (adj > max_adj) max_adj = adj;
        if (adj < min_adj) min_adj = adj;
    }
    closedir(d);

    if (task_bucket.empty()) {
        ALOGW("No killable processes found");
        return 0;
    }

    unsigned long target = reclaim_target_kb_.load();
    std::vector<proc_info> small_victims;
    std::vector<proc_info> big_victims;

    ALOGI("Scanning from adj %d to %d (reclaim target %lu KB)",
          max_adj, min_adj, target);

    for (short adj = max_adj; adj >= min_adj; adj--) {
        auto it = task_bucket.find(adj);
        if (it == task_bucket.end()) continue;

        for (auto& p : it->second) {
            if (p.rss <= target)
                small_victims.push_back(p);
            else
                big_victims.push_back(p);
        }
    }

    std::sort(small_victims.begin(), small_victims.end(),
              [](const proc_info& a, const proc_info& b) {
                  return a.rss > b.rss;
              });

    std::sort(big_victims.begin(), big_victims.end(),
              [](const proc_info& a, const proc_info& b) {
                  return a.rss < b.rss;
              });

    *vindex = 0;
    victims_array.clear();
    victims_array.resize(SLMK_MAX_VICTIMS);

    pages_found = 0;

    for (auto& p : small_victims) {
        if (*vindex >= SLMK_MAX_VICTIMS)
            break;
        victims_array[*vindex] = p;
        pages_found += p.rss;
        (*vindex)++;
    }

    for (auto& p : big_victims) {
        if (*vindex >= SLMK_MAX_VICTIMS)
            break;
        victims_array[*vindex] = p;
        pages_found += p.rss;
        (*vindex)++;
    }

    return pages_found;
}

int SimpleLmk::process_victims(int vlen) {
    unsigned long target = reclaim_target_kb_.load();
    unsigned long collected = 0;
    int count = 0;

    for (int i = 0; i < vlen; i++) {
        if (victims_array[i].rss > target)
            continue;

        collected += victims_array[i].rss;
        count++;

        if (collected >= target)
            return count;
    }

    for (int i = 0; i < vlen; i++) {
        if (victims_array[i].rss <= target)
            continue;

        collected += victims_array[i].rss;
        count++;

        if (collected >= target)
            break;
    }

    return count;
}

static void set_task_rt_prio(pid_t pid, int priority) {
    struct sched_param param = {.sched_priority = priority};
    if (sched_setscheduler(pid, SCHED_RR, &param) != 0) {
    }
}

static void thaw_task(pid_t pid) {
    kill(pid, SIGCONT); // not sure if this matches __thaw_task
}

void SimpleLmk::scan_and_kill() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &start);
    
    int nr_found = 0;
    int nr_to_kill = 0;
    unsigned long pages_found;
    
    pthread_mutex_lock(&victims_lock);
    nr_victims.store(0);
    nr_killed.store(0);
    victims_array.clear();
    victims_array.resize(SLMK_MAX_VICTIMS);
    pthread_mutex_unlock(&victims_lock);
    
    pages_found = find_victims(&nr_found);
    
    if (nr_found == 0) {
        ALOGE("No processes available to kill!");
        return;
    }
    
    ALOGI("Found %d potential victims (%lu KB)", nr_found, pages_found);
    
    unsigned long target = reclaim_target_kb_.load();
    if (pages_found > target) {
        nr_to_kill = process_victims(nr_found);
        
        ALOGI("First pass wants to kill %d victims", nr_to_kill);
        
        std::sort(victims_array.begin(), victims_array.begin() + nr_to_kill,
                 [](const proc_info& a, const proc_info& b) {
                     return a.rss > b.rss;
                 });
        
        nr_to_kill = process_victims(nr_to_kill);
        
        ALOGI("After optimization, killing %d victims", nr_to_kill);
    } else {
        nr_to_kill = nr_found;
    }
    
    pthread_mutex_lock(&victims_lock);
    nr_victims.store(nr_to_kill);
    reclaim_active.store(true);
    pthread_mutex_unlock(&victims_lock);
    
    for (int i = 0; i < nr_to_kill; i++) {
        proc_info* victim = &victims_array[i];
        pid_t pid = victim->pid;
        
        if (!is_pid_alive(pid)) {
            ALOGD("Process %d already dead", pid);
            nr_killed.fetch_add(1);
            continue;
        }
        
        char comm[256];
        get_process_name(pid, comm, sizeof(comm));
		
        if (!strncmp("com.wstxda.viper4android", comm, strlen(comm))) {
            ALOGD("Process %s is excluded", comm);
            continue;
        }
        
        ALOGI("Killing %s (pid %d, adj %d) to free %lu KB",
              comm, pid, victim->adj, victim->rss);
        
        kill(pid, SIGKILL);
        
        set_task_rt_prio(pid, 1);
        
        thaw_task(pid);
        
        if (reaper_instance) {
            int pidfd = pidfd_open(pid, 0);
            if (pidfd >= 0) {
                victim->anon_pages = get_task_anon_kb(pid);
                
                int result = reaper_instance->kill({pidfd, pid, victim->uid}, false);
                if (result == 0) {
                    ALOGD("Reaper took pid %d", pid);
                    nr_killed.fetch_add(1);
                } else {
                    ALOGW("Reaper failed for pid %d", pid);
                    close(pidfd);
                }
            }
        }
    }
    
    struct timespec wait_start;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &wait_start);
    
    bool timeout = false;
    while (nr_killed.load() < nr_to_kill) {
        usleep(10000);
        
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (get_time_diff_ms(&wait_start, &now) > RECLAIM_TIMEOUT_MS) {
            ALOGI("Timeout waiting for victims to die");
            timeout = true;
            break;
        }
    }
    
    pthread_mutex_lock(&victims_lock);
    reclaim_active.store(false);
    int killed = nr_killed.load();
    nr_killed.store(0);
    pthread_mutex_unlock(&victims_lock);
    
    clock_gettime(CLOCK_MONOTONIC_COARSE, &end);
    
    unsigned long freed_kb = 0;
    for (int i = 0; i < killed; i++) {
        freed_kb += victims_array[i].rss;
    }
    
    ALOGI("Killed %d/%d processes in %ld ms (freed ~%.1f MB)%s",
          killed, nr_to_kill, get_time_diff_ms(&start, &end),
          freed_kb / 1024.0, timeout ? " [TIMEOUT]" : "");
}

void SimpleLmk::set_reaper(Reaper* reaper) {
    reaper_instance = reaper;
    if (reaper_instance) {
        ALOGI("Reaper configured");
    }
}

bool SimpleLmk::init(int comm_fd) {
    if (thread_cnt_ > 0) {
        ALOGE("Already initialized");
        return false;
    }

    thread_pool_ = new pthread_t[THREAD_POOL_SIZE];
    struct sched_param param = {
        .sched_priority = 98,
    };

    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&thread_pool_[thread_cnt_], nullptr, 
                          slmk_main, this) != 0) {
            ALOGE("pthread_create failed: %s", strerror(errno));
            continue;
        }
        
        if (pthread_setschedparam(thread_pool_[thread_cnt_], 
                                 SCHED_RR, &param) != 0) {
            ALOGW("set SCHED_RR failed: %s", strerror(errno));
        }
        
        char name[16];
        snprintf(name, sizeof(name), "lmkd_slmk%d", thread_cnt_);
        if (pthread_setname_np(thread_pool_[thread_cnt_], name) != 0) {
            ALOGW("pthread_setname_np failed: %s", strerror(errno));
        }
        
        thread_cnt_++;
    }

    if (!thread_cnt_) {
        ALOGE("Failed to create any threads");
        delete[] thread_pool_;
        thread_pool_ = nullptr;
        return false;
    }

    comm_fd_ = comm_fd;
    victims_array.resize(SLMK_MAX_VICTIMS);
    ALOGI("Initialized with %d threads", thread_cnt_);
    return true;
}

void SimpleLmk::mp_event_psi(int level) {
    unsigned long base = SLMK_PER_RECLAIM_MIN;

    if (level == VMPRESS_LEVEL_LOW) {
        reclaim_target_kb_.store(base / 2);
        ALOGI("PSI: LOW event → reclaim target = %lu KB", base / 2);
    } else if (level == VMPRESS_LEVEL_MEDIUM) {
        reclaim_target_kb_.store(base);
        ALOGI("PSI: MED event → reclaim target = %lu KB", base);
    } else if (level == VMPRESS_LEVEL_CRITICAL) {
        reclaim_target_kb_.store(base * 2);
        ALOGI("PSI: HIGH event → reclaim target = %lu KB", base);
    }
    
    current_pressure_level = level;

    bool expected = false;
    if (reclaim_pending_.compare_exchange_strong(expected, true)) {
        scan_and_kill();
        reclaim_pending_.store(false);
    } else {
        ALOGD("SLMK PSI: Reclaim already in progress");
    }
}

void* slmk_main(void* param) {
    SimpleLmk* slmk = static_cast<SimpleLmk*>(param);
    pid_t tid = gettid();
    
    struct sched_param slmk_param = { 
        .sched_priority = 98 
    };

    if (!SetTaskProfiles(tid, {"CPUSET_SP_TOP_APP"}, true)) {
        ALOGE("Failed to assign cpuset to thread");
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
 
    std::vector<int32_t> big_cores;
 
    auto parseCpusets = [](const std::string& cpuset_str, 
                          std::vector<int32_t>& cpus) {
        std::istringstream ss(cpuset_str);
        std::string token;
        while (std::getline(ss, token, ',')) {
            char* endptr;
            long cpu = std::strtol(token.c_str(), &endptr, 10);
            if (*endptr == '\0' && cpu >= 0) {
                cpus.push_back(static_cast<int32_t>(cpu));
            } else {
                ALOGW("Invalid CPU core value: %s", token.c_str());
            }
        }
    };
 
    parseCpusets(android::base::GetProperty("persist.sys.axion_cpu_big", 
                                           "0,1,2,3"), big_cores);
 
    for (int core : big_cores) {
        CPU_SET(core, &cpuset);
    }
 
    if (sched_setaffinity(tid, sizeof(cpu_set_t), &cpuset) != 0) {
        ALOGW("Failed to set thread CPU affinity to big cores");
    } else {
        ALOGI("Successfully set thread CPU affinity to big cores");
    }

    if (sched_setscheduler(tid, SCHED_RR, &slmk_param) != 0) {
        ALOGW("Failed to set scheduler: %s", strerror(errno));
    }

    ALOGI("Monitor thread started (tid %d)", tid);

    for (;;) {
        sleep(1);

        if (is_memory_under_pressure()) {
            ALOGI("memory pressure. scanning");
            bool expected = false;
            if (slmk->reclaim_pending_.compare_exchange_strong(expected, true)) {
                slmk->scan_and_kill();
                slmk->reclaim_pending_.store(false);
            } else {
                ALOGD("Reclaim already in progress");
            }
        }
    }

    return nullptr;
}
