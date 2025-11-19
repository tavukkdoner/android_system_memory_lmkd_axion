#ifndef _SLMK_H
#define _SLMK_H

#include <atomic>
#include <pthread.h>
#include <sys/types.h>
#include <vector>
#include <limits.h>

#define SLMK_MAX_VICTIMS 1024
#define SLMK_PER_RECLAIM_MIN (128UL * 1024UL)

struct proc_info {
    pid_t pid;
    int adj;
    unsigned long rss; 
    uid_t uid;
    unsigned long anon_pages;
};

class SimpleLmk {
public:
    SimpleLmk()
        : reclaim_pending_(false),
          comm_fd_(-1),
          thread_pool_(nullptr),
          thread_cnt_(0) {}
    ~SimpleLmk() {
        if (thread_pool_) {
            delete[] thread_pool_;
        }
    }

    bool init(int comm_fd);
    void set_reaper(class Reaper* reaper);
    void scan_and_kill();

    std::atomic<bool> reclaim_pending_;
    int comm_fd_;
    
    void mp_event_psi(int level);

private:
    pthread_t* thread_pool_;
    int thread_cnt_;
    std::atomic<unsigned long> reclaim_target_kb_{SLMK_PER_RECLAIM_MIN};
    std::vector<proc_info> small_victims;
    std::vector<proc_info> big_victims;
    unsigned long find_victims(int* vindex);
    int process_victims(int vlen);
};

void* slmk_main(void* param);

#endif // _SLMK_H
