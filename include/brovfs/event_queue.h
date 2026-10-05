// Multi-producer, single-consumer queue that carries facts from a backend thread to the host.
//
// Producers push from their own threads; the host drains on its own thread whenever it likes.
// Producers never call into host code except the optional wake hook, which must be cheap and
// thread-safe (post a message, write an eventfd, push an SDL event, ...).
#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <utility>
#include <vector>

namespace bro::vfs {

template <class T>
class MessageQueue {
public:
    void push(T value) {
        std::function<void()> wake;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            items_.push_back(std::move(value));
            wake = wake_;
        }
        cv_.notify_all();
        if (wake) wake();
    }

    // Pushes several values atomically (the consumer sees all or none of them), one wake.
    void push_all(std::vector<T>&& values) {
        if (values.empty()) return;
        std::function<void()> wake;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& v : values) items_.push_back(std::move(v));
            wake = wake_;
        }
        values.clear();
        cv_.notify_all();
        if (wake) wake();
    }

    // Removes and returns everything queued, in push order.
    std::vector<T> drain() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<T> out;
        out.swap(items_);
        return out;
    }

    // Blocks until at least one item is queued or the timeout passes.
    bool wait_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, timeout, [&] { return !items_.empty(); });
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return items_.size();
    }

    // Called (on the producer's thread) after every push.
    void set_wake(std::function<void()> wake) {
        std::lock_guard<std::mutex> lock(mutex_);
        wake_ = std::move(wake);
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<T> items_;
    std::function<void()> wake_;
};

} // namespace bro::vfs
