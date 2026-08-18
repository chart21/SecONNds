#ifndef HE_LINEAR_TRACKER_H__
#define HE_LINEAR_TRACKER_H__

#include <atomic>
#include <chrono>
#include <cstdint>

namespace sci {

// Splits a Cheetah linear layer into its HE part and its HE->MPC conversion.
//
// The conversion is not a step that has to be added: it is already the transfer
// of the masked result ciphertexts. The server masks its homomorphic result
// with its own share and ships it; the client decrypts to obtain the
// complementary share. Everything before that -- encrypting/encoding the
// inputs and the homomorphic evaluation itself -- is the HE part.
//
// So we only need to measure that transfer. Scoping it here lets the layer
// wrappers report preprocessing = layer - conversion and online = conversion,
// which by construction sums back to the unmodified layer cost. Nothing extra
// goes on the wire.
struct HELinearOnlineMetrics {
  uint64_t sent_bytes = 0;
  uint64_t runtime_microseconds = 0;
};

inline std::atomic<uint64_t> he_linear_online_sent_bytes{0};
inline std::atomic<uint64_t> he_linear_online_runtime_microseconds{0};

inline HELinearOnlineMetrics GetHELinearOnlineMetrics() {
  return {he_linear_online_sent_bytes.load(),
          he_linear_online_runtime_microseconds.load()};
}

inline HELinearOnlineMetrics HELinearOnlineDifference(
    const HELinearOnlineMetrics &after, const HELinearOnlineMetrics &before) {
  return {after.sent_bytes - before.sent_bytes,
          after.runtime_microseconds - before.runtime_microseconds};
}

// Measures one conversion transfer. On the receiving party no bytes are sent,
// so only the time is attributed -- which also covers the wait for the peer.
class HELinearOnlineScope {
 public:
  template <typename IO>
  explicit HELinearOnlineScope(IO *io)
      : counter_(&io->counter),
        sent_start_(io->counter),
        start_(std::chrono::high_resolution_clock::now()) {}

  ~HELinearOnlineScope() {
    he_linear_online_sent_bytes.fetch_add(*counter_ - sent_start_);
    he_linear_online_runtime_microseconds.fetch_add(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - start_)
            .count());
  }

  HELinearOnlineScope(const HELinearOnlineScope &) = delete;
  HELinearOnlineScope &operator=(const HELinearOnlineScope &) = delete;

 private:
  uint64_t *counter_;
  uint64_t sent_start_;
  std::chrono::high_resolution_clock::time_point start_;
};

}  // namespace sci

#endif  // HE_LINEAR_TRACKER_H__
