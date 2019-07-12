#ifndef ENTROPY_CALCULAOR_H
#define ENTROPY_CALCULAOR_H

#include <array>
#include <cstdint>

class Entropy_calculator {
public:
  double calculate_entropy(const unsigned char* data, size_t num_bytes);

  // Convenience to get upper bound entropy dependent on input size.
  double max_entropy_for_size(size_t num_bytes) const;

  static constexpr size_t freq_base = 256;

private:
  std::array<uint32_t, freq_base> frequency_map = {0};
};

#endif

// vim: et:ts=2:sw=2