// Pure-logic test for the completion queue's two miss tests: no device, no daemon, no sweep.
// Every branch is driven from synthetic counter values, including the ones a live run reaches
// only by luck.

#include <datacrumbs/utils/client/doca/cq_lap.h>

#include <cstdio>
#include <cstdlib>

using datacrumbs::utils::doca_cq::CtrTrack;
using datacrumbs::utils::doca_cq::is_lap_not_empty;
using datacrumbs::utils::doca_cq::missed_from_counter;

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", what);
    ++g_failures;
  }
}

/// A track that has learned a stride of @p stride and is ready for the next sweep's first entry.
CtrTrack primed(uint16_t last, uint16_t stride) {
  CtrTrack t;
  t.last = last;
  t.stride = stride;
  t.have = true;
  t.seen_this_sweep = false;
  return t;
}

void stride_is_learned_inside_one_sweep() {
  CtrTrack t;
  check(missed_from_counter(t, 100, 1024) == 0, "first entry of a queue reports nothing");
  check(missed_from_counter(t, 104, 1024) == 0, "second entry of the same sweep is not a gap");
  check(t.stride == 4, "the step inside one sweep is the stride");
}

void one_operation_between_sweeps_is_not_a_gap() {
  CtrTrack t = primed(100, 4);
  check(missed_from_counter(t, 104, 1024) == 0, "one step at the seam is not a gap");
}

void a_forward_gap_counts_what_it_skipped() {
  CtrTrack t = primed(100, 4);
  check(missed_from_counter(t, 140, 1024) == 9, "ten steps at the seam means nine missed");
}

/// The regression: a gap of 32768 or more used to read as a backwards step and count nothing.
void a_gap_past_half_the_counter_still_counts() {
  CtrTrack t = primed(0, 4);
  check(missed_from_counter(t, 40000, 1024) == 9999, "a 40000 step is a real gap, not a wrap");
  CtrTrack u = primed(0, 1);
  check(missed_from_counter(u, 32768, 1024) == 32767, "the old bound excluded exactly this");
}

/// A work queue index wrapping at its own depth reads as a large forward step. It is bounded by
/// the queue depth, so it lands inside the excluded window next to the counter's wrap.
void a_backwards_step_is_not_a_gap() {
  CtrTrack t = primed(0, 1);
  check(missed_from_counter(t, 65472, 1024) == 0, "a 64-entry queue stepping back is not a gap");
  CtrTrack u = primed(0, 1);
  check(missed_from_counter(u, 64513, 1024) == 0, "a step back by the whole cq depth is not one");
}

void a_static_counter_reports_nothing() {
  CtrTrack t = primed(100, 4);
  check(missed_from_counter(t, 100, 1024) == 0, "a repeat marks the counter static");
  check(t.is_static, "a repeat marks the counter static");
  CtrTrack u = t;
  u.seen_this_sweep = false;
  check(missed_from_counter(u, 40000, 1024) == 0, "a static counter never reports a gap");
}

void the_owner_bit_test_separates_a_lap_from_an_empty_slot() {
  CtrTrack t = primed(100, 4);
  check(!is_lap_not_empty(t, /*written=*/false, 104), "an unwritten entry is not a lap");
  check(!is_lap_not_empty(t, true, 100), "the same counter means the hardware never came back");
  check(is_lap_not_empty(t, true, 104), "a moved counter under a stale phase is a lap");
  CtrTrack fresh;
  check(!is_lap_not_empty(fresh, true, 104), "a queue with no history claims nothing");
}

}  // namespace

int main() {
  stride_is_learned_inside_one_sweep();
  one_operation_between_sweeps_is_not_a_gap();
  a_forward_gap_counts_what_it_skipped();
  a_gap_past_half_the_counter_still_counts();
  a_backwards_step_is_not_a_gap();
  a_static_counter_reports_nothing();
  the_owner_bit_test_separates_a_lap_from_an_empty_slot();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return EXIT_FAILURE;
  }
  std::printf("cq lap tests passed\n");
  return EXIT_SUCCESS;
}
