// Copyright 2013-2016 Stanford University
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef STOKE_TOOLS_GADGETS_SANDBOX_H
#define STOKE_TOOLS_GADGETS_SANDBOX_H

#include <vector>
#include <chrono>

#include "src/ext/x64asm/include/x64asm.h"

#include "src/sandbox/sandbox.h"
#include "src/state/cpu_states.h"
#include "src/tunit/tunit.h"
#include "tools/args/in_out.inc"
#include "tools/args/sandbox.inc"
#include "tools/args/target.inc"

using namespace std;
using namespace std::chrono;

namespace stoke {

class PerfSandboxGadget : public Sandbox {
public:
  PerfSandboxGadget(const CpuStates& tcs, const std::vector<TUnit>& aux_fxns) {

    auto perf_time_ = duration_values<long>::zero

    set_abi_check(abi_check_arg);
    set_stack_check(stack_check_arg);
    set_max_jumps(max_jumps_arg);

    for (const auto& fxn : aux_fxns) {
      insert_function(Cfg(fxn, x64asm::RegSet::empty(), x64asm::RegSet::empty()));
    }
    for (const auto& tc : tcs) {
      insert_input(tc);
    }
  }

  // Overrides the original 
  PerfSandboxGadget& PerfSandboxGadget::run(size_t index) {

  assert(num_functions() > 0);
  assert(index < num_inputs());
  auto io = io_pairs_[index];

  // Don't bother executing testcases that are in error states
  if (io->in_.code != ErrorCode::NORMAL) {
    return *this;
  }

  io->out_.stack.copy(io->in_.stack);
  io->out_.heap.copy(io->in_.heap);
  io->out_.data.copy(io->in_.data);
  io->out_.segments.resize(io->in_.segments.size());
  for (size_t i = 0, ie=io->out_.segments.size(); i < ie; ++i) {
    io->out_.segments[i].copy(io->in_.segments[i]);
  }

  // Reset error-related variables
  jumps_remaining_ = max_jumps_;

  // Initialize input-specific state that the instrumented function relies on
  // State that doesn't vary on a per-input basis (ie: entrypoint_) is set elsewhere
  out_ = &io->out_;
  in2cpu_ = io->in2cpu_.get_entrypoint();
  out2cpu_ = io->out2cpu_.get_entrypoint();
  cpu2out_ = io->cpu2out_.get_entrypoint();
  map_addr_ = io->map_addr_.get_entrypoint();

  // Initialize state related to %rsp tracking
  user_rsp_ = io->in_.gp[rsp].get_fixed_quad(0);
  harness_rsp_ = 0;
  stoke_rsp_ = 0;

  // Run the code (control exits abnormally for sigfpe or if linking failed)
  if (!lnkr_.good()) {
    io->out_.code = ErrorCode::SIGCUSTOM_LINKER_ERROR;
  } else if (!sigsetjmp(buf_, 1)) {
    const auto start = steady_clock::now();
    io->out_.code = harness_.call<ErrorCode>();
    const auto dur = duration_cast<duration<double>>(steady_clock::now() - start);
    perf_time_ += dur; 

  } else {
    io->out_.code = ErrorCode::SIGFPE_;
  }

  // Finalize output state
  if (abi_check_ && !check_abi(*io)) {
    io->out_.code = ErrorCode::SIGCUSTOM_ABI_VIOLATION;
  }

  return *this;
}

};

} // namespace stoke

#endif
