#pragma once
#include "types.h"

namespace netguard::dashboard {

// Runs the ncurses UI loop on the current thread until the user quits
// (sets state.running = false on exit). Reads/writes `state` under its
// mutex; scanner threads run concurrently and publish into the same
// state.
void run(SharedState& state);

} // namespace netguard::dashboard
