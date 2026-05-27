// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/utils/explorer/probe_explorer.h>

int main(int argc, char** argv) {
  DC_LOG_TRACE("probe_configurator main - start");
  datacrumbs::utils::Timer timer;
  timer.resumeTime();

  datacrumbs::ProbeExplorer explorer(argc, argv, true);
  explorer.writeProbesToJson();

  timer.pauseTime();
  DC_LOG_PRINT("Elapsed time in Probe Configurator: %f seconds", timer.getElapsedTime());
  return explorer.has_invalid_probes_ ? 1 : 0;
}
