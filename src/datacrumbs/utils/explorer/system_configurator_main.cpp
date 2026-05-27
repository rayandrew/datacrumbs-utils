// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/probe_file.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/utils/explorer/probe_explorer.h>

int main(int argc, char** argv) {
  DC_LOG_TRACE("system_configurator main - start");
  datacrumbs::utils::Timer timer;
  timer.resumeTime();

  std::string secret;
  if (!datacrumbs::probe_file::ensure_probe_secret(&secret)) {
    DC_LOG_ERROR("Failed to create probe signing secret");
    return 1;
  }

  datacrumbs::ProbeExplorer explorer(argc, argv, false);
  if (!explorer.writeSystemProbeJson()) {
    return 1;
  }

  timer.pauseTime();
  DC_LOG_PRINT("Elapsed time in System Configurator: %f seconds", timer.getElapsedTime());
  return 0;
}
