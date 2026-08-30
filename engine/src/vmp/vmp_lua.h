#pragma once
#include "vmp_analyzer.h"
#include <string>
#include <vector>
#include <functional>

class IpcClient;

std::string vmp_run_lua(const std::string& script_path,
                        VmpAnalysisResult& res,
                        IpcClient& ipc,
                        const std::function<void(const std::string&)>& log_fn,
                        int context_row = -1);
