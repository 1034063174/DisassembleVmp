#pragma once
#include "vmp_analyzer.h"

// 对完整分析结果做后处理标注，填充每行的 analysis 字段。
// 在 vmp_analyze 返回前、dump 之前调用。
void vmp_annotate(VmpAnalysisResult& res);
