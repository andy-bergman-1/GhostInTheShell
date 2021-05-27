#pragma once

#include <stdio.h>

#define log(format, ...) fprintf(stdout, format, __VA_ARGS__)