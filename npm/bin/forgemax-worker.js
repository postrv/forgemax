#!/usr/bin/env node
"use strict";

const { spawnNative } = require("./spawn-native");

process.exit(spawnNative("forgemax-worker"));
