// SPDX-License-Identifier: MIT
// `migcom` binary: same unified driver+compiler as `mig`, under the
// traditional compiler name. Some build scripts invoke `migcom` directly
// (pre-processed `.defs` on stdin); others go through the `mig` driver.
include!("main.rs");
