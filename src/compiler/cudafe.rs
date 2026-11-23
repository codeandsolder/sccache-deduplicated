// Copyright 2016 Mozilla Foundation
// SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::compiler::Language;
use crate::compiler::args::{ArgDisposition, ArgInfo, FromArg};
use crate::compiler::c::CCompilerKind;
use crate::compiler::cicc;
use crate::counted_array;

use std::ffi::OsString;
use std::path::PathBuf;
/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct CudaFE {
    pub version: Option<String>,
}

impl_cuda_stage_compiler!(
    CudaFE,
    CCompilerKind::CudaFE,
    Language::CudaFE,
    &ARGS[..],
    1,
    cicc::OutputStyle::ModuleIdFile,
);

use cicc::ArgData::{GenModuleIdFileFlag, Output, UnhashedOutput, UnhashedPassThrough};

counted_array!(pub static ARGS: [ArgInfo<cicc::ArgData>; _] = [
    take_arg!("--gen_c_file_name", PathBuf, Separated, UnhashedOutput),
    flag!("--gen_module_id_file", GenModuleIdFileFlag),
    take_arg!("--module_id_file_name", PathBuf, Separated, Output),
    take_arg!("--stub_file_name", OsString, Separated, UnhashedPassThrough),
]);
