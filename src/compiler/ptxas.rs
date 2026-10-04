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

#![allow(
    clippy::enum_glob_use,
    reason = "legacy implementation retained during strict-gate rollout to avoid unrelated semantic/API churn"
)]
#![allow(
    clippy::wildcard_imports,
    reason = "legacy implementation retained during strict-gate rollout to avoid unrelated semantic/API churn"
)]

use crate::compiler::args::*;
use crate::compiler::c::{
    CCompileContext, CCompilerImpl, CCompilerKind, CPreprocessContext, ParsedArguments,
};
use crate::compiler::cicc;
use crate::compiler::{CCompileCommand, Cacheable, CompileCommand, CompilerArguments, Language};
use crate::{counted_array, dist};

use crate::mock_command::CommandCreatorSync;

use async_trait::async_trait;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process;

use crate::errors::*;

/// A unit struct on which to implement `CCompilerImpl`.
#[derive(Clone, Debug)]
pub struct Ptxas {
    pub version: Option<String>,
}

#[async_trait]
impl CCompilerImpl for Ptxas {
    fn kind(&self) -> CCompilerKind {
        CCompilerKind::Ptxas
    }
    fn plusplus(&self) -> bool {
        true
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn parse_arguments(
        &self,
        arguments: &[OsString],
        cwd: &Path,
        _env_vars: &[(OsString, OsString)],
    ) -> CompilerArguments<ParsedArguments> {
        cicc::parse_arguments(arguments, cwd, Language::Cubin, &ARGS[..], 3)
    }
    async fn preprocess<T>(&self, context: CPreprocessContext<'_, T>) -> Result<process::Output>
    where
        T: CommandCreatorSync,
    {
        let CPreprocessContext {
            parsed_args, cwd, ..
        } = context;
        cicc::preprocess(cwd, parsed_args).await
    }
    fn generate_compile_commands<T>(
        &self,
        context: CCompileContext<'_>,
    ) -> Result<(
        Box<dyn CompileCommand<T>>,
        Option<dist::CompileCommand>,
        Cacheable,
    )>
    where
        T: CommandCreatorSync,
    {
        let CCompileContext {
            path_transformer,
            executable,
            parsed_args,
            cwd,
            env_vars,
            ..
        } = context;
        cicc::generate_compile_commands(path_transformer, executable, parsed_args, cwd, env_vars)
            .map(|(command, dist_command, cacheable)| {
                (CCompileCommand::boxed(command), dist_command, cacheable)
            })
    }
}

use cicc::ArgData::*;

counted_array!(pub static ARGS: [ArgInfo<cicc::ArgData>; _] = [
    take_arg!("-arch", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("-m", OsString, CanBeSeparated(b'='), PassThrough),
    take_arg!("-o", PathBuf, Separated, Output),
]);
