// Copyright 2025 The NativeLink Authors. All rights reserved.
//
// Licensed under the Functional Source License, Version 1.1, Apache 2.0 Future License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    See LICENSE file for details
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Keeps files' bytes on local disk while an archive is expanded, for
//! whatever has to read them again after the archive has moved past them.
//! Nothing is read from the CAS.
//!
//! A file the expander spilled is kept as the expander's own temp file,
//! through a clone of its [`Held`] handle, so it is never copied. Smaller
//! files, which the expander held in memory, are appended to one temp file.
//! Each distinct content is kept once, so memory holds an offset per digest
//! and no content, and disk holds at most the expanded size. Every file is
//! removed when the spill is dropped, however the expansion ends.

use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::PathBuf;

use nativelink_error::{Code, Error, ResultExt, make_err};
use nativelink_util::common::DigestInfo;
use nativelink_util::fs;
use tempfile::{NamedTempFile, TempPath};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::archive_expander::Held;

/// Where one content is kept.
#[derive(Debug)]
enum Kept {
    Empty,
    /// In the expander's temp file.
    Held(Held),
    /// In the append file.
    Appended {
        offset: u64,
        len: u64,
    },
}

#[derive(Debug)]
pub(crate) struct Spill {
    temp_dir: Option<PathBuf>,
    /// The append file, once something is appended, and its length.
    file: Option<(TempPath, fs::FileSlot)>,
    len: u64,
    kept: HashMap<DigestInfo, Kept>,
}

impl Spill {
    pub(crate) fn new(temp_dir: Option<PathBuf>) -> Self {
        Self {
            temp_dir,
            file: None,
            len: 0,
            kept: HashMap::new(),
        }
    }

    async fn file(&mut self) -> Result<&mut fs::FileSlot, Error> {
        if self.file.is_none() {
            let path = match &self.temp_dir {
                Some(dir) => NamedTempFile::new_in(dir),
                None => NamedTempFile::new(),
            }
            .err_tip(|| "Could not create a spill file")?
            .into_temp_path();
            let file = fs::create_file(&path)
                .await
                .err_tip(|| "Could not open a spill file")?;
            self.file = Some((path, file));
        }
        let (_, file) = self
            .file
            .as_mut()
            .ok_or_else(|| make_err!(Code::Internal, "Spill file vanished"))?;
        Ok(file)
    }

    /// Keeps the content `digest`, whose bytes are `held`.
    pub(crate) async fn keep(&mut self, digest: DigestInfo, held: &Held) -> Result<(), Error> {
        if self.kept.contains_key(&digest) {
            return Ok(());
        }
        let kept = match held {
            Held::Inline(bytes) if bytes.is_empty() => Kept::Empty,
            Held::Inline(bytes) => {
                let offset = self.len;
                self.file()
                    .await?
                    .write_all(bytes)
                    .await
                    .err_tip(|| "Writing a spill file")?;
                self.len += bytes.len() as u64;
                Kept::Appended {
                    offset,
                    len: bytes.len() as u64,
                }
            }
            Held::Spilled(_) => Kept::Held(held.clone()),
            Held::NotKept => {
                return Err(make_err!(
                    Code::Internal,
                    "A spill was not given the bytes it asked for"
                ));
            }
        };
        self.kept.insert(digest, kept);
        Ok(())
    }

    /// Streams the content `digest` to `f`.
    pub(crate) async fn read(
        &mut self,
        digest: DigestInfo,
        f: &mut (dyn FnMut(&[u8]) + Send),
    ) -> Result<(), Error> {
        let (offset, len) = match self.kept.get(&digest) {
            None => {
                return Err(make_err!(Code::Internal, "Spill does not have {digest}"));
            }
            Some(Kept::Empty) => return Ok(()),
            Some(Kept::Held(held)) => return held.read(f).await,
            Some(Kept::Appended { offset, len }) => (*offset, *len),
        };
        let file = self.file().await?;
        file.flush().await.err_tip(|| "Flushing a spill file")?;
        file.seek(SeekFrom::Start(offset))
            .await
            .err_tip(|| "Seeking in a spill file")?;
        let mut remaining = len;
        let mut buf = vec![0u8; fs::DEFAULT_READ_BUFF_SIZE];
        while remaining > 0 {
            let want = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
            let n = file
                .read(&mut buf[..want])
                .await
                .err_tip(|| "Reading a spill file")?;
            if n == 0 {
                return Err(make_err!(
                    Code::Internal,
                    "Spill file is shorter than what was written to it"
                ));
            }
            f(&buf[..n]);
            remaining -= n as u64;
        }
        // Later appends go to the end again.
        file.seek(SeekFrom::End(0))
            .await
            .err_tip(|| "Seeking in a spill file")?;
        Ok(())
    }
}
