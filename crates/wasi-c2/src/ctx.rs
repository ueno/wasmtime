use crate::clocks::{WasiMonotonicClock, WasiSystemClock};
use crate::dir::{DirCaps, DirEntry, WasiDir};
use crate::file::{FileCaps, FileEntry, WasiFile};
use crate::string_array::{StringArray, StringArrayError};
use crate::table::Table;
use crate::Error;
use cap_rand::RngCore;
use std::cell::{RefCell, RefMut};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

#[derive(Clone)]
pub struct WasiCtx(Arc<WasiCtxInner>);

struct WasiCtxInner {
    pub(crate) args: StringArray,
    pub(crate) env: StringArray,
    pub(crate) random: RefCell<Box<dyn RngCore>>,
    pub(crate) clocks: WasiCtxClocks,
    table: Rc<RefCell<Table>>,
}

impl WasiCtx {
    pub fn builder() -> WasiCtxBuilder {
        WasiCtxBuilder {
            args: StringArray::new(),
            env: StringArray::new(),
            random: None,
            table: Table::new(),
        }
    }

    pub fn insert_file_at(&self, fd: u32, file: Box<dyn WasiFile>, caps: FileCaps) {
        self.table()
            .insert_at(fd, Box::new(FileEntry::new(caps, file)));
    }

    pub fn insert_dir_at(
        &self,
        fd: u32,
        dir: Box<dyn WasiDir>,
        caps: DirCaps,
        file_caps: FileCaps,
        path: PathBuf,
    ) {
        self.table().insert_at(
            fd,
            Box::new(DirEntry::new(caps, file_caps, Some(path), dir)),
        );
    }

    pub fn insert_file(&self, file: Box<dyn WasiFile>, caps: FileCaps) -> Result<u32, Error> {
        self.table().push(Box::new(FileEntry::new(caps, file)))
    }

    pub(crate) fn args(&self) -> &StringArray {
        &self.0.args
    }

    pub(crate) fn env(&self) -> &StringArray {
        &self.0.env
    }

    pub(crate) fn clocks(&self) -> &WasiCtxClocks {
        &self.0.clocks
    }

    pub(crate) fn random(&self) -> RefMut<Box<dyn RngCore>> {
        self.0.random.borrow_mut()
    }

    pub(crate) fn table(&self) -> RefMut<Table> {
        self.0.table.borrow_mut()
    }
}

impl Default for WasiCtx {
    fn default() -> Self {
        WasiCtx(Arc::new(WasiCtxInner {
            args: StringArray::new(),
            env: StringArray::new(),
            random: RefCell::new(Box::new(unsafe { cap_rand::rngs::OsRng::default() })),
            clocks: WasiCtxClocks::default(),
            table: Rc::new(RefCell::new(Table::new())),
        }))
    }
}

pub struct WasiCtxBuilder {
    args: StringArray,
    env: StringArray,
    random: Option<Box<dyn RngCore>>,
    table: Table,
}

impl WasiCtxBuilder {
    pub fn build(self) -> Result<WasiCtx, Error> {
        Ok(WasiCtx(Arc::new(WasiCtxInner {
            args: self.args,
            env: self.env,
            random: RefCell::new(self.random.unwrap_or_else(|| {
                Box::new(unsafe { cap_rand::rngs::OsRng::default() })
            })),
            clocks: WasiCtxClocks::default(),
            table: Rc::new(RefCell::new(self.table)),
        })))
    }

    pub fn arg(&mut self, arg: &str) -> Result<&mut Self, StringArrayError> {
        self.args.push(arg.to_owned())?;
        Ok(self)
    }

    pub fn stdin(&mut self, f: Box<dyn WasiFile>) -> &mut Self {
        // XXX fixme: more rights are ok, but this is read-only
        self.table.insert_at(0, Box::new(FileEntry::new(FileCaps::READ, f)));
        self
    }

    pub fn stdout(&mut self, f: Box<dyn WasiFile>) -> &mut Self {
        // XXX fixme: more rights are ok, but this is append only
        self.table.insert_at(1, Box::new(FileEntry::new(FileCaps::WRITE, f)));
        self
    }

    pub fn stderr(&mut self, f: Box<dyn WasiFile>) -> &mut Self {
        // XXX fixme: more rights are ok, but this is append only
        self.table.insert_at(2, Box::new(FileEntry::new(FileCaps::WRITE, f)));
        self
    }

    pub fn inherit_stdio(&mut self) -> &mut Self {
        self.stdin(Box::new(crate::stdio::stdin()))
            .stdout(Box::new(crate::stdio::stdout()))
            .stderr(Box::new(crate::stdio::stderr()))
    }

    pub fn preopened_dir(
        &mut self,
        dir: Box<dyn WasiDir>,
        path: impl AsRef<Path>,
    ) -> Result<&mut Self, Error> {
        let caps = DirCaps::all();
        let file_caps = FileCaps::all();
        self.table.push(Box::new(DirEntry::new(
            caps,
            file_caps,
            Some(path.as_ref().to_owned()),
            dir,
        )))?;
        Ok(self)
    }

    pub fn random(&mut self, random: Box<dyn RngCore>) -> &mut Self {
        self.random.replace(random);
        self
    }
}

pub struct WasiCtxClocks {
    pub(crate) system: Box<dyn WasiSystemClock>,
    pub(crate) monotonic: Box<dyn WasiMonotonicClock>,
    pub(crate) creation_time: cap_std::time::Instant,
}

impl Default for WasiCtxClocks {
    fn default() -> WasiCtxClocks {
        let system = Box::new(unsafe { cap_std::time::SystemClock::new() });
        let monotonic = unsafe { cap_std::time::MonotonicClock::new() };
        let creation_time = monotonic.now();
        let monotonic = Box::new(monotonic);
        WasiCtxClocks {
            system,
            monotonic,
            creation_time,
        }
    }
}
