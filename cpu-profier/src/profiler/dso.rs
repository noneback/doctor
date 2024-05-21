use anyhow::{anyhow, Error, Ok};
use blazesym::symbolize::{Elf, Input, Source, Symbolizer};

pub struct Dso {
    path: String,
}

impl Dso {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn translate_single(&self, symbolizer: &Symbolizer, offset: u64) -> Result<String, Error> {
        let src = Source::Elf(Elf::new(&self.path));

        let sym = symbolizer
            .symbolize_single(&src, Input::FileOffset(offset))
            .map_err(|e| anyhow!("symbolizer -> {}", e))?;

        Ok(match sym {
            blazesym::symbolize::Symbolized::Sym(symbol) => symbol.name.to_string(),
            blazesym::symbolize::Symbolized::Unknown(r) => {
                println!(
                    "file offset {:x}, elf {}, reason {:#?}",
                    offset, self.path, r
                );
                "unknown".to_string()
            }
        })
    }

    pub fn translate(
        &self,
        symbolizer: &Symbolizer,
        offsets: &Vec<u64>,
    ) -> Result<Vec<String>, Error> {
        let src = Source::Elf(Elf::new(&self.path));

        let syms = symbolizer
            .symbolize(&src, Input::FileOffset(offsets))
            .map_err(|e| anyhow!("symbolizer -> {}", e))?;

        Ok(syms
            .iter()
            .map(|sym| match sym {
                blazesym::symbolize::Symbolized::Sym(symbol) => symbol.name.to_string(),
                blazesym::symbolize::Symbolized::Unknown(r) => {
                    println!(
                        "file offset {:#?}, elf {}, reason {:#?}",
                        offsets, self.path, r
                    );
                    "unknown".to_string()
                }
            })
            .collect::<Vec<_>>())
    }
}
