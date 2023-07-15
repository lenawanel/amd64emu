//! simple parsed symbol table for getting function and symbol information
use std::collections::HashMap;

pub type SymbolTable = HashMap<usize, String>;
