// ruleid: cesa.hygiene.allow-dead-code
#[allow(dead_code)]
fn unused() {}

// ruleid: cesa.hygiene.allow-dead-code
#[allow(clippy::too_many_arguments, unused_variables)]
fn many(a: u8) {}

// ruleid: cesa.hygiene.allow-dead-code
#![allow(unused_imports)]

// ruleid: cesa.hygiene.allow-dead-code
#[expect(dead_code, reason = "later")]
fn later() {}

// ok: cesa.hygiene.allow-dead-code
#[allow(clippy::too_many_arguments)] // one call per role
fn fine(a: u8, b: u8) {}

// ruleid: cesa.hygiene.allow-unwrap
#[allow(clippy::unwrap_used)]
fn crashes(v: Option<u8>) -> u8 { v.unwrap() }

// ruleid: cesa.hygiene.allow-unwrap
#![allow(clippy::expect_used)]

// ruleid: cesa.hygiene.allow-unwrap
#[cfg_attr(not(test), allow(clippy::too_many_arguments, clippy::unwrap_used))]
fn hidden(a: u8) {}

// ruleid: cesa.hygiene.allow-unwrap
#[expect(clippy::expect_used, reason = "can't fail")]
fn sure(v: Option<u8>) -> u8 { v.expect("set") }

// ok: cesa.hygiene.allow-unwrap
#[allow(clippy::unwrap_or_default)]
fn other(v: Option<u8>) -> u8 { v.unwrap_or_default() }
