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
