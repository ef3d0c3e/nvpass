/*
* main.rs
*
* nvpass -- Neovim secure vault
* Copyright (C) 2026 Lino Gamba <linogamba@pundalik.org>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* SPDX-License-Identifier: GPL-3.0-or-later
*/

use std::{
	env,
	io::{self, BufRead, Read, Write},
};

pub mod db;

use getopts::Options;
use rand::rngs::ThreadRng;
use rand_distr::{Distribution, Uniform};
use zeroize::Zeroizing;

use crate::db::Database;

/// Where to get the passphrase from
enum PassphraseSource {
	Prompt,
	Fd(i32),
	#[allow(unused)]
	Stdin,
}

/// Read passphrase from stdin, prompt or specific fd
fn read_passphrase(source: PassphraseSource) -> io::Result<Zeroizing<String>> {
	match source {
		PassphraseSource::Prompt => rpassword::prompt_password("Passphrase: ")
			.map(Zeroizing::new)
			.map_err(io::Error::other),
		PassphraseSource::Stdin => {
			let mut line = Zeroizing::new(String::new());
			io::stdin().lock().read_line(&mut line)?;
			Ok(Zeroizing::new(
				line.trim_end_matches(['\n', '\r']).to_string(),
			))
		}
		PassphraseSource::Fd(fd) => {
			use std::os::unix::io::FromRawFd;
			let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
			let mut line = Zeroizing::new(String::new());
			std::io::BufReader::new(&mut f).read_line(&mut line)?;
			std::mem::forget(f); // don't close a fd we don't own
			Ok(Zeroizing::new(
				line.trim_end_matches(['\n', '\r']).to_string(),
			))
		}
	}
}

fn print_usage(program: &str, opts: Options) {
	let brief = format!(
		"Usage: {0} [OPTIONS] [OUTPUT]\nEncrypt: {0} -e INPUT OUTPUT\nDecrypt: {0} -d INPUT OUTPUT",
		program
	);
	print!("{}", opts.usage(&brief));
}

fn print_version() {
	print!(
		"nvpass version 0.1\nauthor: ef3d0c3e\nlicense: GNU GPL version 3\ndatabase version: {}\n",
		db::DbVersion::default() as u64
	);
}

fn main() -> std::io::Result<()> {
	let args: Vec<String> = env::args().collect();
	let program = args[0].clone();

	let mut opts = Options::new();
	opts.optopt("d", "decrypt", "Decrypt a file", "FILE");
	opts.optopt("e", "encrypt", "Encrypt a file", "FILE");
	opts.optopt(
		"",
		"passphrase-fd",
		"Read password from specific FD",
		"NUMBER",
	);
	opts.optopt("g", "generate", "Generate random text", "LEN");
	opts.optflag("h", "help", "Print this help menu");
	opts.optflag("v", "version", "Display program version");
	let matches = opts
		.parse(&args[1..])
		.map_err(|err| io::Error::other(err.to_string()))?;
	if matches.opt_present("h") {
		print_usage(&program, opts);
		return Ok(());
	}
	if matches.opt_present("v") {
		print_version();
		return Ok(());
	}
	if let Some(len) = matches.opt_str("g") {
		let value = len.parse::<usize>().map_err(|err| io::Error::other(format!("Failed to parse `{len}' as length: {err}")))?;

		if value == 0 || value > 1024 {
			return Err(io::Error::other(format!(
				"Generate length out of bounds, expected a value between 1 and 1024, got: {value}"
			)));
		}

		const CHARSET: &[u8; 62] =
			b"0123456789abcdefghjiklmnopqrstuvwxyzABCDEFGHJIKLMNOPQRSTUVWXYZ";
		let mut rng = ThreadRng::default();
		let distr = Uniform::new(0, CHARSET.len()).map_err(
			|err| io::Error::other(format!("Failed to build uniform distribution: {err}"))
		)?;
		let output: Vec<u8> = (0..value).map(|_| {
			let idx = distr.sample(&mut rng);
			CHARSET[idx]
		}).collect();
		io::stdout().write_all(output.as_slice())?;
	} else if let Some(input) = matches.opt_str("e") {
		let output = matches.free.first().ok_or(
			io::Error::other("Expected output file".to_string()),
		)?;

		let pass_source = match matches.opt_str("passphrase-fd") {
			Some(opt) => {
				let fd = opt.parse::<i32>().map_err(|err| {
					io::Error::other(format!("Failed to parse passphrase-fd: {err}"))
				})?;
				PassphraseSource::Fd(fd)
			}
			None => PassphraseSource::Prompt,
		};

		// Read input
		let mut src_in: Box<dyn Read> = if input == "-" {
			Box::new(io::stdin().lock())
		} else {
			Box::new(std::fs::File::open(&input)?)
		};
		let mut data = Zeroizing::new(Vec::with_capacity(4096));
		src_in.read_to_end(&mut data)?;

		// Read passphrase & build db
		let passphrase = read_passphrase(pass_source)?;
		let db = db::v1::Db::new(passphrase);

		// Write
		let dest_out: Box<dyn Write> = if output == "-" {
			Box::new(io::stdout().lock())
		} else {
			Box::new(std::fs::File::create(output)?)
		};
		db.write(dest_out, &data)?;

		return Ok(());
	} else if let Some(input) = matches.opt_str("d") {
		let output = matches.free.first().ok_or(
			io::Error::other("Expected output file".to_string()),
		)?;

		let pass_source = match matches.opt_str("passphrase-fd") {
			Some(opt) => {
				let fd = opt.parse::<i32>().map_err(|err| {
					io::Error::other(format!("Failed to parse passphrase-fd: {err}"))
				})?;
				PassphraseSource::Fd(fd)
			}
			None => PassphraseSource::Prompt,
		};

		// Read input
		let src_in: Box<dyn Read> = if input == "-" {
			Box::new(io::stdin().lock())
		} else {
			Box::new(std::fs::File::open(&input)?)
		};

		// Read passphrase & build db
		let passphrase = read_passphrase(pass_source)?;
		let db = db::v1::Db::new(passphrase);

		let data = db.read(src_in)?;

		// Write
		let mut dest_out: Box<dyn Write> = if output == "-" {
			Box::new(io::stdout().lock())
		} else {
			Box::new(std::fs::File::create(output)?)
		};
		dest_out.write_all(&data)?;

		return Ok(());
	} else {
		print_usage(&args[0], opts);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use crate::db::v1;

	use super::*;

	fn make_db(passphrase: &str) -> v1::Db {
		v1::Db::new(Zeroizing::new(passphrase.to_string()))
	}

	fn roundtrip(passphrase: &str, data: &[u8]) -> Vec<u8> {
		let mut buf = Vec::new();
		let db = make_db(passphrase);
		db.write(Box::new(&mut buf), data).unwrap();

		let db2 = make_db(passphrase);
		db2.read(Box::new(buf.as_slice())).unwrap().to_vec()
	}

	#[test]
	fn test_roundtrip() {
		let data = b"hello world";
		assert_eq!(roundtrip("passphrase123", data), data);
	}

	#[test]
	fn test_roundtrip_empty() {
		assert_eq!(roundtrip("passphrase123", b""), b"");
	}

	#[test]
	fn test_roundtrip_large() {
		let data = vec![0x7fu8; 1024 * 1024];
		assert_eq!(roundtrip("passphrase123", &data), data);
	}

	#[test]
	fn test_long_passphrase() {
		let data = b"hello world";
		let pass = String::from_utf8_lossy(&[0x1au8; 1024 * 1024]);
		assert_eq!(roundtrip(pass.to_string().as_str(), data), data);
	}

	#[test]
	fn test_empty_passphrase() {
		let data = b"hello world";
		assert_eq!(roundtrip("", data), data);
	}

	#[test]
	fn test_wrong_passphrase_fails() {
		let mut buf = Vec::new();
		make_db("correct")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		let result = make_db("wrong").read(Box::new(buf.as_slice()));
		assert!(result.is_err());
	}

	#[test]
	fn test_tampered_version_fails() {
		let mut buf = Vec::new();
		make_db("passphrase")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		// Flip a byte in the version field
		buf[0] ^= 0xFF;

		let result = make_db("passphrase").read(Box::new(buf.as_slice()));
		assert!(result.is_err());
	}

	#[test]
	fn test_tampered_salt_fails() {
		let mut buf = Vec::new();
		make_db("passphrase")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		// Flip a byte in the salt
		buf[8] ^= 0xFF;

		let result = make_db("passphrase").read(Box::new(buf.as_slice()));
		assert!(result.is_err());
	}

	#[test]
	fn test_tampered_nonce_fails() {
		let mut buf = Vec::new();
		make_db("passphrase")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		// Flip a byte in the nonce
		buf[8 + 32] ^= 0xFF;

		let result = make_db("passphrase").read(Box::new(buf.as_slice()));
		assert!(result.is_err());
	}

	#[test]
	fn test_tampered_ciphertext_fails() {
		let mut buf = Vec::new();
		make_db("passphrase")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		// Flip a byte in the ciphertext region (after version + salt + nonce)
		buf[8 /* version */ + 32 /* salt */ + 24 /* nonce */] ^= 0xFF;

		let result = make_db("passphrase").read(Box::new(buf.as_slice()));
		assert!(result.is_err());
	}

	#[test]
	fn test_nonce_salt() {
		let db = make_db("passphrase");
		let mut buf1 = Vec::new();
		let mut buf2 = Vec::new();
		db.write(Box::new(&mut buf1), b"same data").unwrap();
		db.write(Box::new(&mut buf2), b"same data").unwrap();
		assert_ne!(buf1, buf2);
	}

	#[test]
	fn test_tampered_input_fails() {
		let mut buf = Vec::new();
		make_db("passphrase")
			.write(Box::new(&mut buf), b"secret data")
			.unwrap();

		let truncated = &buf[..buf.len() / 2];
		let result = make_db("passphrase").read(Box::new(truncated));
		assert!(result.is_err());
	}
}
