/*
* db.rs
*
* nvpass -- Neovim secure vault
* Copyright (C) 2026 ef3d0c3e <ef3d0c3e@pundalik.org>
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
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Database format version
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DbVersion {
	#[default]
	V1,
}

pub trait Database {
	fn version(&self) -> DbVersion;
	fn write(&self, writer: Box<dyn Write + '_>, data: &[u8]) -> io::Result<()>;
	fn read(&self, reader: Box<dyn Read + '_>) -> io::Result<Zeroizing<Vec<u8>>>;
}

/// Database V1: Argon2 + ChaCha20poly1305
pub mod v1 {
	use std::io::{self, Read, Write};

	use argon2::{
		Argon2,
		password_hash::{Salt, SaltString, rand_core::RngCore},
	};
	use chacha20poly1305::{KeyInit, aead::OsRng};
	use serde::{Deserialize, Serialize};
	use zeroize::Zeroizing;

	use crate::db::{Database, DbVersion};

	/// Header for AAD
	#[derive(Serialize, Deserialize)]
	struct Header {
		/// Database version
		version: DbVersion,
		/// Database nonce
		nonce: [u8; 24],
	}

	pub struct Db {
		passphrase: Zeroizing<String>,
	}

	impl Db {
		pub fn new(passphrase: Zeroizing<String>) -> Self {
			Self {
				passphrase,
			}
		}

		/// Derive key from passphrase using argon2
		pub fn derive_key(&self, salt: &[u8; 32]) -> io::Result<Zeroizing<[u8; 32]>> {
			// Assert we are using an appropriate salt length
			const {
				const ENCODED_LEN: usize = (32 * 4_usize).div_ceil(3); // = 43
				assert!(ENCODED_LEN >= Salt::RECOMMENDED_LENGTH);
				assert!(ENCODED_LEN <= Salt::MAX_LENGTH);
			}

			let salt = SaltString::encode_b64(salt)
				.map_err(|err| io::Error::other(format!("Failed to encode salt: {err}")))?;
			let mut key = [0u8; 32];
			Argon2::default()
				.hash_password_into(
					self.passphrase.as_bytes(),
					salt.as_salt().as_str().as_bytes(),
					&mut key,
				)
				.map_err(|err| {
					io::Error::other(format!("Failed to derive key for passphrase: {err}"))
				})?;
			Ok(Zeroizing::new(key))
		}

		/// Get the AAD header for the database
		fn aad(&self, nonce: [u8; 24]) -> Header {
			Header {
				version: self.version(),
				nonce,
			}
		}
	}

	impl Database for Db {
		fn version(&self) -> DbVersion {
			DbVersion::V1
		}

		fn write(&self, mut writer: Box<dyn Write + '_>, data: &[u8]) -> io::Result<()> {
			// Generate new salt
			let mut salt = Zeroizing::new([0u8; 32]);
			OsRng.fill_bytes(salt.as_mut_slice());
			let key = self.derive_key(&salt)?;

			// Generate nonce
			let nonce =
				<chacha20poly1305::XChaCha20Poly1305 as chacha20poly1305::AeadCore>::generate_nonce(
					&mut chacha20poly1305::aead::OsRng,
				);

			// Write DB version field
			writer.write_all(&(self.version() as u64).to_le_bytes())?;

			// Write salt
			writer.write_all(salt.as_slice())?;

			// Write nonce
			writer.write_all(nonce.as_slice())?;

			// Build header for AAD
			let aad = self.aad(nonce.into());

			// Build cipher
			let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key.as_slice())
				.map_err(|err| {
					io::Error::other(format!(
						"Failed to initialize chacha20-poly1305 cipher: {err}"
					))
				})?;

			// Encrypt
			let ciphertext = chacha20poly1305::aead::Aead::encrypt(
				&cipher,
				&nonce,
				chacha20poly1305::aead::Payload {
					msg: data,
					aad: bincode2::serialize(&aad)
						.map_err(|err| {
							io::Error::other(format!("Failed to serialize AAD header: {err}"))
						})?
						.as_slice(),
				},
			)
			.map_err(|err| {
				io::Error::other(format!("Failed to encrypt using chacha20-poly1305: {err}"))
			})?;

			// Write to file
			writer.write_all(&ciphertext)?;
			Ok(())
		}

		fn read(&self, mut reader: Box<dyn Read + '_>) -> io::Result<Zeroizing<Vec<u8>>> {
			// Check database version by reading first 8 bytes
			let mut version_bytes = [0u8; 8];
			reader.read_exact(&mut version_bytes)?;
			let version = u64::from_le_bytes(version_bytes);
			if version != self.version() as u64 {
				return Err(io::Error::other(format!(
					"Invalid database version, got {version}, expected {}",
					self.version() as u64
				)));
			}

			// Read 32-byte argon2 salt
			let mut salt = Zeroizing::new([0u8; 32]);
			reader.read_exact(salt.as_mut_slice())?;

			// Read 24-byte nonce
			let mut nonce = [0u8; 24];
			reader.read_exact(&mut nonce)?;

			// Read rest of file
			let mut data = Vec::with_capacity(4096);
			reader.read_to_end(&mut data)?;

			// Derive key
			let key = self.derive_key(&salt)?;

			// Build aad
			let aad = self.aad(nonce);

			// Build cipher
			let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key.as_slice())
				.map_err(|err| {
					io::Error::other(format!(
						"Failed to initialize chacha20-poly1305 cipher: {err}"
					))
				})?;

			// Decrypt
			chacha20poly1305::aead::Aead::decrypt(
				&cipher,
				(&nonce).into(),
				chacha20poly1305::aead::Payload {
					msg: &data,
					aad: bincode2::serialize(&aad)
						.map_err(|err| {
							io::Error::other(format!("Failed to serialize AAD header: {err}"))
						})?
						.as_slice(),
				},
			)
			.map(Zeroizing::new)
			.map_err(|err| {
				io::Error::other(format!("Failed to decrypt using chacha20-poly1305: {err}"))
			})
		}
	}
}
