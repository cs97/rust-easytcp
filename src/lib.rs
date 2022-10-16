// tcp
pub mod tcp {

  use std::io::Write;
  use std::io::Read;
  use std::convert::TryInto;
  use std::net::{TcpListener, TcpStream};

	// tcp
	//--------------------------------------------------------------------
	fn recive_vec(mut stream: &TcpStream) -> std::io::Result<Vec<u8>> {
		let mut package_len = [0 as u8; 8];
		stream.read_exact(&mut package_len)?;
		let len = u64::from_be_bytes(package_len);
		
		let mut data = vec![0; len.try_into().unwrap()];
		stream.read_exact(&mut data)?;
		return Ok(data);
	}

	fn send_vec(mut stream: &TcpStream, data: Vec<u8>)-> std::io::Result<()>  {
		let length: u64 = data.len().try_into().unwrap();
		let len_bytes = length.to_be_bytes();
		stream.write(&len_bytes)?;
		stream.write(&data)?;
		Ok(())
	}

	fn connect_to(ip: &str, port: &str) -> std::io::Result<TcpStream> {
		let addr = format!("{}{}{}", ip, ":", port);
		let stream = TcpStream::connect(addr)?;
		return Ok(stream);
	}

	fn listen_on(ip: &str, port: &str) -> std::io::Result<TcpStream> {
		let addr = format!("{}{}{}", ip, ":", port);
		let listener = TcpListener::bind(addr)?;
		let (stream, _addr) = listener.accept()?;
		return Ok(stream);
	}

	// connect/listen
	//--------------------------------------------------------------------
	pub fn listen(ip: &str, port: &str) -> std::io::Result<SimpleTcp> {
		return Ok(SimpleTcp{ conn: listen_on(ip, port)?});
	}
	pub fn connect(ip: &str, port: &str) -> std::io::Result<SimpleTcp> {
		return Ok(SimpleTcp{ conn: connect_to(ip, port)?});
	}

	// simple conn
	//--------------------------------------------------------------------
	pub struct SimpleTcp {
		conn: TcpStream,
	}
	impl SimpleTcp {
		pub fn send(&self, data: Vec::<u8>) -> std::io::Result<()> {
			send_vec(&self.conn, data)?;
			return Ok(());
		}
		pub fn recive(&self) -> std::io::Result<Vec<u8>> {
			return Ok(recive_vec(&self.conn)?);
		}
	}

}

// tcp_openssl
#[cfg(feature = "tcp_openssl")]
pub mod tcp_openssl {
	
	extern crate openssl;
	use openssl::symm::{Cipher, encrypt, decrypt};
	use openssl::rand::rand_bytes;

	// key converter
	//--------------------------------------------------------------------
	fn convert_key(key: &str) -> [u8; 32] {
		let mut key = key.to_owned();
		while key.len() < 32 {
			key.push('x');
		}
		return key[..32].as_bytes().try_into().unwrap();
	}

	// cipher aes256cbc
	//--------------------------------------------------------------------
	fn enc256(data: Vec::<u8>, key: &[u8]) -> std::io::Result<Vec<u8>> {
		let mut ranarr = vec![0u8; 16];
		rand_bytes(&mut ranarr).unwrap();
		ranarr.extend(data);
		return Ok(encrypt(Cipher::aes_256_cbc(), key, None, &ranarr)?);
	}
	fn dec256(data: Vec::<u8>, key: &[u8]) -> std::io::Result<Vec<u8>> {
		let newdata = decrypt(Cipher::aes_256_cbc(), key, None, &data)?;
		return Ok(newdata[16..].to_vec());
	}

	// secure connect/listen 256aes cbc
	//--------------------------------------------------------------------
	pub fn listen(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ tcp_conn: crate::tcp::listen(ip, port)?, key: convert_key(set_key)});
	}
	pub fn connect(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ tcp_conn: crate::tcp::connect(ip, port)?, key: convert_key(set_key)});
	}

	// secure conn aes256cbc
	//--------------------------------------------------------------------
	pub struct SecureTcp {
		tcp_conn: crate::tcp::SimpleTcp,
		key: [u8; 32],
	}
	impl SecureTcp {
		pub fn send(&self, data: Vec::<u8>) -> std::io::Result<()> {
			//send_vec(&self.conn, enc256(data, &self.key)?)?;
			let _ = &self.tcp_conn.send(enc256(data, &self.key)?)?;
			return Ok(());
		}
		pub fn recive(&self) -> std::io::Result<Vec<u8>> {
			//return Ok(dec256(recive_vec(&self.conn)?, &self.key)?);
			return Ok(dec256(self.tcp_conn.recive()?, &self.key)?);
		}
	}

}






// tcp_aes_cbc
#[cfg(feature = "tcp_aes_cbc")]
pub mod tcp_aes_cbc {
	
	use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

	// key converter
	//--------------------------------------------------------------------
	fn convert_key(key: &str) -> [u8; 32] {
		let mut key = key.to_owned();
		while key.len() < 32 {
			key.push('x');
		}
		return key[..32].as_bytes().try_into().unwrap();
	}

	// rand block
	//--------------------------------------------------------------------
	fn rand_block() -> Vec<u8> {
		let mut ranarr = vec![0u8; 16];
		for x in 0..16{
			 ranarr[x] = rand::random::<u8>();
		}
		return ranarr
	}

	// cipher aes256cbc
	//--------------------------------------------------------------------
	fn enc256cbc(block: Vec<u8>, key: [u8; 32]) -> std::io::Result<Vec<u8>> {
		type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
		let iv = [0x24; 16];
		let mut buf = vec![0u8; 16+block.len()];
		let ct = Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_b2b_mut::<Pkcs7>(&block, &mut buf).unwrap();
		return Ok(ct.to_vec())
	}	
	fn dec256cbc(block: Vec<u8>, key: [u8; 32]) -> std::io::Result<Vec<u8>> {
		type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
		let iv = [0x24; 16];
		let mut buf = vec![0u8; 16+block.len()];
		let pt = Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_b2b_mut::<Pkcs7>(&block, &mut buf).unwrap();
		return Ok(pt.to_vec())
	}

	// secure connect/listen 256aes cbc
	//--------------------------------------------------------------------
	pub fn listen(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ tcp_conn: crate::tcp::listen(ip, port)?, key: convert_key(set_key)});
	}
	pub fn connect(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ tcp_conn: crate::tcp::connect(ip, port)?, key: convert_key(set_key)});
	}

	// secure conn aes256cbc
	//--------------------------------------------------------------------
	pub struct SecureTcp {
		tcp_conn: crate::tcp::SimpleTcp,
		key: [u8; 32],
	}
	impl SecureTcp {
		pub fn send(&self, data: Vec::<u8>) -> std::io::Result<()> {
			//let block = rand_block().extend(block);
			let _ = &self.tcp_conn.send(enc256cbc(data, self.key)?)?;
			return Ok(());
		}
		pub fn recive(&self) -> std::io::Result<Vec<u8>> {
			return Ok(dec256cbc(self.tcp_conn.recive()?, self.key)?);
		}
	}

}