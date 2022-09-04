
pub mod tcp {
	extern crate openssl;
	use openssl::symm::{Cipher, encrypt, decrypt};
	use openssl::rand::rand_bytes;

	use std::io::Write;
  use std::io::Read;
  use std::convert::TryInto;
  use std::net::{TcpListener, TcpStream};

	//tcp
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

	//key converter 32B-> 258bit
	//--------------------------------------------------------------------
	fn convert_key(key: &str) -> [u8; 32] {
		let mut key = key.to_owned();
		while key.len() < 32 {
			key.push('x');
		}
		return key[..32].as_bytes().try_into().unwrap();
	}

	//cipher 256
	//--------------------------------------------------------------------
	fn enc256(data: Vec::<u8>, key: &[u8]) -> std::io::Result<Vec<u8>> {
		let mut ranarr = vec![0u8; 16];
		rand_bytes(&mut ranarr).unwrap();
		ranarr.extend(data);
		return Ok(encrypt(Cipher::aes_256_cbc(), key, None, &ranarr)?);
	}
	fn dec256(data: Vec::<u8>, key: &[u8]) -> std::io::Result<Vec<u8>> {
		let newdata = decrypt(Cipher::aes_128_cbc(), key, None, &data)?;
		return Ok(newdata[16..].to_vec());
	}

	//connect/listen
	//--------------------------------------------------------------------
	pub fn simple_listen(ip: &str, port: &str) -> std::io::Result<SimpleTcp> {
		return Ok(SimpleTcp{ conn: listen_on(ip, port)?});
	}
	pub fn simple_connect(ip: &str, port: &str) -> std::io::Result<SimpleTcp> {
		return Ok(SimpleTcp{ conn: connect_to(ip, port)?});
	}

	//secure connect/listen 128aes cbc
	//--------------------------------------------------------------------
	pub fn secure_listen(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ conn: listen_on(ip, port)?, key: convert_key(set_key)});
	}
	pub fn secure_connect(ip: &str, port: &str, set_key: &str) -> std::io::Result<SecureTcp> {
		return Ok(SecureTcp{ conn: connect_to(ip, port)?, key: convert_key(set_key)});
	}
	
	//simple conn
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

	//secure conn aes128 cbc
	//--------------------------------------------------------------------
	pub struct SecureTcp {
		conn: TcpStream,
		key: [u8; 32],
	}
	impl SecureTcp {
		pub fn send(&self, data: Vec::<u8>) -> std::io::Result<()> {
			send_vec(&self.conn, enc256(data, &self.key)?)?;
			return Ok(());
		}
		pub fn recive(&self) -> std::io::Result<Vec<u8>> {
			return Ok(dec256(recive_vec(&self.conn)?, &self.key)?);
		}
	}

}
