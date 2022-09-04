# easytcp 4 rust

### Usage

Cargo.toml
```
[dependencies]
easytcp = { git = "https://github.com/cs97/rust-easytcp" }
```

```
fn foo() {
  let key = "1234567890ABCDEFsomenicekey";
	let tcp = easytcp::tcp::secure_connect("127.0.0.1", "6666", key).unwrap();
	tcp.send("nice msg".as_bytes().to_vec()).unwrap();
  
 ```
