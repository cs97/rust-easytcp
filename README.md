# easytcp 4 rust

### Usage

Cargo.toml
```
[dependencies]
easytcp = { git = "https://github.com/cs97/rust-easytcp" }
#easytcp = { git = "https://github.com/cs97/rust-easytcp", features = ["tcp_openssl"] }
```

main.rs
```
fn foo() {
  let tcp = easytcp::tcp::simple_connect("127.0.0.1", "6666").unwrap();
  tcp.send("nice msg".as_bytes().to_vec()).unwrap();
 }
 ```

```
fn foo() {
  let key = "1234567890ABCDEFsomenicekey";
  let tcp = easytcp::tcp::secure_connect("127.0.0.1", "6666", key).unwrap();
  tcp.send("nice msg".as_bytes().to_vec()).unwrap();
 }
 ```
