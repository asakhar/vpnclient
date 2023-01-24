use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
  let socket = tokio::net::TcpSocket::new_v4().expect("Failed to create socket");
  let mut stream = socket
    .connect("127.0.0.1:9011".parse().unwrap())
    .await
    .expect("Failed to connect to server");
  let mut pub_key_buf = vec![0u8; rmce::PublicKey::SIZE];
  stream
    .read_exact(&mut pub_key_buf)
    .await
    .expect("Failed to read from server");
  let pk = rmce::PublicKey::try_from(pub_key_buf).unwrap();
  let (ss, ps) = pk.session();
  stream.write_all(ss.as_bytes()).await.expect("Failed to write to server");

  let mut iv_len_buf = [0u8; std::mem::size_of::<usize>()];
  stream.read_exact(&mut iv_len_buf).await.expect("Failed to read iv length from server");
  let iv_len = usize::from_be_bytes(iv_len_buf);
  let mut iv_buf = vec![0u8; iv_len];
  stream.read_exact(&mut iv_buf).await.expect("Failed to read iv from server");

  let mut message_len_buf = [0u8; std::mem::size_of::<usize>()];
  stream.read_exact(&mut message_len_buf).await.expect("Failed to read msg length from server");
  let message_len = usize::from_be_bytes(message_len_buf);
  let mut message_buf = vec![0u8; message_len];
  stream.read_exact(&mut message_buf).await.expect("Failed to read message from server");
  let cipher = openssl::symm::Cipher::aes_256_cbc();
  let plaintext = openssl::symm::decrypt(cipher, ps.as_bytes(), Some(iv_buf.as_slice()), &message_buf).expect("Failed to decrypt");
  let plaintext = String::from_utf8(plaintext).expect("Invalid utf");
  println!("Plaintext: {plaintext}");
}
