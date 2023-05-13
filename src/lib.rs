use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use vpnmessaging::{iv_from_hello, send_sized, ClientCrypter};
use vpnmessaging::{qprov, DecryptedHandshakeMessage, HandshakeMessage, Uuid};
use vpnmessaging::{HelloMessage, KeyType};

use qprov::{Certificate, CertificateChain, SecKeyPair};

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

pub fn handshake(
  server: SocketAddr,
  secret_key: &SecKeyPair,
  ca_cert: &Certificate,
  chain: &CertificateChain,
) -> Result<(Uuid, Ipv4Addr, u8, ClientCrypter), Box<dyn std::error::Error>> {
  let stream = TcpStream::connect(server)?;
  let mut stream = std::io::BufWriter::new(stream);
  // ======== CLIENT HELLO
  let client_hello = HelloMessage::from(chain);
  let client_random = client_hello.random;
  let message = HandshakeMessage::Hello(client_hello);
  send_sized(&mut stream, message)?;
  stream.flush()?;
  // ======== !CLIENT HELLO

  // ======== SERVER HELLO
  let message = bincode::deserialize_from(stream.get_mut())?;
  let HandshakeMessage::Hello(server_hello) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message during hello")));
  };
  let server_chain = server_hello.chain().ok_or(std::io::Error::new(
    ErrorKind::InvalidData,
    "Server sent invalid certificate chain",
  ))?;
  if !server_chain.verify(&ca_cert, certificate_verificator) {
    return Err(Box::new(std::io::Error::new(
      ErrorKind::InvalidInput,
      "Failed to authorize servers certificate",
    )));
  }
  // ======== !SERVER HELLO

  // ======== SERVER PREMASTER
  let (encapsulated, server_premaster) =
    KeyType::encapsulate(&server_chain.get_target().contents.pub_keys).ok_or(
      std::io::Error::new(ErrorKind::InvalidData, "Failed to encapsulte"),
    )?;
  let message = HandshakeMessage::Premaster(encapsulated);
  send_sized(&mut stream, message)?;
  stream.flush()?;
  // ======== !SERVER PREMASTER

  // ======== CLIENT PREMASTER
  let message = bincode::deserialize_from(stream.get_mut())?;
  let HandshakeMessage::Premaster(encapsulated) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message during client premaster")));
  };
  let client_premaster = KeyType::decapsulate(secret_key, &encapsulated).ok_or(
    std::io::Error::new(ErrorKind::InvalidData, "Failed to decapsulate"),
  )?;
  // ======== !CLIENT PREMASTER

  // ======== KEY DERIVATION
  let derived_key = client_random ^ server_hello.random ^ server_premaster ^ client_premaster;
  let mut crypter = ClientCrypter::new(derived_key, iv_from_hello(server_hello.random));
  let hash = KeyType::zero(); // TODO: compute hashes

  // ======== !KEY DERIVATION

  // ======== CLIENT READY
  let encrypted = DecryptedHandshakeMessage::Ready { hash }.encrypt(&mut crypter);
  send_sized(&mut stream, encrypted)?;
  stream.flush()?;
  // ======== !CLIENT READY

  // ======== SERVER WELCOME
  let message = bincode::deserialize_from(stream.get_mut())?;
  let HandshakeMessage::Ready(encrypted) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message during welcome")));
  };
  let decrypted = encrypted.decrypt(&mut crypter).ok_or(std::io::Error::new(
    ErrorKind::InvalidData,
    "Failed to decrypt server hello",
  ))?;
  let DecryptedHandshakeMessage::Welcome{ip, mask, id} = decrypted else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message")))
  };
  // ======== !SERVER WELCOME

  Ok((id, ip, mask, crypter))
}
