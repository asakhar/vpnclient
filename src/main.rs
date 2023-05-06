#![allow(unused_parens)]
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};
use vpnmessaging::mio::net::UdpSocket;
use vpnmessaging::{iv_from_hello, mio, send_sized, ClientCrypter, DecryptedMessage};
use vpnmessaging::{qprov, DecryptedHandshakeMessage, HandshakeMessage, Uuid};
use vpnmessaging::{
  receive_unreliable, send_unreliable, HelloMessage, KeyType, MessagePartsCollection,
};

use clap::Parser;
use qprov::{Certificate, CertificateChain, FileSerialize, SecKeyPair};

use crate::transient_hashmap::TransientHashMap;
pub mod transient_hashmap;

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

const SOCK: mio::Token = mio::Token(0);
const TUN: mio::Token = mio::Token(1);

const BUF_SIZE: usize = 0x10000;

fn main() {
  let cli = Cli::parse();

  let mut socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    .expect("Failed to bind to address");
  let mut server_tcp = cli.server;
  server_tcp.set_port(cli.server_tcp_port);
  if let Some(ip) = cli.override_server_tcp_ip {
    server_tcp.set_ip(ip);
  }
  socket.connect(cli.server).unwrap();

  let ca_cert = Certificate::from_file(&cli.ca_certificate_file).unwrap();
  let chain = CertificateChain::from_file(&cli.certificate_chain_file).unwrap();
  let secret_key = SecKeyPair::from_file(cli.secret_key_file).unwrap();
  let keep_alive_interval = Duration::from_secs(cli.keep_alive_interval);

  let mut buffer: Box<[u8; BUF_SIZE]> = boxed_array::from_default();

  loop {
    let mut retries_count = 0;
    const MAX_ATTEMPTS: usize = 10;
    let (client_id, ip, mask, mut crypter) = loop {
      match handshake(server_tcp, &secret_key, &ca_cert, &chain) {
        Ok(res) => break res,
        _ => {
          if retries_count > MAX_ATTEMPTS {
            eprintln!("Failed to connect");
            return;
          }
          retries_count += 1;
        }
      }
    };
    println!("received ip: {ip}/{mask}");

    let mut tun =
      mio_tun::Tun::new_with_path(&cli.libpath, &cli.iface_name, &cli.iface_pool, ip, mask)
        .unwrap();
    println!("Ip successfully set!");

    let mut poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    registry
      .register(&mut socket, SOCK, mio::Interest::READABLE)
      .unwrap();
    registry
      .register(&mut tun, TUN, mio::Interest::READABLE)
      .unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut messages_map = TransientHashMap::new(Duration::from_secs(5));
    let mut last_keep_alive = Instant::now();
    'inner: loop {
      messages_map.prune();
      poll.poll(&mut events, Some(keep_alive_interval)).unwrap();
      if events.is_empty() {
        let keep_alive = DecryptedMessage::KeepAlive.encrypt(&mut crypter, client_id);
        drop(send_unreliable(
          &mut socket,
          keep_alive,
          buffer.as_mut_slice(),
        ));
      }
      for event in &events {
        match event.token() {
          SOCK => {
            let parts = receive_unreliable(&mut socket, buffer.as_mut_slice());
            for part in parts {
              let id = part.id;
              let messages = messages_map
                .entry(id)
                .or_insert_with(|| MessagePartsCollection::new(part.total));
              let Ok(Some(data)) = messages.add(part) else {
                continue;
              };
              if data.get_sender_id() != client_id {
                continue;
              }
              let Some(decrypted) = data.decrypt(&mut crypter) else {
                continue;
              };
              if matches!(decrypted, DecryptedMessage::KeepAlive) {
                last_keep_alive = Instant::now();
                continue;
              }
              let DecryptedMessage::IpPacket(packet) = decrypted else {
              continue;
            };
              tun.send(packet);
            }
          }
          TUN => {
            for packet in tun.iter() {
              let message = DecryptedMessage::IpPacket(packet).encrypt(&mut crypter, client_id);
              drop(send_unreliable(&mut socket, message, buffer.as_mut_slice()));
            }
          }
          _ => {}
        }
      }
      if Instant::now().duration_since(last_keep_alive) > Duration::from_secs(60) {
        eprintln!("Lost connection. Reconnecting...");
        break 'inner;
      }
    }
    poll.registry().deregister(&mut socket).unwrap();
  }
}

fn handshake(
  server: SocketAddr,
  secret_key: &SecKeyPair,
  ca_cert: &Certificate,
  chain: &CertificateChain,
) -> Result<(Uuid, Ipv4Addr, u8, ClientCrypter), Box<dyn std::error::Error>> {
  let mut stream = TcpStream::connect(server)?;
  // ======== CLIENT HELLO
  let client_hello = HelloMessage::from(chain);
  let client_random = client_hello.random;
  let message = HandshakeMessage::Hello(client_hello);
  send_sized(&mut stream, message)?;
  stream.flush()?;
  // ======== !CLIENT HELLO

  // ======== SERVER HELLO
  let message = bincode::deserialize_from(&mut stream)?;
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
  let message = bincode::deserialize_from(&mut stream)?;
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
  let message = bincode::deserialize_from(&mut stream)?;
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

#[derive(Parser)]
struct Cli {
  #[arg()]
  server: SocketAddr,
  #[arg(default_value_t = 9010)]
  server_tcp_port: u16,
  #[arg(long, short, required(false))]
  override_server_tcp_ip: Option<IpAddr>,
  #[arg(long, short, default_value_t = ("./wintun.dll".to_owned()))]
  libpath: String,
  #[arg(long, short = 'n', default_value_t = ("Demo".to_owned()))]
  iface_name: String,
  #[arg(long, short = 'p', default_value_t = ("Example".to_owned()))]
  iface_pool: String,
  #[arg(long, short, default_value_t = ("keys/client.key".to_owned()))]
  secret_key_file: String,
  #[arg(short, long, default_value_t = ("keys/ca.crt".to_owned()))]
  ca_certificate_file: String,
  #[arg(short = 'e', long, default_value_t = ("keys/client.chn".to_owned()))]
  certificate_chain_file: String,
  #[arg(short, long, default_value_t = 1)]
  keep_alive_interval: u64,
}
