#![allow(unused_parens)]
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use vpnmessaging::mio::net::UdpSocket;
use vpnmessaging::{iv_from_hello, mio, ClientCrypter, DecryptedMessage};
use vpnmessaging::{
  receive_unreliable, recv_all_parts_blocking, send_guaranteed, send_unreliable, HelloMessage,
  KeyType, MessagePartsCollection, PlainMessage,
};
use vpnmessaging::qprov;

use clap::Parser;
use qprov::keys::CertificateChain;
use qprov::{Certificate, SecKeyPair};

use crate::transient_hashmap::TransientHashMap;
pub mod transient_hashmap;

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

const SOCK: mio::Token = mio::Token(0);
const TUN: mio::Token = mio::Token(1);

fn main() {
  let cli = Cli::parse();

  let mut socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    .expect("Failed to bind to address");
  socket.connect(cli.server).unwrap();

  let ca_cert = Certificate::from_file(&cli.ca_certificate_file).unwrap();
  let chain = CertificateChain::from_file(&cli.certificate_chain_file).unwrap();
  let secret_key = SecKeyPair::from_file(cli.secret_key_file).unwrap();

  let mut buffer: Box<[u8; 0xffff]> = boxed_array::from_default();

  let (ip, mask, mut crypter) = handshake(
    &mut socket,
    &secret_key,
    &ca_cert,
    &chain,
    buffer.as_mut_slice(),
  )
  .unwrap();
  println!("received ip: {ip}/{mask}");

  let mut tun =
    mio_tun::Tun::new_with_path(cli.libpath, cli.iface_name, cli.iface_pool, ip, mask).unwrap();
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
  loop {
    messages_map.prune();
    poll.poll(&mut events, None).unwrap();
    for event in &events {
      match event.token() {
        SOCK => {
          let parts = receive_unreliable(&mut socket, buffer.as_mut_slice());
          for part in parts {
            let id = part.id;
            let messages = messages_map
              .entry(id)
              .or_insert_with(|| MessagePartsCollection::new(part.total));
            let Ok(Some(PlainMessage::Encrypted(data))) = messages.add(part) else {
              continue;
            };
            let Some(DecryptedMessage::IpPacket(packet)) = data.decrypt(&mut crypter) else {
              continue;
            };
            tun.send(packet);
          }
        }
        TUN => {
          for packet in tun.iter() {
            let message = DecryptedMessage::IpPacket(packet).encrypt(&mut crypter);
            drop(send_unreliable(&mut socket, message, buffer.as_mut_slice()));
          }
        }
        _ => {}
      }
    }
  }
}

fn handshake(
  socket: &mut UdpSocket,
  secret_key: &SecKeyPair,
  ca_cert: &Certificate,
  chain: &CertificateChain,
  buffer: &mut [u8],
) -> Result<(Ipv4Addr, u8, ClientCrypter), Box<dyn std::error::Error>> {
  // ======== CLIENT HELLO
  let client_random = KeyType::generate();
  let client_hello = HelloMessage {
    chain: chain.clone(),
    random: client_random,
  };
  let message = PlainMessage::Hello(client_hello.clone());
  send_guaranteed(socket, message, buffer, Some(Duration::from_secs(3)))?;
  // ======== !CLIENT HELLO

  // ======== SERVER HELLO
  let message = recv_all_parts_blocking(socket, buffer, Some(Duration::from_secs(3)))?;
  let PlainMessage::Hello(server_hello) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message during hello")));
  };
  if !server_hello.chain.verify(&ca_cert, certificate_verificator) {
    return Err(Box::new(std::io::Error::new(
      ErrorKind::InvalidInput,
      "Failed to authorize servers certificate",
    )));
  }
  // ======== !SERVER HELLO

  // ======== SERVER PREMASTER
  let (encapsulated, server_premaster) =
    KeyType::encapsulate(&server_hello.chain.get_target().contents.pub_keys);
  let message = PlainMessage::Premaster(encapsulated);
  send_guaranteed(socket, message, buffer, Some(Duration::from_secs(3)))?;
  // ======== !SERVER PREMASTER

  // ======== CLIENT PREMASTER
  let message = recv_all_parts_blocking(socket, buffer, Some(Duration::from_secs(3)))?;
  let PlainMessage::Premaster(encapsulated) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message during client premaster")));
  };
  let client_premaster = KeyType::decapsulate(secret_key, &encapsulated);
  // ======== !CLIENT PREMASTER

  // ======== KEY DERIVATION
  let derived_key = client_hello.random ^ server_hello.random ^ server_premaster ^ client_premaster;
  let mut crypter = ClientCrypter::new(derived_key, iv_from_hello(server_hello.random));
  let hash = KeyType::zero(); // TODO: compute hashes

  // ======== !KEY DERIVATION

  // ======== CLIENT READY
  let encrypted = DecryptedMessage::Ready { hash }.encrypt(&mut crypter);
  send_guaranteed(socket, encrypted, buffer, Some(Duration::from_secs(3)))?;
  // ======== !CLIENT READY

  // ======== SERVER WELCOME
  let message = recv_all_parts_blocking(socket, buffer, Some(Duration::from_secs(3)))?;
  let PlainMessage::Encrypted(encrypted) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message")));
  };
  let decrypted = encrypted
    .decrypt(&mut crypter)
    .expect("Failed to decrypt server hello");
  let DecryptedMessage::Welcome{ip, mask} = decrypted else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message")))
  };
  // ======== !SERVER WELCOME

  Ok((ip, mask, crypter))
}

#[derive(Parser)]
struct Cli {
  #[arg()]
  server: SocketAddr,
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
}
