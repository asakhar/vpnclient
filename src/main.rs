#![allow(unused_parens)]
use qprov::signatures::SecretKey;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use vpnmessaging::mio::net::UdpSocket;
use vpnmessaging::{
  compare_hashes, recv_all_parts_blocking, send_guaranteed, HelloMessage, KeyType, PlainMessage,
};
use vpnmessaging::{iv_from_hello, mio, ClientCrypter, DecryptedMessage};

use clap::Parser;
use qprov::keys::CertificateChain;
use qprov::{Certificate, SecKeyPair};
use wintun::Adapter;

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

  let ip = handshake(&mut socket, &secret_key, &ca_cert, &chain).unwrap();
  println!("received ip: {ip}");

  // let wintun = unsafe { wintun::load_from_path(cli.libpath) }.expect("Failed to load wintun dll");
  // let adapter = match Adapter::open(&wintun, &cli.iface_name) {
  //   Ok(a) => a,
  //   Err(_) => {
  //     //If loading failed (most likely it didn't exist), create a new one
  //     wintun::Adapter::create(&wintun, &cli.iface_pool, &cli.iface_name, None)
  //       .expect("Failed to create wintun adapter!")
  //   }
  // };
  // set_ip_address(&adapter, internal_ip_bytes).unwrap();
  // println!("ip successfully set");
  // //Specify the size of the ring buffer the wintun driver should use.
  // let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
  // let mut poll = mio::Poll::new().unwrap();
  // let registry = poll.registry();
  // registry.register(&mut socket, SOCK, mio::Interest::READABLE);
  // registry.register(&mut )
  // let mut internal_ip_bytes = [0u8; 4];
  // stream.read_exact(&mut internal_ip_bytes).unwrap();
  // println!("received ip: {:?}", internal_ip_bytes);
  // stream
  //   .set_read_timeout(Some(std::time::Duration::from_millis(300)))
  //   .unwrap();
  // set_ip_address(&adapter, internal_ip_bytes).unwrap();
  // println!("ip successfully set");
  // //Specify the size of the ring buffer the wintun driver should use.
  // let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());
  // loop {
  //   if let Some(packet) = session.try_receive().unwrap() {
  //     stream.write_sized(packet.bytes()).unwrap();
  //   }
  //   match stream.read_sized() {
  //     Ok(packet_data) => {
  //       let mut packet = session
  //         .allocate_send_packet(packet_data.len() as u16)
  //         .unwrap();
  //       packet.bytes_mut().copy_from_slice(&packet_data);
  //       //Send the packet to wintun virtual adapter for processing by the system
  //       session.send_packet(packet);
  //     }
  //     Err(err) => {
  //       if !matches!(
  //         err.kind(),
  //         std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
  //       ) {
  //         panic!("Error: {err:?}");
  //       }
  //     }
  //   }
  // }
}

fn handshake(
  socket: &mut UdpSocket,
  secret_key: &SecKeyPair,
  ca_cert: &Certificate,
  chain: &CertificateChain,
) -> Result<Ipv4Addr, Box<dyn std::error::Error>> {
  let mut buffer: Box<[u8; 0xffff]> = boxed_array::from_default();

  // ======== CLIENT HELLO
  let client_random = KeyType::generate();
  let client_hello = HelloMessage {
    chain: chain.clone(),
    random: client_random,
  };
  let message = PlainMessage::Hello(client_hello.clone());
  send_guaranteed(socket, message, buffer.as_mut_slice())?;
  // ======== !CLIENT HELLO

  // ======== SERVER HELLO
  let message = recv_all_parts_blocking(socket, buffer.as_mut_slice())?;
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
  send_guaranteed(socket, message, buffer.as_mut_slice())?;
  // ======== !SERVER PREMASTER

  // ======== CLIENT PREMASTER
  let message = recv_all_parts_blocking(socket, buffer.as_mut_slice())?;
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
  send_guaranteed(socket, encrypted, buffer.as_mut_slice())?;
  // ======== !CLIENT READY

  // ======== SERVER WELCOME
  let message = recv_all_parts_blocking(socket, buffer.as_mut_slice())?;
  let PlainMessage::Encrypted(encrypted) = message else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message")));
  };
  let decrypted = encrypted
    .decrypt(&mut crypter)
    .expect("Failed to decrypt server hello");
  let DecryptedMessage::Welcome{ip} = decrypted else {
    return Err(Box::new(std::io::Error::new(ErrorKind::InvalidData, "Server sent invalid message")))
  };
  // ======== !SERVER WELCOME

  Ok(ip)
}

fn set_ip_address(adapter: &Arc<Adapter>, internal_ip: [u8; 4]) -> std::io::Result<()> {
  let mut address_row = winapi::shared::netioapi::MIB_UNICASTIPADDRESS_ROW::default();
  unsafe {
    winapi::shared::netioapi::InitializeUnicastIpAddressEntry(&mut address_row as *mut _);
  }
  address_row.InterfaceLuid = winapi::shared::ifdef::NET_LUID_LH {
    Value: adapter.get_luid(),
  };
  unsafe {
    let ipv4 = address_row.Address.Ipv4_mut();
    ipv4.sin_family = winapi::shared::ws2def::AF_INET as _;
    *ipv4.sin_addr.S_un.S_addr_mut() = u32::from_ne_bytes(internal_ip);
  }
  address_row.OnLinkPrefixLength = 24;
  address_row.DadState = winapi::shared::nldef::IpDadStatePreferred;
  let error =
    unsafe { winapi::shared::netioapi::CreateUnicastIpAddressEntry(&mut address_row as *mut _) };
  if error != winapi::shared::winerror::ERROR_SUCCESS {
    return Err(std::io::Error::new(
      ErrorKind::AddrNotAvailable,
      format!(
        "Failed to set IP address: {:?}",
        get_last_error::Win32Error::new(error)
      ),
    ));
  }
  Ok(())
}
// //Write IPV4 version and header length
// bytes[0] = 0x40;

// //Finish writing IP header
// bytes[9] = 0x69;
// bytes[10] = 0x04;
// bytes[11] = 0x20;
// //...
// loop {
//   let mut line = String::new();
//   std::io::stdin().read_line(&mut line).unwrap();
//   stream.write_all(&line.len().to_be_bytes()).unwrap();
//   stream.write_all(line.as_bytes()).unwrap();
//   let mut buf = [0u8; std::mem::size_of::<usize>()];
//   stream.read_exact(&mut buf).unwrap();
//   let len = usize::from_be_bytes(buf);
//   let mut line = vec![0u8; len];
//   stream.read_exact(&mut line).unwrap();
//   println!("-> {}", String::from_utf8(line).unwrap());
// }
#[derive(Parser)]
struct Cli {
  #[arg()]
  server: SocketAddr,
  #[arg(long, short, default_value_t = ("wintun/bin/amd64/wintun.dll".to_owned()))]
  libpath: String,
  #[arg(long, short = 'n', default_value_t = ("Demo".to_owned()))]
  iface_name: String,
  #[arg(long, short = 'p', default_value_t = ("Example".to_owned()))]
  iface_pool: String,
  #[arg(long, short, default_value_t = ("client.key".to_owned()))]
  secret_key_file: String,
  #[arg(short, long, default_value_t = ("ca.crt".to_owned()))]
  ca_certificate_file: String,
  #[arg(short = 'e', long, default_value_t = ("client.chn".to_owned()))]
  certificate_chain_file: String,
}
