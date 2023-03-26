#![allow(unused_parens)]
use std::io::{ErrorKind, Read};
use std::sync::Arc;

use qprov::Certificate;

use qprov::sized_read_writes::{ReadSizedExt, WriteSizedExt};
use qprov::{PqsChannel, PqsContext};
use wintun::Adapter;
use clap::Parser;

fn main() {
  let cli = Cli::parse();
  let wintun = unsafe { wintun::load_from_path(cli.libpath) }
    .expect("Failed to load wintun dll");
  let adapter = match Adapter::open(&wintun, &cli.iface_name) {
    Ok(a) => a,
    Err(_) => {
      //If loading failed (most likely it didn't exist), create a new one
      wintun::Adapter::create(&wintun, &cli.iface_pool, &cli.iface_name, None)
        .expect("Failed to create wintun adapter!")
    }
  };

  let stream = std::net::TcpStream::connect(&cli.server).unwrap();
  stream
    .set_read_timeout(Some(std::time::Duration::from_millis(1000)))
    .unwrap();
  let ca_cert = Certificate::from_file(&cli.ca_certificate_file).unwrap();
  let context = PqsContext::client(ca_cert);
  let mut stream = PqsChannel::new(stream, &context).unwrap();
  let mut internal_ip_bytes = [0u8; 4];
  stream.read_exact(&mut internal_ip_bytes).unwrap();
  println!("received ip: {:?}", internal_ip_bytes);

  set_ip_address(&adapter, internal_ip_bytes).unwrap();
  println!("ip successfully set");
  //Specify the size of the ring buffer the wintun driver should use.
  let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).unwrap());

  loop {
    if let Some(packet) = session.try_receive().unwrap() {
      stream.write_sized(packet.bytes()).unwrap();
    }
    match stream.read_sized() {
      Ok(packet_data) => {
        let mut packet = session
          .allocate_send_packet(packet_data.len() as u16)
          .unwrap();
        packet.bytes_mut().copy_from_slice(&packet_data);

        //Send the packet to wintun virtual adapter for processing by the system
        session.send_packet(packet);
      }
      Err(err) => {
        if !matches!(
          err.kind(),
          std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
          panic!("Error: {err:?}");
        }
      }
    }
  }
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
  server: String,
  #[arg(long, short, default_value_t = ("wintun/bin/amd64/wintun.dll".to_owned()))]
  libpath: String,
  #[arg(long, short, default_value_t = ("Demo".to_owned()))]
  iface_name: String,
  #[arg(long, short, default_value_t = ("Example".to_owned()))]
  iface_pool: String,
  #[arg(short, long, default_value_t = ("ca.cert".to_owned()))]
  ca_certificate_file: String,
}