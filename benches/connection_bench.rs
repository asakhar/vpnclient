#[macro_use]
extern crate criterion;

use std::{
  net::{Ipv4Addr, SocketAddr, SocketAddrV4},
  process::{Child, Stdio},
  time::Duration,
};

use criterion::{measurement::WallTime, BenchmarkGroup, Criterion};

use vpnclient::handshake;
use vpnmessaging::{
  mio::{self, net::UdpSocket},
  qprov::{Certificate, CertificateChain, SecKeyPair},
  send_unreliable, DecryptedMessage,
};
const SERVER_ADDR: SocketAddr =
  std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9010));
const SERVER_UDP_ADDR: SocketAddr =
  std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9011));

lazy_static::lazy_static! {
static ref SECRET_KEY: SecKeyPair = bincode::deserialize(include_bytes!("precomputed/client.key")).unwrap();
static ref CA_CERT: Certificate = bincode::deserialize(include_bytes!("precomputed/ca.crt")).unwrap();
static ref CHAIN: CertificateChain =
  bincode::deserialize(include_bytes!("precomputed/client.chn")).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
  let mut group = c.benchmark_group("client");
  handshake_bench(group.measurement_time(Duration::from_secs(250)));
  echo_bench(group.measurement_time(Duration::from_secs(5)));
}

fn setup_echo_receiver() -> Child {
  std::process::Command::new("python")
    .args(["-c", include_str!("echo.py")]).stdout(Stdio::piped())
    .spawn()
    .unwrap()
}

fn handshake_bench(group: &mut BenchmarkGroup<WallTime>) {
  group.bench_function("handshake", |b| {
    b.iter(|| {
      handshake(SERVER_ADDR, &SECRET_KEY, &CA_CERT, &CHAIN).unwrap();
    })
  });
}

fn echo_bench(group: &mut BenchmarkGroup<WallTime>) {
  let mut socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
    .expect("Failed to bind to address");
  socket.connect(SERVER_UDP_ADDR).unwrap();

  let mut buffer: Box<[u8; 2048]> = boxed_array::from_default();
  let mut poll = mio::Poll::new().unwrap();
  let registry = poll.registry();
  registry
    .register(&mut socket, mio::Token(0), mio::Interest::WRITABLE)
    .unwrap();

  let mut events = mio::Events::with_capacity(1024);
  poll.poll(&mut events, None).unwrap();
  let (client_id, ip, _, mut crypter) =
    handshake(SERVER_ADDR, &SECRET_KEY, &CA_CERT, &CHAIN).unwrap();
  let child = setup_echo_receiver();
  std::thread::sleep(Duration::from_secs(1));
  let mut payload: Vec<_> = (0..208).collect();
  let mut i: u64 = 0;
  group.bench_function("send", |b| {
    b.iter(|| {
      arrayref::array_mut_ref![payload, 200, 8].copy_from_slice(&i.to_be_bytes());
      i += 1;
      let mut packet = Vec::new();
      etherparse::PacketBuilder::ipv4(ip.octets(), [10, 10, 10, 1], 2)
        .udp(5432, 8080)
        .write(&mut packet, &payload)
        .unwrap();

      let message = DecryptedMessage::IpPacket(packet).encrypt(&mut crypter, client_id);
      drop(send_unreliable(&mut socket, message, buffer.as_mut_slice()));
    });
  });
  println!("total sent => {i}");
  let received: u64 = String::from_utf8(child.wait_with_output().unwrap().stdout)
    .unwrap()
    .parse()
    .unwrap();

  println!("received   => {received}");
  let lost = i-received;
  println!("lost {} out of {i} packets ({:.3}%)", lost, lost as f64 / i as f64 * 100f64)
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
