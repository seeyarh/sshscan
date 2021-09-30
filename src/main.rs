use crossbeam::channel::{unbounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::io;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
struct Target {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
struct Response {
    target: Target,
    error: Option<String>,
    ssh_info: Option<SshInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
struct SshInfo {
    banner: Option<String>,
    auth_methods: String,
}

fn targets_reader(tx_targets: Sender<Target>) {
    // read targets
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(io::stdin());

    for result in rdr.deserialize() {
        let target: Target = result.expect("failed to read target");
        tx_targets.send(target).expect("failed to send target");
    }
}

fn responses_writer(rx_responses: Receiver<Response>) {
    for response in rx_responses {
        let s = serde_json::to_string(&response).expect("failed to serialize");
        println!("{}", s);
    }
}

fn scan_target(target: &Target) -> Result<SshInfo, String> {
    let host = format!("{}:{}", target.ip, target.port);
    let tcp = TcpStream::connect_timeout(
        &host.parse().expect("failed to parse host"),
        Duration::from_millis(1000),
    )
    .map_err(|e| e.to_string())?;

    let mut sess = Session::new().map_err(|e| e.to_string())?;
    sess.set_tcp_stream(tcp);
    sess.handshake().map_err(|e| e.to_string())?;
    let banner = sess.banner();
    let auth_methods = sess.auth_methods("root").map_err(|e| e.to_string())?;
    Ok(SshInfo {
        banner: banner.map(|s| s.into()),
        auth_methods: auth_methods.into(),
    })
}

fn scanner(rx_targets: Receiver<Target>, tx_responses: Sender<Response>) {
    for target in rx_targets {
        let response = match scan_target(&target) {
            Ok(ssh_info) => Response {
                target,
                ssh_info: Some(ssh_info),
                error: None,
            },
            Err(e) => Response {
                target,
                ssh_info: None,
                error: Some(e),
            },
        };
        tx_responses
            .send(response)
            .expect("failed to send response");
    }
}

fn main() {
    let (tx_targets, rx_targets) = unbounded();
    let (tx_responses, rx_responses) = unbounded();

    let targets_handle = thread::spawn(move || {
        targets_reader(tx_targets);
    });

    let responses_handle = thread::spawn(move || {
        responses_writer(rx_responses);
    });

    let n_send_threads = 32;

    let mut send_handles = vec![];
    for _ in 0..n_send_threads {
        let rx_targets = rx_targets.clone();
        let tx_responses = tx_responses.clone();
        let h = thread::spawn(move || {
            scanner(rx_targets, tx_responses);
        });
        send_handles.push(h);
    }

    drop(tx_responses);

    targets_handle
        .join()
        .expect("failed to join targets handle");
    for h in send_handles {
        h.join().expect("failed to join scanner handle");
    }
    responses_handle
        .join()
        .expect("failed to join responses_handle handle");
}
